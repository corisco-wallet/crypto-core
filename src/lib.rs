pub mod bip32;
pub mod frost;
pub mod mnemonic_gen;
#[cfg(feature = "seed-lock")]
pub mod seed_lock;
#[cfg(feature = "transfer-crypto")]
pub mod vss;

use bip32::ExtendedKey;
use bip39::Mnemonic;
#[cfg(not(feature = "hw-sha512"))]
use hmac::{Hmac, Mac};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey};
use k256::schnorr::signature::Signer as SchnorrSigner;
use k256::schnorr::{Signature as SchnorrSignature, SigningKey as SchnorrSigningKey};
#[cfg(not(feature = "hw-sha512"))]
use sha2::Sha512;
use sha2::{Digest, Sha256};

/// Spark's five key roots, all hardened-derived from the master seed.
/// Path scheme: m/8797555'/{account}'/{index}'
/// (verified against Spark signer docs; NOT yet checked against an official
/// Rust/JS SDK test vector -- do that before trusting this with real funds)
const SPARK_PURPOSE: u32 = 8797555;

pub struct SparkKeyRoots {
    pub identity: ExtendedKey,       // index 0
    pub signing_hd: ExtendedKey,     // index 1 - base for LEAF derivation
    pub deposit: ExtendedKey,        // index 2
    pub static_deposit: ExtendedKey, // index 3
    pub htlc_preimage: ExtendedKey,  // index 4
}

impl SparkKeyRoots {
    pub fn from_seed(seed: &[u8], account: u32) -> Result<Self, bip32::Bip32Error> {
        let master = ExtendedKey::master(seed);
        let base = master
            .derive_hardened(SPARK_PURPOSE)?
            .derive_hardened(account)?;

        Ok(Self {
            identity: base.derive_hardened(0)?,
            signing_hd: base.derive_hardened(1)?,
            deposit: base.derive_hardened(2)?,
            static_deposit: base.derive_hardened(3)?,
            htlc_preimage: base.derive_hardened(4)?,
        })
    }

    /// LEAF key derivation, matched against Spark's actual reference
    /// implementation (`DefaultSparkSigner.deriveSigningKey` in
    /// `sdks/js/packages/spark-sdk/src/signer/signer.ts`, buildonspark/spark)
    /// rather than inferred from docs: it's a plain BIP32 *hardened child*
    /// derivation of `signing_hd`, where the child index is derived from the
    /// leaf id (a UUIDv7 string, e.g. a tree node's `id`) as
    /// `(be_u32(sha256(leaf_id)[0..4]) % 2^31) + 2^31`. This must stay in
    /// exact lockstep with the reference implementation -- any divergence
    /// silently derives a different (wrong) key with no error at derivation
    /// time.
    pub fn derive_leaf_key(&self, leaf_id: &str) -> Result<[u8; 32], bip32::Bip32Error> {
        Ok(self.derive_leaf_child(leaf_id)?.private_key)
    }

    /// Public-key counterpart of [`Self::derive_leaf_key`] -- used by
    /// `getPublicKeyFromDerivation(LEAF)`, which the SDK calls during wallet
    /// sync to compute each leaf's expected public key WITHOUT needing the
    /// private key itself.
    pub fn derive_leaf_public_key(&self, leaf_id: &str) -> Result<[u8; 33], bip32::Bip32Error> {
        Ok(self.derive_leaf_child(leaf_id)?.public_key_compressed())
    }

    fn derive_leaf_child(&self, leaf_id: &str) -> Result<ExtendedKey, bip32::Bip32Error> {
        let hash = Sha256::digest(leaf_id.as_bytes());
        let index = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 0x8000_0000;
        self.signing_hd.derive_hardened(index)
    }

    /// Public-key counterpart of `getStaticDepositSecretKey(idx)`.
    pub fn static_deposit_public_key(&self, idx: u32) -> Result<[u8; 33], bip32::Bip32Error> {
        Ok(self
            .static_deposit
            .derive_hardened(idx)?
            .public_key_compressed())
    }

    /// `getStaticDepositSecretKey(idx)` -- genuinely returns a private key
    /// (see `DefaultSparkSigner.getStaticDepositSecretKey` in signer.ts),
    /// unlike the similarly-named `getStaticDepositSigningKey`. Callers may
    /// use this as an input to a local key-tweak subtraction, but the raw
    /// value itself must never cross the wire.
    pub fn static_deposit_private_key(&self, idx: u32) -> Result<[u8; 32], bip32::Bip32Error> {
        Ok(self.static_deposit.derive_hardened(idx)?.private_key)
    }
}

pub fn generate_mnemonic() -> Mnemonic {
    // 128 bits of entropy -> 12-word mnemonic. Host-only convenience
    // wrapper: the firmware calls `mnemonic_gen::generate_mnemonic_from_entropy`
    // directly with hardware-TRNG (`esp_fill_random`) entropy instead, since
    // getrandom's OS-backed source is host-only.
    let mut entropy = [0u8; 16];
    getrandom::getrandom(&mut entropy).expect("OS RNG should not fail");
    mnemonic_gen::generate_mnemonic_from_entropy(&entropy)
}

/// BIP39 seed derivation: PBKDF2-HMAC-SHA512(mnemonic sentence, "mnemonic"
/// + passphrase, 2048 rounds).
///
/// Hand-rolled rather than `bip39::Mnemonic::to_seed`, which pulls in
/// `bitcoin_hashes`. On real hardware (T-Display-S3 / ESP32-S3), pure
/// software SHA512 -- whether `bitcoin_hashes`'s or RustCrypto's `sha2` --
/// measured at ~6ms per 128-byte block, since Xtensa has no native 64-bit
/// ALU and every op in SHA512's round function is synthesized from 32-bit
/// pairs. Across 2048 PBKDF2 rounds (~4096 compressions) that's ~25s,
/// which trips the ESP-IDF idle-task watchdog. The host tests never
/// caught it since x86_64 does this natively and fast.
///
/// With the `hw-sha512` feature (only enabled by the firmware), the
/// inner HMAC-SHA512 routes through ESP-IDF's mbedtls instead, which uses
/// the ESP32-S3's hardware SHA accelerator peripheral.
pub fn mnemonic_to_seed(mnemonic: &Mnemonic, passphrase: &str) -> [u8; 64] {
    let phrase = mnemonic.to_string();
    let salt = format!("mnemonic{passphrase}");
    pbkdf2_hmac_sha512(phrase.as_bytes(), salt.as_bytes(), 2048)
}

/// Isolates a single hardware HMAC-SHA512 round-trip via the `hw-sha512`
/// path, independent of the full 2048-round PBKDF2 loop -- useful for
/// confirming the mbedtls peripheral itself is working correctly.
#[cfg(feature = "hw-sha512")]
pub fn hw_sha512_smoke_test() -> [u8; 64] {
    pbkdf2_hmac_sha512(b"smoke-test-password", b"smoke-test-salt", 1)
}

#[cfg(not(feature = "hw-sha512"))]
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;

    let mac_base = HmacSha512::new_from_slice(password).expect("HMAC accepts keys of any length");

    let mut mac = mac_base.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes()); // block index INT(1), single 64-byte block covers dkLen=64
    let mut block: [u8; 64] = mac.finalize().into_bytes().into();
    let mut result = block;

    for _ in 1..iterations {
        let mut mac = mac_base.clone();
        mac.update(&block);
        block = mac.finalize().into_bytes().into();
        for (r, b) in result.iter_mut().zip(block.iter()) {
            *r ^= b;
        }
    }

    result
}

/// Hardware-accelerated PBKDF2-HMAC-SHA512 via ESP-IDF's mbedtls, which
/// uses the ESP32-S3's SHA peripheral (`CONFIG_MBEDTLS_HARDWARE_SHA=y` by
/// default).
///
/// The HMAC key (the password) is the same across all 2048 rounds, so the
/// mbedtls MD context is set up *once* and reused via
/// `mbedtls_md_hmac_reset` for every round, rather than calling the
/// one-shot `mbedtls_md_hmac()` convenience function per round -- that
/// first attempt allocated and freed a hardware-engine context 2048
/// times in a tight loop and corrupted unrelated heap state (it crashed
/// inside the *logging* subsystem's mutex on the very next log call,
/// nowhere near this code -- a classic heap-corruption symptom).
#[cfg(feature = "hw-sha512")]
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    use esp_idf_sys as sys;

    unsafe {
        let md_info = sys::mbedtls_md_info_from_type(sys::mbedtls_md_type_t_MBEDTLS_MD_SHA512);
        assert!(!md_info.is_null(), "mbedtls built without SHA512 support");

        let mut ctx: sys::mbedtls_md_context_t = core::mem::zeroed();
        sys::mbedtls_md_init(&mut ctx);

        let ret = sys::mbedtls_md_setup(&mut ctx, md_info, 1 /* hmac */);
        assert_eq!(ret, 0, "mbedtls_md_setup failed with code {ret}");

        let ret = sys::mbedtls_md_hmac_starts(&mut ctx, password.as_ptr(), password.len());
        assert_eq!(ret, 0, "mbedtls_md_hmac_starts failed with code {ret}");

        let mut message = Vec::with_capacity(salt.len() + 4);
        message.extend_from_slice(salt);
        message.extend_from_slice(&1u32.to_be_bytes()); // block index INT(1)

        let mut block = [0u8; 64];
        let ret = sys::mbedtls_md_hmac_update(&mut ctx, message.as_ptr(), message.len());
        assert_eq!(ret, 0, "mbedtls_md_hmac_update failed with code {ret}");
        let ret = sys::mbedtls_md_hmac_finish(&mut ctx, block.as_mut_ptr());
        assert_eq!(ret, 0, "mbedtls_md_hmac_finish failed with code {ret}");
        let mut result = block;

        for round in 1..iterations {
            let ret = sys::mbedtls_md_hmac_reset(&mut ctx); // same key, new message
            assert_eq!(ret, 0, "mbedtls_md_hmac_reset failed with code {ret}");
            let ret = sys::mbedtls_md_hmac_update(&mut ctx, block.as_ptr(), block.len());
            assert_eq!(ret, 0, "mbedtls_md_hmac_update failed with code {ret}");
            let ret = sys::mbedtls_md_hmac_finish(&mut ctx, block.as_mut_ptr());
            assert_eq!(ret, 0, "mbedtls_md_hmac_finish failed with code {ret}");
            for (r, b) in result.iter_mut().zip(block.iter()) {
                *r ^= b;
            }

            // Progress logging: this loop takes long enough (2048 rounds)
            // that a completely silent hang would be indistinguishable
            // from a real one.
            if round % 200 == 0 {
                log::info!("hw pbkdf2: completed round {round}/{iterations}");
            }
        }

        sys::mbedtls_md_free(&mut ctx);
        result
    }
}

/// Plain ECDSA signature over a 32-byte digest (used for identity/deposit key ops).
pub fn sign_ecdsa_prehashed(private_key: &[u8; 32], digest: &[u8; 32]) -> EcdsaSignature {
    let signing_key = EcdsaSigningKey::from_bytes(private_key.into()).expect("valid scalar");
    signing_key
        .sign_prehash(digest)
        .expect("signing over a fixed 32-byte digest cannot fail")
}

/// BIP340 Schnorr signature (used for signSchnorrWithIdentityKey).
pub fn sign_schnorr(private_key: &[u8; 32], message: &[u8]) -> SchnorrSignature {
    let signing_key = SchnorrSigningKey::from_bytes(private_key).expect("valid scalar");
    signing_key.sign(message)
}

/// `(a - b) mod n` over the secp256k1 scalar field -- matches the SDK's own
/// `subtractPrivateKeys` (utils/keys.ts), which the leaf-ownership-transfer
/// "key tweak" step needs: the difference between a leaf's current private
/// key and a fresh one becomes the secret that gets Shamir-split to the
/// Signing Operators.
#[cfg(feature = "transfer-crypto")]
pub fn subtract_private_keys(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    use k256::elliptic_curve::PrimeField;
    let a = k256::Scalar::from_repr((*a).into()).expect("valid scalar");
    let b = k256::Scalar::from_repr((*b).into()).expect("valid scalar");
    (a - b).to_bytes().into()
}

/// ECIES encryption to a compressed secp256k1 public key -- matches Spark's
/// actual `encrypt_ecies`/`decrypt_ecies` (`signer/spark-frost/src/
/// bridge.rs` in buildonspark/spark), which is a thin wrapper over the same
/// `ecies` crate pinned here to the same version/features so ciphertexts
/// this produces (or consumes) are interoperable with real Signing
/// Operators and other Spark clients.
#[cfg(feature = "transfer-crypto")]
pub fn encrypt_ecies(msg: &[u8], public_key_compressed: &[u8; 33]) -> Result<Vec<u8>, String> {
    ecies::encrypt(public_key_compressed, msg).map_err(|e| e.to_string())
}

#[cfg(feature = "transfer-crypto")]
pub fn decrypt_ecies(ciphertext: &[u8], private_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    ecies::decrypt(private_key, ciphertext).map_err(|e| e.to_string())
}

/// The compressed SEC1 public key for a raw private key -- used by
/// `decryptEcies`'s actual `SparkSigner` interface contract, which
/// (despite the name) returns only the *public* key of an ECIES-decrypted
/// value, never the private key itself.
#[cfg(feature = "transfer-crypto")]
pub fn private_key_to_public_key_compressed(private_key: &[u8; 32]) -> [u8; 33] {
    let signing_key = EcdsaSigningKey::from_bytes(private_key.into()).expect("valid scalar");
    let encoded = k256::ecdsa::VerifyingKey::from(&signing_key).to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// A fresh, uniformly-random private key -- matches `KeyDerivationType.
/// RANDOM` (`secp256k1.utils.randomPrivateKey()` in the SDK's own
/// `getSigningPrivateKeyFromDerivation`), used as the ephemeral "new" key in
/// a leaf-ownership-transfer key tweak. Retries on the astronomically
/// unlikely case of an invalid/zero scalar.
#[cfg(feature = "transfer-crypto")]
pub fn random_private_key() -> [u8; 32] {
    use k256::elliptic_curve::PrimeField;
    loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS RNG should not fail");
        let Some(scalar) = Option::<k256::Scalar>::from(k256::Scalar::from_repr(bytes.into()))
        else {
            continue;
        };
        if !bool::from(k256::elliptic_curve::Field::is_zero(&scalar)) {
            return bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Language;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
    use k256::schnorr::signature::Verifier as _;
    use k256::schnorr::VerifyingKey as SchnorrVerifyingKey;

    #[test]
    fn mnemonic_round_trip_and_key_root_derivation() {
        let mnemonic = generate_mnemonic();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let roots = SparkKeyRoots::from_seed(&seed, 0).expect("derivation should succeed");

        // Different roots must not collide.
        assert_ne!(roots.identity.private_key, roots.signing_hd.private_key);
        assert_ne!(roots.deposit.private_key, roots.static_deposit.private_key);
    }

    #[test]
    fn ecdsa_sign_verify_round_trip() {
        let mnemonic = generate_mnemonic();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let roots = SparkKeyRoots::from_seed(&seed, 0).unwrap();

        let digest = Sha256::digest(b"spark test transaction sighash");
        let digest: [u8; 32] = digest.into();

        let sig = sign_ecdsa_prehashed(&roots.identity.private_key, &digest);

        let signing_key =
            EcdsaSigningKey::from_bytes((&roots.identity.private_key).into()).unwrap();
        let verifying_key = EcdsaVerifyingKey::from(&signing_key);
        // Important: we signed a *prehash* (sign_prehash), so verification
        // must also treat `digest` as an already-hashed value
        // (verify_prehash), not re-hash it (plain verify()). Using the
        // wrong pairing here silently "fails closed" in tests but would be
        // a nasty bug to chase in the field.
        assert!(verifying_key.verify_prehash(&digest, &sig).is_ok());
    }

    #[test]
    fn schnorr_sign_verify_round_trip() {
        let mnemonic = generate_mnemonic();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let roots = SparkKeyRoots::from_seed(&seed, 0).unwrap();

        let message = b"spark test schnorr message";
        let sig = sign_schnorr(&roots.identity.private_key, message);

        let signing_key = SchnorrSigningKey::from_bytes(&roots.identity.private_key).unwrap();
        let verifying_key: SchnorrVerifyingKey = *signing_key.verifying_key();
        assert!(verifying_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn leaf_derivation_is_deterministic_and_distinct_per_path() {
        let mnemonic = generate_mnemonic();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let roots = SparkKeyRoots::from_seed(&seed, 0).unwrap();

        let leaf_a1 = roots.derive_leaf_key("leaf-a").unwrap();
        let leaf_a2 = roots.derive_leaf_key("leaf-a").unwrap();
        let leaf_b = roots.derive_leaf_key("leaf-b").unwrap();

        assert_eq!(leaf_a1, leaf_a2, "same path must derive the same key");
        assert_ne!(
            leaf_a1, leaf_b,
            "different paths must derive different keys"
        );
    }

    #[test]
    fn leaf_derivation_matches_reference_implementation() {
        // Cross-checked against an independent, from-scratch Python
        // implementation of Spark's actual algorithm (BIP32 hardened child
        // derivation of signing_hd, index = (be_u32(sha256(leaf_id)[0..4]) %
        // 2^31) + 2^31 -- see `DefaultSparkSigner.deriveSigningKey` in
        // buildonspark/spark's JS SDK). Seed and leaf id are arbitrary but
        // fixed so the expected values are reproducible.
        let seed: [u8; 64] = {
            let mut s = [0u8; 64];
            for (i, b) in s.iter_mut().enumerate() {
                *b = i as u8;
            }
            s
        };
        let roots = SparkKeyRoots::from_seed(&seed, 0).unwrap();

        assert_eq!(
            hex::encode(roots.signing_hd.private_key),
            "f66960fb0edd6bd1a09a9ff1240d66bb8cd864cdd8f9ebe69431158ba6a6f929"
        );

        let leaf_id = "018f3e2a-1b2c-7000-8000-000000000000";
        let leaf_key = roots.derive_leaf_key(leaf_id).unwrap();
        assert_eq!(
            hex::encode(leaf_key),
            "ea9bc01e0c43cf8d126f37c1be929ab75387c148a4583c0bfa3f3a885b4255a0"
        );
    }

    #[test]
    fn mnemonic_to_seed_matches_official_bip39_test_vector() {
        // From the reference BIP39 test vectors (trezor/python-mnemonic).
        let mnemonic = Mnemonic::parse_in_normalized(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about",
        )
        .unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "TREZOR");
        // Verified against the reference `mnemonic` Python package (trezor's
        // canonical BIP39 implementation), not transcribed from memory.
        assert_eq!(
            hex::encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e534955\
             31f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[cfg(feature = "transfer-crypto")]
    #[test]
    fn subtract_private_keys_matches_manual_scalar_math() {
        use k256::elliptic_curve::PrimeField;

        let a = [0x11u8; 32];
        let b = [0x03u8; 32];
        let diff = subtract_private_keys(&a, &b);

        let expected =
            k256::Scalar::from_repr(a.into()).unwrap() - k256::Scalar::from_repr(b.into()).unwrap();
        assert_eq!(diff, <[u8; 32]>::from(expected.to_bytes()));

        // a - a == 0
        assert_eq!(subtract_private_keys(&a, &a), [0u8; 32]);
    }

    #[cfg(feature = "transfer-crypto")]
    #[test]
    fn ecies_encrypt_decrypt_round_trip() {
        let mnemonic = generate_mnemonic();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let roots = SparkKeyRoots::from_seed(&seed, 0).unwrap();

        let msg = b"leaf ownership transfer secret (test)";
        let ciphertext = encrypt_ecies(msg, &roots.identity.public_key_compressed())
            .expect("encrypt should succeed");
        let recovered = decrypt_ecies(&ciphertext, &roots.identity.private_key)
            .expect("decrypt should succeed");
        assert_eq!(recovered, msg);
    }

    #[cfg(feature = "transfer-crypto")]
    #[test]
    fn leaf_transfer_key_tweak_shares_recover_to_expected_difference() {
        // End-to-end sanity check mirroring `subtractSplitAndEncrypt`:
        // subtract two leaf keys, split the result, and verify a quorum of
        // shares recovers exactly that difference.
        let mnemonic = generate_mnemonic();
        let seed = mnemonic_to_seed(&mnemonic, "");
        let roots = SparkKeyRoots::from_seed(&seed, 0).unwrap();

        let leaf_key = roots.derive_leaf_key("some-leaf-id").unwrap();
        let fresh_key = {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k).unwrap();
            k
        };

        let diff = subtract_private_keys(&leaf_key, &fresh_key);
        let shares = vss::split_secret_with_proofs(&diff, 3, 5).unwrap();

        let plain: Vec<vss::SecretShare> = shares
            .iter()
            .map(|vs| vss::SecretShare {
                threshold: vs.share.threshold,
                index: vs.share.index,
                share: vs.share.share,
            })
            .collect();
        let recovered = vss::recover_secret(&plain[..3]).unwrap();
        assert_eq!(recovered, diff);
    }
}
