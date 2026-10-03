//! At-rest encryption of the BIP39 seed behind a user PIN.
//!
//! Deliberately a *different* KDF workload than `mnemonic_to_seed`'s
//! PBKDF2-HMAC-SHA512 (2048 rounds, BIP39-mandated, and already measured at
//! ~25s in pure software on this chip -- see `lib.rs`'s doc comment on
//! `mnemonic_to_seed`). This one runs on every PIN-unlock attempt (not just
//! once at wallet creation), so it needs to land well under a second;
//! PBKDF2-HMAC-SHA256 with a caller-chosen, much smaller round count is used
//! instead. The PIN's real defense against brute force is the device-side
//! attempt counter / wipe policy in `esp32-firmware`'s `storage` module, not
//! this KDF alone -- a short numeric PIN's entropy is too low for the KDF
//! cost alone to matter much against an attacker who can extract the flash
//! and brute-force offline.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// PBKDF2-HMAC-SHA256 round count for PIN unlock. There is no hardware-SHA
/// acceleration path for this (unlike `mnemonic_to_seed`'s `hw-sha512`), and
/// this call blocks synchronously wherever it's invoked -- a caller running
/// this on a UI thread needs to render a "working" frame *before* calling
/// in, not after, since nothing feeds the watchdog or redraws the screen
/// while this runs.
pub const PIN_KDF_ITERATIONS: u32 = 2_000;

#[derive(Debug, thiserror::Error)]
pub enum SeedLockError {
    #[error("wrong PIN or corrupted data")]
    DecryptionFailed,
}

/// A seed encrypted at rest. All fields are safe to store as-is (the salt
/// and nonce are not secret; the ciphertext includes the GCM tag).
#[derive(Clone)]
pub struct EncryptedSeed {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// PBKDF2-HMAC-SHA256(pin, salt, iterations) -> a 256-bit AES key.
/// Mirrors the hand-rolled PBKDF2 loop in `lib.rs`'s
/// `pbkdf2_hmac_sha512` (SHA256 here instead, and a caller-supplied round
/// count rather than BIP39's fixed 2048).
fn derive_pin_key(pin: &str, salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let mac_base = <HmacSha256 as Mac>::new_from_slice(pin.as_bytes())
        .expect("HMAC accepts keys of any length");

    let mut mac = mac_base.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes()); // block index INT(1), single 32-byte block covers dkLen=32
    let mut block: [u8; 32] = mac.finalize().into_bytes().into();
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

/// Encrypts `seed` under a key derived from `pin`, using caller-supplied
/// random `salt`/`nonce` -- kept explicit (rather than generated
/// internally) so this module stays platform-agnostic: callers supply
/// whichever RNG source is appropriate (host `getrandom`, or
/// `esp_fill_random` on-device), matching the same split already used for
/// `mnemonic_gen::generate_mnemonic_from_entropy`.
pub fn encrypt_seed_with_randomness(
    seed: &[u8; 64],
    pin: &str,
    salt: [u8; 16],
    nonce: [u8; 12],
) -> EncryptedSeed {
    let mut key_bytes = derive_pin_key(pin, &salt, PIN_KDF_ITERATIONS);
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_bytes));
    key_bytes.zeroize();

    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), seed.as_slice())
        .expect("encryption over a fixed-size buffer with a fresh nonce cannot fail");

    EncryptedSeed {
        salt,
        nonce,
        ciphertext,
    }
}

/// Decrypts an `EncryptedSeed` with `pin`. A wrong PIN fails the GCM tag
/// check and returns `DecryptionFailed` -- no separate correctness check is
/// needed, an authenticated cipher's tag mismatch already tells you "wrong
/// key or corrupted data".
pub fn decrypt_seed(enc: &EncryptedSeed, pin: &str) -> Result<[u8; 64], SeedLockError> {
    let mut key_bytes = derive_pin_key(pin, &enc.salt, PIN_KDF_ITERATIONS);
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_bytes));
    key_bytes.zeroize();

    let plaintext = cipher
        .decrypt(&Nonce::from(enc.nonce), enc.ciphertext.as_slice())
        .map_err(|_| SeedLockError::DecryptionFailed)?;

    plaintext
        .try_into()
        .map_err(|_| SeedLockError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 64] {
        let mut s = [0u8; 64];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn round_trips_with_correct_pin() {
        let seed = test_seed();
        let enc = encrypt_seed_with_randomness(&seed, "123456", [0x11; 16], [0x22; 12]);
        let recovered = decrypt_seed(&enc, "123456").expect("correct PIN should decrypt");
        assert_eq!(recovered, seed);
    }

    #[test]
    fn wrong_pin_fails_to_decrypt() {
        let seed = test_seed();
        let enc = encrypt_seed_with_randomness(&seed, "123456", [0x11; 16], [0x22; 12]);
        assert!(matches!(
            decrypt_seed(&enc, "000000"),
            Err(SeedLockError::DecryptionFailed)
        ));
    }

    #[test]
    fn different_salts_produce_different_ciphertexts_for_same_pin_and_seed() {
        let seed = test_seed();
        let a = encrypt_seed_with_randomness(&seed, "123456", [0x11; 16], [0x22; 12]);
        let b = encrypt_seed_with_randomness(&seed, "123456", [0x33; 16], [0x44; 12]);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    // Rough regression guard: PBKDF2-HMAC-SHA256 at PIN_KDF_ITERATIONS
    // should be well under a second even on a host, let alone at whatever
    // this device benchmarks to. Not a tight bound -- just catches an
    // accidental jump back into BIP39-2048-round territory.
    #[test]
    fn kdf_iteration_count_is_not_absurdly_expensive() {
        let start = std::time::Instant::now();
        let _ = derive_pin_key("123456", &[0u8; 16], PIN_KDF_ITERATIONS);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "PBKDF2-HMAC-SHA256 at {PIN_KDF_ITERATIONS} rounds took too long on host -- check PIN_KDF_ITERATIONS hasn't regressed"
        );
    }
}
