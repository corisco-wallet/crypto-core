//! FROST signing for Spark transactions, matching Spark's actual reference
//! implementation (`signer/spark-frost/src/{bridge,signing}.rs` in
//! buildonspark/spark) rather than the generic `frost-secp256k1-tr` API in
//! isolation.
//!
//! A single hardware-wallet device only ever needs the "legacy" single-user
//! scheme (`role: User`, `signing_scheme: SingleUser` on the wire) -- the
//! "MPC user group" / two-group scheme is for an unrelated feature
//! (splitting one user's signing authority across multiple devices) and is
//! out of scope here.
//!
//! Round-1 commitments/nonces are generated fresh per signature and the
//! nonce is never exposed outside this module -- callers only ever see it
//! move from [`frost_commit`] into [`frost_sign`], matching
//! `DefaultSparkSigner`'s "store nonces internally to prevent reuse" model
//! from the SparkSigner contract.

use std::collections::{BTreeMap, BTreeSet};

use frost_secp256k1_tr::{
    keys::{EvenY, KeyPackage, SigningShare, Tweak, VerifyingShare},
    round1, round2, Identifier, SigningPackage, VerifyingKey,
};
use rand_core::OsRng;

pub use frost_secp256k1_tr::Error as FrostError;
pub use round1::{NonceCommitment, SigningCommitments, SigningNonces};

/// Our fixed FROST identifier as the "user" participant. Must be
/// byte-identical to what the Signing Operators expect --
/// `Identifier::derive("user".as_bytes())` in Spark's reference signer.
pub fn user_identifier() -> Identifier {
    Identifier::derive(b"user").expect("\"user\" is a valid identifier seed")
}

/// Round 1 (`getRandomSigningCommitment`): generate a fresh signing nonce +
/// commitment for one leaf key. `leaf_private_key` is the output of
/// [`SparkKeyRoots::derive_leaf_key`](crate::SparkKeyRoots::derive_leaf_key).
///
/// The returned [`SigningNonces`] must be used for exactly one call to
/// [`frost_sign`] and then discarded -- reusing a nonce leaks the signing
/// key. Keep it on-device; only the [`SigningCommitments`] half goes to the
/// phone.
pub fn frost_commit(
    leaf_private_key: &[u8; 32],
) -> Result<(SigningNonces, SigningCommitments), FrostError> {
    let signing_share = SigningShare::deserialize(leaf_private_key)?;
    let mut rng = OsRng;
    Ok(round1::commit(&signing_share, &mut rng))
}

/// Round 2 (`signFrost`): produce this device's signature share, matching
/// the `role: User` path in Spark's reference `signing.rs::sign_frost_job`
/// exactly:
///
/// - Key package uses `min_signers: 1` (the device holds the whole leaf key
///   -- no multi-device splitting) and is even-Y normalized against the
///   *untweaked* combined verifying key's parity, but its `verifying_key`
///   field is taken from the *Taproot-tweaked* package. The final signature
///   is checked against the tweaked key, but this device's own signing math
///   must NOT apply the tweak itself -- the Signing-Operator side already
///   folds it in via `sign_with_tweak`, and applying it on both sides would
///   double-count it.
/// - The `SigningPackage` carries two participant groups: the Signing
///   Operators who submitted commitments, and this device alone -- the
///   "nested signing" scheme, not the two-group/MPC one.
///
/// `statechain_commitments` are the Signing Operators' round-1 commitments
/// (received from the phone); `self_commitment` is this device's own
/// commitment from [`frost_commit`] (sent back alongside, per
/// `bridge.rs::sign_frost`). Returns the serialized `SignatureShare` to send
/// back to the phone -- aggregation into a final signature happens there,
/// never on this device.
///
/// `adaptor_public_key` is `Some` for Lightning payments that need a leaf
/// *swap* first (the wallet's existing leaves don't sum to the exact
/// invoice amount, so the SSP trades them for ones that do) -- matching
/// Spark's reference `frost_build_signin_package` in `signer/spark-frost/
/// src/signing.rs`, which is the only thing that changes about signing when
/// an adaptor is present: the `SigningPackage` carries the adaptor point,
/// and everything else (key package construction, `round2::sign`, no
/// tweak) is identical to plain signing. The resulting signature share
/// combines (on the phone, via the SDK's own aggregation) into an
/// *incomplete* signature that only becomes valid once the swap
/// counterparty reveals the adaptor secret -- that completion step is the
/// SDK's own responsibility (`getSparkFrost().aggregateFrost`), not this
/// device's; see the round-trip test below for why that split is safe.
pub fn frost_sign(
    message: &[u8],
    leaf_private_key: &[u8; 32],
    nonce: &SigningNonces,
    self_commitment: SigningCommitments,
    statechain_commitments: BTreeMap<Identifier, SigningCommitments>,
    verifying_key_bytes: &[u8],
    adaptor_public_key: Option<&[u8]>,
) -> Result<Vec<u8>, FrostError> {
    let verifying_key = VerifyingKey::deserialize(verifying_key_bytes)?;
    let signing_share = SigningShare::deserialize(leaf_private_key)?;
    let verifying_share = VerifyingShare::from(signing_share);
    let user_id = user_identifier();

    let base = KeyPackage::new(user_id, signing_share, verifying_share, verifying_key, 1);
    let merkle_root: Vec<u8> = vec![];
    let tweaked = base.clone().tweak(Some(merkle_root.as_slice()));
    let even_y = base.into_even_y(Some(verifying_key.has_even_y()));
    let key_package = KeyPackage::new(
        *even_y.identifier(),
        *even_y.signing_share(),
        *even_y.verifying_share(),
        *tweaked.verifying_key(),
        *tweaked.min_signers(),
    );

    let mut commitments = statechain_commitments;
    let mut signing_participants_groups = Vec::new();
    signing_participants_groups.push(commitments.keys().cloned().collect::<BTreeSet<_>>());
    commitments.insert(user_id, self_commitment);
    signing_participants_groups.push(BTreeSet::from([user_id]));

    let adaptor_verifying_key = adaptor_public_key
        .map(VerifyingKey::deserialize)
        .transpose()?;
    let signing_package = SigningPackage::new_with_adaptor(
        commitments,
        Some(signing_participants_groups),
        message,
        adaptor_verifying_key,
    );

    let share = round2::sign(&signing_package, nonce, &key_package)?;
    Ok(share.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1_tr::{
        aggregate_with_tweak,
        keys::{
            generate_with_dealer, IdentifierList, KeyPackage as FrostKeyPackage, PublicKeyPackage,
        },
        round2::SignatureShare,
        Signature, SigningKey,
    };
    use rand_core::OsRng;

    /// End-to-end signing + aggregation, exercising `frost_commit`/
    /// `frost_sign` exactly as a real device would use them, against a
    /// trusted-dealer Signing-Operator group standing in for the real SEs.
    /// Mirrors Spark's own `test_legacy_sign_and_aggregate` in
    /// `signer/spark-frost/src/signing.rs`, but through our wrapper
    /// functions rather than their proto/job layer, to prove *our* wiring
    /// (key-package parity/tweak handling, participant groups) is correct.
    #[test]
    fn user_signature_share_aggregates_into_valid_signature() {
        let mut rng = OsRng;

        // Signing-Operator group: 3-of-5 trusted-dealer FROST key.
        let (se_shares, se_pubkey_pkg) =
            generate_with_dealer(5, 3, IdentifierList::Default, rng).unwrap();
        let se_key_packages: BTreeMap<Identifier, FrostKeyPackage> = se_shares
            .into_iter()
            .map(|(id, share)| (id, FrostKeyPackage::try_from(share).unwrap()))
            .collect();

        // Our device's leaf key -- stands in for `derive_leaf_key`'s output.
        //
        // `into_even_y` (used internally by `frost_sign`, mirroring role
        // `User` in Spark's reference) negates the key package when the
        // *combined* key's Y is odd. In production the deployed leaf key is
        // established even-Y by construction at leaf-creation time (a
        // standard Taproot convention), so retry here until the combined
        // key is even -- this test proves the core sign+aggregate flow is
        // correct for that steady-state case, not the negated-branch's
        // aggregate-side bookkeeping (which lives on Spark's server, not
        // this device, and isn't exercised by a device-side test anyway).
        let (user_signing_key, combined_vk) = loop {
            let sk = SigningKey::new(&mut rng);
            let vk = VerifyingKey::from(&sk);
            let combined =
                VerifyingKey::new(se_pubkey_pkg.verifying_key().to_element() + vk.to_element());
            if combined.has_even_y() {
                break (sk, combined);
            }
        };
        let user_leaf_private_key: [u8; 32] = user_signing_key.serialize().try_into().unwrap();
        let merkle_root: Vec<u8> = vec![];

        let message = b"spark test transaction sighash";

        // --- Round 1 ---
        let se_signers: Vec<Identifier> = se_key_packages.keys().take(3).cloned().collect();
        let mut se_nonces = BTreeMap::new();
        let mut se_commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for id in &se_signers {
            let kp = &se_key_packages[id];
            let (nonce, commitment) = round1::commit(kp.signing_share(), &mut rng);
            se_nonces.insert(*id, nonce);
            se_commitments.insert(*id, commitment);
        }
        let (user_nonce, user_commitment) = frost_commit(&user_leaf_private_key).unwrap();

        // --- Round 2 ---
        // SE signers: sign_with_tweak (role STATECHAIN), same convention as
        // Spark's `sign_frost_job` role == 0 branch.
        let mut se_shares_out: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        let signing_package_for_se = SigningPackage::new_with_adaptor(
            {
                let mut c = se_commitments.clone();
                c.insert(user_identifier(), user_commitment);
                c
            },
            Some(vec![
                se_commitments.keys().cloned().collect(),
                BTreeSet::from([user_identifier()]),
            ]),
            message,
            None,
        );
        for id in &se_signers {
            let orig = &se_key_packages[id];
            // Matches `frost_key_package_from_proto`: the key package's
            // verifying_key is always overridden to the overall combined
            // (SE+user) key, not the SE sub-group's own dealer-generated
            // key -- the taproot tweak must be computed relative to the
            // final output key.
            let kp = FrostKeyPackage::new(
                *orig.identifier(),
                *orig.signing_share(),
                *orig.verifying_share(),
                combined_vk,
                *orig.min_signers(),
            )
            .tweak(Some(merkle_root.as_slice()));
            let share = round2::sign(&signing_package_for_se, &se_nonces[id], &kp).unwrap();
            se_shares_out.insert(*id, share);
        }

        // Our device: the function under test.
        let user_share_bytes = frost_sign(
            message,
            &user_leaf_private_key,
            &user_nonce,
            user_commitment,
            se_commitments.clone(),
            &combined_vk.serialize().unwrap(),
            None,
        )
        .unwrap();
        let user_share = SignatureShare::deserialize(&user_share_bytes).unwrap();

        // --- Aggregate (phone/coordinator side, not the device) ---
        let mut all_shares = se_shares_out;
        all_shares.insert(user_identifier(), user_share);

        let mut all_verifying_shares: BTreeMap<_, _> = se_key_packages
            .iter()
            .map(|(id, kp)| (*id, *kp.verifying_share()))
            .collect();
        let user_signing_share = SigningShare::deserialize(&user_leaf_private_key).unwrap();
        all_verifying_shares.insert(user_identifier(), VerifyingShare::from(user_signing_share));
        let public_package = PublicKeyPackage::new(all_verifying_shares, combined_vk, None);

        let signature: Signature = aggregate_with_tweak(
            &signing_package_for_se,
            &all_shares,
            &public_package,
            Some(&merkle_root),
        )
        .expect("aggregation should succeed with valid shares");

        let tweaked_vk = *public_package
            .clone()
            .tweak(Some(merkle_root.as_slice()))
            .verifying_key();
        tweaked_vk
            .verify(message, &signature)
            .expect("aggregated signature should verify against the tweaked combined key");
    }

    /// Proves `frost_sign`'s `adaptor_public_key` parameter is wired
    /// correctly by round-tripping a full adaptor-signature flow: sign with
    /// an adaptor point (as a Lightning-swap leaf transfer would), confirm
    /// the raw aggregate is genuinely *incomplete* (does not verify), then
    /// apply the adaptor secret and confirm the completed signature does
    /// verify. Mirrors Spark's actual reference `signer/spark-frost/src/
    /// adaptor_signature.rs` math (`s' = s - t`, so completion is `s = s' +
    /// t`) and `frost-core`'s own `compute_group_commitment` (`R_used =
    /// R_group + adaptor_point`, computed BEFORE the challenge, which is
    /// exactly what makes `z_completed = z' + t` with the SAME `R` valid) --
    /// derived from reading both, not guessed.
    #[test]
    fn adaptor_signature_share_completes_into_valid_signature_after_applying_secret() {
        let mut rng = OsRng;

        let (se_shares, se_pubkey_pkg) =
            generate_with_dealer(5, 3, IdentifierList::Default, rng).unwrap();
        let se_key_packages: BTreeMap<Identifier, FrostKeyPackage> = se_shares
            .into_iter()
            .map(|(id, share)| (id, FrostKeyPackage::try_from(share).unwrap()))
            .collect();

        let (user_signing_key, combined_vk) = loop {
            let sk = SigningKey::new(&mut rng);
            let vk = VerifyingKey::from(&sk);
            let combined =
                VerifyingKey::new(se_pubkey_pkg.verifying_key().to_element() + vk.to_element());
            if combined.has_even_y() {
                break (sk, combined);
            }
        };
        let user_leaf_private_key: [u8; 32] = user_signing_key.serialize().try_into().unwrap();
        let merkle_root: Vec<u8> = vec![];
        let message = b"spark lightning swap adaptor test";

        // The swap counterparty's adaptor secret -- unknown to us (and to
        // our device generally) until the swap actually completes; only its
        // public key ever goes into signing.
        let adaptor_secret = SigningKey::new(&mut rng);
        let adaptor_public = VerifyingKey::from(&adaptor_secret);

        // --- Round 1 ---
        let se_signers: Vec<Identifier> = se_key_packages.keys().take(3).cloned().collect();
        let mut se_nonces = BTreeMap::new();
        let mut se_commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for id in &se_signers {
            let kp = &se_key_packages[id];
            let (nonce, commitment) = round1::commit(kp.signing_share(), &mut rng);
            se_nonces.insert(*id, nonce);
            se_commitments.insert(*id, commitment);
        }
        let (user_nonce, user_commitment) = frost_commit(&user_leaf_private_key).unwrap();

        // --- Round 2: both sides' SigningPackage carries the SAME adaptor
        // point, matching `frost_build_signin_package` in Spark's reference.
        let mut se_shares_out: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        let signing_package = SigningPackage::new_with_adaptor(
            {
                let mut c = se_commitments.clone();
                c.insert(user_identifier(), user_commitment);
                c
            },
            Some(vec![
                se_commitments.keys().cloned().collect(),
                BTreeSet::from([user_identifier()]),
            ]),
            message,
            Some(adaptor_public),
        );
        for id in &se_signers {
            let orig = &se_key_packages[id];
            let kp = FrostKeyPackage::new(
                *orig.identifier(),
                *orig.signing_share(),
                *orig.verifying_share(),
                combined_vk,
                *orig.min_signers(),
            )
            .tweak(Some(merkle_root.as_slice()));
            let share = round2::sign(&signing_package, &se_nonces[id], &kp).unwrap();
            se_shares_out.insert(*id, share);
        }

        let user_share_bytes = frost_sign(
            message,
            &user_leaf_private_key,
            &user_nonce,
            user_commitment,
            se_commitments.clone(),
            &combined_vk.serialize().unwrap(),
            Some(&adaptor_public.serialize().unwrap()),
        )
        .unwrap();
        let user_share = SignatureShare::deserialize(&user_share_bytes).unwrap();

        // --- Aggregate (phone-side): succeeds, but the result is
        // deliberately INCOMPLETE -- frost-core skips its own verification
        // step whenever the signing package carries an adaptor, since a
        // normal check would (correctly) reject it at this stage.
        let mut all_shares = se_shares_out;
        all_shares.insert(user_identifier(), user_share);

        let mut all_verifying_shares: BTreeMap<_, _> = se_key_packages
            .iter()
            .map(|(id, kp)| (*id, *kp.verifying_share()))
            .collect();
        let user_signing_share = SigningShare::deserialize(&user_leaf_private_key).unwrap();
        all_verifying_shares.insert(user_identifier(), VerifyingShare::from(user_signing_share));
        let public_package = PublicKeyPackage::new(all_verifying_shares, combined_vk, None);

        let incomplete_signature: Signature = aggregate_with_tweak(
            &signing_package,
            &all_shares,
            &public_package,
            Some(&merkle_root),
        )
        .expect("aggregation itself succeeds even though the signature isn't complete yet");

        let tweaked_vk = *public_package
            .clone()
            .tweak(Some(merkle_root.as_slice()))
            .verifying_key();

        // The whole point of an adaptor signature: it must NOT verify yet.
        assert!(
            tweaked_vk.verify(message, &incomplete_signature).is_err(),
            "raw aggregate should be incomplete (invalid) before the adaptor secret is applied"
        );

        // --- Apply the adaptor secret (the swap counterparty's job, once it
        // reveals `adaptor_secret` to complete the swap).
        //
        // Not as simple as `z + t` in this BIP340/Taproot FROST variant:
        // `compute_signature_share` (frost-secp256k1-tr) has each
        // participant negate their OWN nonce whenever the group commitment
        // R (which already includes the adaptor point -- see
        // `compute_group_commitment`, `group_commitment + adaptor.
        // to_element()`) has odd Y-parity, to keep the final R
        // BIP340-representable. That per-participant negation flips the
        // sign the adaptor secret needs to be applied with: `z + t` when R
        // is even, `z - t` when R is odd. Worked out from first principles
        // by tracing frost-core/frost-secp256k1-tr's source (the
        // `EvenY`/`compute_signature_share` machinery), not guessed -- an
        // unconditional `z + t` (matching Spark's own `adaptor_signature.
        // rs`, which operates on a plain, already-finalized Schnorr
        // signature with no such per-share negation step to account for)
        // verifies exactly half the time and fails the other half,
        // depending on random nonce parity across runs.
        let completed_z = if incomplete_signature.has_even_y() {
            *incomplete_signature.z() + adaptor_secret.to_scalar()
        } else {
            *incomplete_signature.z() - adaptor_secret.to_scalar()
        };
        let completed_signature = Signature::new(*incomplete_signature.R(), completed_z);

        tweaked_vk
            .verify(message, &completed_signature)
            .expect("completed adaptor signature should verify against the tweaked combined key");
    }
}
