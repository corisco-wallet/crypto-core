//! Feldman Verifiable Secret Sharing, matching Spark's actual reference
//! implementation (`signer/spark-frost/src/vss.rs` in buildonspark/spark)
//! so the shares/proofs this produces are accepted by real Signing
//! Operators -- same algorithm (Shamir via `vsss-rs`'s `feldman` module),
//! same byte encodings (32-byte big-endian scalars, 33-byte compressed
//! SEC1 points).

use k256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField};
#[cfg(test)]
use k256::{elliptic_curve::group::GroupEncoding, AffinePoint};
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;
#[cfg(test)]
use vsss_rs::ReadableShareSet;
use vsss_rs::{feldman, FeldmanVerifierSet, IdentifierPrimeField, Share, ValueGroup};

/// A share of a secret produced by Shamir's Secret Sharing.
pub struct SecretShare {
    pub threshold: usize,
    /// 1-based index (evaluation point).
    pub index: u32,
    /// 32-byte big-endian scalar value.
    pub share: [u8; 32],
}

/// A share of a secret together with Feldman VSS commitments.
pub struct VerifiableSecretShare {
    pub share: SecretShare,
    /// Compressed SEC1 pubkeys (33 bytes each), one per coefficient.
    pub proofs: Vec<[u8; 33]>,
}

type VsssShare = (IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>);
type VsssVerifier = ValueGroup<ProjectivePoint>;

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, String> {
    Option::from(Scalar::from_repr((*bytes).into()))
        .ok_or_else(|| "invalid scalar encoding".to_string())
}

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

#[cfg(test)]
fn point_from_compressed(bytes: &[u8; 33]) -> Result<ProjectivePoint, String> {
    Option::<AffinePoint>::from(AffinePoint::from_bytes((*bytes).as_slice().into()))
        .map(ProjectivePoint::from)
        .ok_or_else(|| "malformed public key: invalid encoding".to_string())
}

fn point_to_compressed(p: &ProjectivePoint) -> [u8; 33] {
    let encoded = p.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn scalar_to_index(s: &Scalar) -> u32 {
    let bytes = s.to_bytes();
    u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]])
}

/// Extract proofs (coefficient commitments) from the vsss-rs verifier set.
/// vsss-rs Vec layout: [generator, v0, v1, ..., v_{t-1}]
/// Our proofs format: [v0, v1, ..., v_{t-1}]
fn verifier_set_to_proofs(verifier_set: &Vec<VsssVerifier>) -> Vec<[u8; 33]> {
    <Vec<VsssVerifier> as FeldmanVerifierSet<VsssShare, VsssVerifier>>::verifiers(verifier_set)
        .iter()
        .map(|v| point_to_compressed(&v.0))
        .collect()
}

/// Split `secret` into `num_shares` verifiable shares with Feldman proofs.
///
/// `threshold` must be >= 2 and `num_shares` must be >= `threshold`.
pub fn split_secret_with_proofs(
    secret: &[u8; 32],
    threshold: usize,
    num_shares: usize,
) -> Result<Vec<VerifiableSecretShare>, String> {
    if threshold < 2 {
        return Err(format!("threshold must be >= 2, got {threshold}"));
    }
    if num_shares < threshold {
        return Err(format!(
            "num_shares must be >= threshold, got num_shares={num_shares}, threshold={threshold}"
        ));
    }

    let secret_scalar = scalar_from_bytes(secret)?;

    let (shares, verifier_set): (Vec<VsssShare>, Vec<VsssVerifier>) = feldman::split_secret(
        threshold,
        num_shares,
        &IdentifierPrimeField(secret_scalar),
        None,
        OsRng,
    )
    .map_err(|e| format!("vsss split_secret failed: {e:?}"))?;

    let proofs = verifier_set_to_proofs(&verifier_set);

    Ok(shares
        .iter()
        .map(|s| VerifiableSecretShare {
            share: SecretShare {
                threshold,
                index: scalar_to_index(&s.identifier().0),
                share: scalar_to_bytes(&s.value().0),
            },
            proofs: proofs.clone(),
        })
        .collect())
}

#[cfg(test)]
fn to_vsss_share(index: u32, share_bytes: &[u8; 32]) -> Result<VsssShare, String> {
    let value = scalar_from_bytes(share_bytes)?;
    let id = IdentifierPrimeField(Scalar::from(index as u64));
    Ok((id, IdentifierPrimeField(value)))
}

/// Recover the secret from a set of shares using Lagrange interpolation.
/// Only used by this crate's own host tests, to round-trip-verify
/// `split_secret_with_proofs` -- the bridge itself never reconstructs a
/// secret from shares (that's the Signing Operators' job).
#[cfg(test)]
pub fn recover_secret(shares: &[SecretShare]) -> Result<[u8; 32], String> {
    if shares.is_empty() {
        return Err("no shares provided".to_string());
    }
    if shares.len() < shares[0].threshold {
        return Err("not enough shares to recover secret".to_string());
    }

    let vsss_shares: Vec<VsssShare> = shares
        .iter()
        .map(|s| to_vsss_share(s.index, &s.share))
        .collect::<Result<Vec<_>, _>>()?;

    let recovered: IdentifierPrimeField<Scalar> = vsss_shares
        .combine()
        .map_err(|e| format!("vsss combine failed: {e:?}"))?;

    Ok(scalar_to_bytes(&recovered.0))
}

/// Validate a verifiable secret share against its Feldman commitments.
/// Only used by this crate's own host tests.
#[cfg(test)]
pub fn validate_share(share: &SecretShare, proofs: &[[u8; 33]]) -> Result<(), String> {
    if proofs.len() != share.threshold {
        return Err(format!(
            "invalid VSS proof length: expected {}, got {}",
            share.threshold,
            proofs.len()
        ));
    }

    let vsss_share = to_vsss_share(share.index, &share.share)?;
    let mut set = Vec::with_capacity(proofs.len() + 1);
    set.push(ValueGroup(ProjectivePoint::GENERATOR));
    for p in proofs {
        set.push(ValueGroup(point_from_compressed(p)?));
    }

    set.verify_share(&vsss_share)
        .map_err(|_| "share is not valid".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;

    fn random_secret() -> [u8; 32] {
        scalar_to_bytes(&Scalar::random(&mut OsRng))
    }

    #[test]
    fn split_and_recover_round_trips() {
        let secret = random_secret();
        let shares = split_secret_with_proofs(&secret, 3, 5).unwrap();

        for vs in &shares {
            validate_share(&vs.share, &vs.proofs).unwrap();
        }

        let plain: Vec<SecretShare> = shares
            .iter()
            .map(|vs| SecretShare {
                threshold: vs.share.threshold,
                index: vs.share.index,
                share: vs.share.share,
            })
            .collect();
        let recovered = recover_secret(&plain[..3]).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn not_enough_shares_fails_to_recover() {
        let secret = random_secret();
        let shares = split_secret_with_proofs(&secret, 3, 5).unwrap();
        let plain: Vec<SecretShare> = shares
            .iter()
            .map(|vs| SecretShare {
                threshold: vs.share.threshold,
                index: vs.share.index,
                share: vs.share.share,
            })
            .collect();
        let err = recover_secret(&plain[..2]).unwrap_err();
        assert!(err.contains("not enough shares"));
    }

    #[test]
    fn corrupted_proof_fails_validation() {
        let secret = random_secret();
        let mut shares = split_secret_with_proofs(&secret, 3, 5).unwrap();
        shares[0].proofs[0][0] ^= 0xFF;
        assert!(validate_share(&shares[0].share, &shares[0].proofs).is_err());
    }
}
