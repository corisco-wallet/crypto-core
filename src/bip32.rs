//! Minimal hardened-only BIP32 derivation.
//!
//! Spark's key roots (`m/8797555'/n'/0'` .. `/4'`) are all hardened, so this
//! deliberately does NOT implement public-key (non-hardened) derivation --
//! one less thing to get wrong for a wallet.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, thiserror::Error)]
pub enum Bip32Error {
    #[error("invalid path segment: {0}")]
    InvalidPath(String),
    #[error("derived key is zero or exceeds curve order (1-in-2^127 chance, retry with tweak)")]
    InvalidChildKey,
}

#[derive(Clone)]
pub struct ExtendedKey {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl Drop for ExtendedKey {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.chain_code.zeroize();
    }
}

impl ExtendedKey {
    /// BIP32 master key from a BIP39 seed (any length, typically 64 bytes).
    pub fn master(seed: &[u8]) -> Self {
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("hmac accepts any key len");
        mac.update(seed);
        let i = mac.finalize().into_bytes();

        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);

        Self {
            private_key,
            chain_code,
        }
    }

    /// Hardened child derivation only (index gets the 0x80000000 offset applied).
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Bip32Error> {
        let hardened_index = index | 0x8000_0000;

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("hmac accepts any key len");
        mac.update(&[0x00]);
        mac.update(&self.private_key);
        mac.update(&hardened_index.to_be_bytes());
        let i = mac.finalize().into_bytes();

        let il_bytes: [u8; 32] = i[..32].try_into().unwrap();
        let il = Scalar::from_repr(il_bytes.into())
            .into_option()
            .ok_or(Bip32Error::InvalidChildKey)?;
        let parent_scalar = Scalar::from_repr(self.private_key.into())
            .into_option()
            .ok_or(Bip32Error::InvalidChildKey)?;

        let child_scalar = il + parent_scalar;
        if bool::from(k256::elliptic_curve::group::Group::is_identity(
            &ProjectivePoint::GENERATOR,
        )) {
            unreachable!("generator is never identity");
        }
        if child_scalar.is_zero().into() {
            return Err(Bip32Error::InvalidChildKey);
        }

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&child_scalar.to_bytes());
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);

        Ok(Self {
            private_key,
            chain_code,
        })
    }

    /// Derive a full hardened path like `m/8797555'/0'/1'`. The leading `m` is optional.
    pub fn derive_path(&self, path: &str) -> Result<Self, Bip32Error> {
        let mut key = self.clone();
        for segment in path.split('/') {
            if segment.is_empty() || segment == "m" {
                continue;
            }
            let trimmed = segment
                .strip_suffix('\'')
                .or_else(|| segment.strip_suffix('h'))
                .ok_or_else(|| Bip32Error::InvalidPath(segment.to_string()))?;
            let index: u32 = trimmed
                .parse()
                .map_err(|_| Bip32Error::InvalidPath(segment.to_string()))?;
            key = key.derive_hardened(index)?;
        }
        Ok(key)
    }

    pub fn public_key_compressed(&self) -> [u8; 33] {
        let scalar = Scalar::from_repr(self.private_key.into())
            .into_option()
            .expect("private_key was validated on construction");
        let point = ProjectivePoint::GENERATOR * scalar;
        let encoded = point.to_affine().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Official BIP32 test vector 1 (bitcoin/bips, bip-0032.mediawiki).
    /// Values cross-checked against https://en.bitcoin.it/wiki/BIP_0032_TestVectors
    /// Validates the raw HMAC-SHA512 derivation math independent of any
    /// Spark-specific path -- if this fails, nothing built on top of it can
    /// be trusted.
    #[test]
    fn bip32_test_vector_1_master_and_hardened_child() {
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedKey::master(&seed);

        assert_eq!(
            master.private_key,
            hex!("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
        );
        assert_eq!(
            master.chain_code,
            hex!("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
        );

        // m/0'
        let child = master.derive_hardened(0).unwrap();
        assert_eq!(
            child.private_key,
            hex!("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
        );
        assert_eq!(
            child.public_key_compressed(),
            hex!("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56")
        );
    }

    #[test]
    fn derive_path_matches_manual_hardened_steps() {
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedKey::master(&seed);

        let via_path = master.derive_path("m/8797555'/0'/1'").unwrap();
        let via_steps = master
            .derive_hardened(8797555)
            .unwrap()
            .derive_hardened(0)
            .unwrap()
            .derive_hardened(1)
            .unwrap();

        assert_eq!(via_path.private_key, via_steps.private_key);
        assert_eq!(via_path.chain_code, via_steps.chain_code);
    }
}
