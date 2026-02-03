//! Key derivation using HKDF-SHA256.
//!
//! All key derivations follow the specifications in cryptographic-constants.md § 3-7.
//!
//! # Post-Quantum Key Derivation
//!
//! Additional derivation functions are available for ML-DSA-65 and ML-KEM-768 keys:
//!
//! - `derive_machine_pq_signing_seed`: Derives 32-byte seed for ML-DSA-65
//! - `derive_machine_pq_kem_seed`: Derives 64-byte seed for ML-KEM-768
//! - `derive_machine_keypair_with_scheme`: Derives full key pair with scheme selection

mod identity;
mod machine;
mod pq;
mod session;

pub use identity::{derive_identity_signing_keypair, derive_managed_identity_signing_keypair};
pub use machine::{
    derive_machine_encryption_seed, derive_machine_keypair, derive_machine_seed,
    derive_machine_signing_seed,
};
pub use pq::{
    derive_machine_keypair_with_scheme, derive_machine_pq_kem_seed, derive_machine_pq_signing_seed,
};
pub use session::{derive_jwt_signing_seed, derive_mfa_kek};

use crate::errors::*;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a key using HKDF-SHA256
///
/// # Arguments
///
/// * `ikm` - Input key material
/// * `info` - Domain separation string and context
/// * `output_len` - Length of output key material (default 32 bytes)
///
/// # Returns
///
/// Derived key material of specified length
pub fn hkdf_derive(ikm: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut output = vec![0u8; output_len];

    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::HkdfError)?;

    Ok(output)
}

/// Derive a 32-byte key using HKDF-SHA256
///
/// This is the most common case and returns a fixed-size array.
pub fn hkdf_derive_32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let output = hkdf_derive(ikm, info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&output);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive_is_deterministic() {
        let ikm = b"input key material";
        let info = b"domain:context:v1";

        let output1 = hkdf_derive(ikm, info, 32).unwrap();
        let output2 = hkdf_derive(ikm, info, 32).unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_hkdf_derive_different_info() {
        let ikm = b"input key material";
        let info1 = b"domain:context1:v1";
        let info2 = b"domain:context2:v1";

        let output1 = hkdf_derive(ikm, info1, 32).unwrap();
        let output2 = hkdf_derive(ikm, info2, 32).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hkdf_derive_32() {
        let ikm = b"input key material";
        let info = b"domain:context:v1";

        let output = hkdf_derive_32(ikm, info).unwrap();
        assert_eq!(output.len(), 32);
    }
}
