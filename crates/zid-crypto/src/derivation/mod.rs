//! Key derivation using HKDF-SHA256.
//!
//! PQ-Hybrid machine key derivation is handled by the `zid` crate.
//! This module provides server-specific derivation (managed identity, JWT, MFA)
//! and convenience wrappers around zid's derivation that accept `uuid::Uuid`.

mod identity;
mod session;

pub use identity::{derive_identity_signing_keypair, derive_managed_identity_signing_keypair};
pub use session::{derive_jwt_signing_seed, derive_mfa_kek};

use crate::errors::*;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a PQ-Hybrid [`zid::MachineKeyPair`] from a NeuralKey.
///
/// Convenience wrapper around [`zid::derive_machine_keypair`] that accepts
/// `uuid::Uuid` instead of `IdentityId`/`MachineId`.
pub fn derive_machine_keypair(
    neural_key: &zid::NeuralKey,
    identity_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    epoch: u64,
    capabilities: zid::MachineKeyCapabilities,
) -> Result<zid::MachineKeyPair> {
    zid::derive_machine_keypair(
        neural_key,
        zid::IdentityId::from(*identity_id),
        zid::MachineId::from(*machine_id),
        epoch,
        capabilities,
    )
    .map_err(|_| CryptoError::HkdfError)
}

/// Derive a key using HKDF-SHA256
pub fn hkdf_derive(ikm: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut output = vec![0u8; output_len];
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::HkdfError)?;
    Ok(output)
}

/// Derive a 32-byte key using HKDF-SHA256
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
        let output1 = hkdf_derive(ikm, b"domain:context1:v1", 32).unwrap();
        let output2 = hkdf_derive(ikm, b"domain:context2:v1", 32).unwrap();
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hkdf_derive_32() {
        let output = hkdf_derive_32(b"input key material", b"domain:context:v1").unwrap();
        assert_eq!(output.len(), 32);
    }
}
