//! Identity key derivations.

use crate::{constants::*, errors::*, keys::Ed25519KeyPair};

use super::hkdf_derive_32;

/// Derive Identity Signing Keypair from Neural Key (Ed25519 component)
///
/// This wraps zid's derive_identity_signing_key but returns the Ed25519
/// public key bytes and keypair for backward compatibility with server code.
pub fn derive_identity_signing_keypair(
    neural_key: &crate::keys::NeuralKey,
    identity_id: &uuid::Uuid,
) -> Result<([u8; 32], Ed25519KeyPair)> {
    let mut info = Vec::with_capacity(DOMAIN_IDENTITY_SIGNING.len() + 16);
    info.extend_from_slice(DOMAIN_IDENTITY_SIGNING.as_bytes());
    info.extend_from_slice(identity_id.as_bytes());

    let signing_seed = hkdf_derive_32(neural_key.as_bytes(), &info)?;
    let keypair = Ed25519KeyPair::from_seed(&signing_seed)?;
    let public_key = keypair.public_key_bytes();
    Ok((public_key, keypair))
}

/// Derive managed Identity Signing Keypair (server-side)
///
/// Used for managed identities where the ISK is deterministically derived from
/// the service master key and the authentication method.
pub fn derive_managed_identity_signing_keypair(
    service_master_key: &[u8; 32],
    method_type: &str,
    method_id: &str,
) -> Result<([u8; 32], Ed25519KeyPair)> {
    let mut ikm = Vec::with_capacity(32 + method_type.len() + method_id.len());
    ikm.extend_from_slice(service_master_key);
    ikm.extend_from_slice(method_type.as_bytes());
    ikm.extend_from_slice(method_id.as_bytes());

    let signing_seed = hkdf_derive_32(&ikm, DOMAIN_MANAGED_IDENTITY.as_bytes())?;
    let keypair = Ed25519KeyPair::from_seed(&signing_seed)?;
    let public_key = keypair.public_key_bytes();
    Ok((public_key, keypair))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NeuralKey;

    #[test]
    fn test_derive_identity_signing_keypair() {
        let neural_key = NeuralKey::generate(&mut rand::thread_rng());
        let identity_id = uuid::Uuid::new_v4();
        let (public_key, keypair) =
            derive_identity_signing_keypair(&neural_key, &identity_id).unwrap();
        assert_eq!(public_key.len(), 32);
        assert_eq!(keypair.public_key_bytes(), public_key);
    }

    #[test]
    fn test_derive_managed_identity_signing_keypair() {
        let service_master_key = [42u8; 32];
        let (public_key, keypair) =
            derive_managed_identity_signing_keypair(&service_master_key, "oauth:google", "user-123")
                .unwrap();
        assert_eq!(public_key.len(), 32);
        assert_eq!(keypair.public_key_bytes(), public_key);
    }

    #[test]
    fn test_managed_identity_derivation_is_deterministic() {
        let service_master_key = [42u8; 32];
        let (pk1, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "email", "user@example.com")
                .unwrap();
        let (pk2, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "email", "user@example.com")
                .unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_managed_identity_different_methods() {
        let service_master_key = [42u8; 32];
        let (pk_google, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "oauth:google", "user-123")
                .unwrap();
        let (pk_email, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "email", "user@test.com")
                .unwrap();
        assert_ne!(pk_google, pk_email);
    }
}
