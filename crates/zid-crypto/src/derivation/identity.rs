//! Identity key derivations.

use crate::errors::*;
use zid::IdentitySigningKey;

/// Derive Identity Signing Keypair from Neural Key.
///
/// Returns the serialized hybrid verifying key bytes and the signing key.
pub fn derive_identity_signing_keypair(
    neural_key: &crate::keys::NeuralKey,
    identity_id: &uuid::Uuid,
) -> Result<(Vec<u8>, IdentitySigningKey)> {
    let id = zid::IdentityId::from(*identity_id.as_bytes());
    let isk = zid::derive_identity_signing_key(neural_key, id)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    let vk_bytes = isk.verifying_key().to_bytes();
    Ok((vk_bytes, isk))
}

/// Derive managed Identity Signing Keypair (server-side).
///
/// Used for managed identities where the ISK is deterministically derived from
/// the service master key and the authentication method.
pub fn derive_managed_identity_signing_keypair(
    service_master_key: &[u8; 32],
    method_type: &str,
    method_id: &str,
) -> Result<(Vec<u8>, IdentitySigningKey)> {
    use crate::constants::DOMAIN_MANAGED_IDENTITY;
    use super::hkdf_derive_32;

    // Derive Ed25519 seed
    let mut ikm = Vec::with_capacity(32 + method_type.len() + method_id.len());
    ikm.extend_from_slice(service_master_key);
    ikm.extend_from_slice(method_type.as_bytes());
    ikm.extend_from_slice(method_id.as_bytes());

    let ed_seed = hkdf_derive_32(&ikm, DOMAIN_MANAGED_IDENTITY.as_bytes())?;

    // Derive ML-DSA-65 seed with separate domain
    let pq_seed = hkdf_derive_32(&ikm, b"cypher:managed:identity:pq-sign:v1")?;

    let isk = IdentitySigningKey::from_seeds(ed_seed, pq_seed);
    let vk_bytes = isk.verifying_key().to_bytes();
    Ok((vk_bytes, isk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NeuralKey;
    use zid::IdentityVerifyingKey;

    #[test]
    fn test_derive_identity_signing_keypair() {
        let neural_key = NeuralKey::generate(&mut rand::thread_rng());
        let identity_id = uuid::Uuid::new_v4();
        let (vk_bytes, isk) =
            derive_identity_signing_keypair(&neural_key, &identity_id).unwrap();
        assert_eq!(vk_bytes.len(), 1984);
        // Verify round-trip
        let vk = IdentityVerifyingKey::from_bytes(&vk_bytes).unwrap();
        let msg = b"test";
        let sig = isk.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_derive_managed_identity_signing_keypair() {
        let service_master_key = [42u8; 32];
        let (vk_bytes, isk) =
            derive_managed_identity_signing_keypair(&service_master_key, "oauth:google", "user-123")
                .unwrap();
        assert_eq!(vk_bytes.len(), 1984);
        let vk = IdentityVerifyingKey::from_bytes(&vk_bytes).unwrap();
        let msg = b"test";
        let sig = isk.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_managed_identity_derivation_is_deterministic() {
        let service_master_key = [42u8; 32];
        let (vk1, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "email", "user@example.com")
                .unwrap();
        let (vk2, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "email", "user@example.com")
                .unwrap();
        assert_eq!(vk1, vk2);
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
