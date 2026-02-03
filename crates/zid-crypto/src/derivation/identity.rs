//! Identity key derivations.

use crate::{constants::*, errors::*, keys::Ed25519KeyPair};

use super::hkdf_derive_32;

/// Derive Identity Signing Keypair from Neural Key
///
/// As specified in cryptographic-constants.md § 4.2
///
/// Formula: identity_signing_seed = HKDF(neural_key, "cypher:auth:identity:v1" || identity_id)
///          (private_key, public_key) = Ed25519_derive(identity_signing_seed)
///
/// The Identity Signing Key (formerly "central key") is used to sign identity-level
/// operations such as machine enrollments.
pub fn derive_identity_signing_keypair(
    neural_key: &crate::keys::NeuralKey,
    identity_id: &uuid::Uuid,
) -> Result<([u8; 32], Ed25519KeyPair)> {
    // Build info: "cypher:auth:identity:v1" || identity_id
    let mut info = Vec::with_capacity(DOMAIN_IDENTITY_SIGNING.len() + 16);
    info.extend_from_slice(DOMAIN_IDENTITY_SIGNING.as_bytes());
    info.extend_from_slice(identity_id.as_bytes());

    // Derive signing seed
    let signing_seed = hkdf_derive_32(neural_key.as_bytes(), &info)?;

    // Generate Ed25519 keypair
    let keypair = Ed25519KeyPair::from_seed(&signing_seed)?;
    let public_key = keypair.public_key_bytes();

    Ok((public_key, keypair))
}

/// Derive managed Identity Signing Keypair (server-side)
///
/// Used for managed identities where the ISK is deterministically derived from
/// the service master key and the authentication method used for signup.
///
/// Formula: identity_signing_seed = HKDF(service_master_key || method_type || method_id,
///                                       "cypher:managed:identity:v1")
///          (private_key, public_key) = Ed25519_derive(identity_signing_seed)
///
/// SECURITY: This key is deterministic from service master key.
/// The service operator can regenerate this key. Users should
/// upgrade to self-sovereign for full security.
///
/// # Arguments
///
/// * `service_master_key` - The service's master secret key (32 bytes)
/// * `method_type` - Authentication method type (e.g., "oauth:google", "email", "wallet:evm")
/// * `method_id` - Method-specific identifier (e.g., provider sub claim, email hash, wallet address)
///
/// # Returns
///
/// Tuple of (public_key bytes, Ed25519KeyPair)
pub fn derive_managed_identity_signing_keypair(
    service_master_key: &[u8; 32],
    method_type: &str,
    method_id: &str,
) -> Result<([u8; 32], Ed25519KeyPair)> {
    // Build IKM: service_master_key || method_type || method_id
    let mut ikm = Vec::with_capacity(32 + method_type.len() + method_id.len());
    ikm.extend_from_slice(service_master_key);
    ikm.extend_from_slice(method_type.as_bytes());
    ikm.extend_from_slice(method_id.as_bytes());

    // Derive signing seed using domain separation
    let signing_seed = hkdf_derive_32(&ikm, DOMAIN_MANAGED_IDENTITY.as_bytes())?;

    // Generate Ed25519 keypair from seed
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
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();

        let (public_key, keypair) =
            derive_identity_signing_keypair(&neural_key, &identity_id).unwrap();

        assert_eq!(public_key.len(), 32);
        assert_eq!(keypair.public_key_bytes(), public_key);
    }

    #[test]
    fn test_derive_managed_identity_signing_keypair() {
        let service_master_key = [42u8; 32];
        let method_type = "oauth:google";
        let method_id = "google-user-123";

        let (public_key, keypair) =
            derive_managed_identity_signing_keypair(&service_master_key, method_type, method_id)
                .unwrap();

        assert_eq!(public_key.len(), 32);
        assert_eq!(keypair.public_key_bytes(), public_key);
    }

    #[test]
    fn test_managed_identity_derivation_is_deterministic() {
        let service_master_key = [42u8; 32];
        let method_type = "email";
        let method_id = "user@example.com";

        let (pk1, _) =
            derive_managed_identity_signing_keypair(&service_master_key, method_type, method_id)
                .unwrap();
        let (pk2, _) =
            derive_managed_identity_signing_keypair(&service_master_key, method_type, method_id)
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
        let (pk_wallet, _) = derive_managed_identity_signing_keypair(
            &service_master_key,
            "wallet:evm",
            "0x1234567890123456789012345678901234567890",
        )
        .unwrap();

        assert_ne!(pk_google, pk_email);
        assert_ne!(pk_google, pk_wallet);
        assert_ne!(pk_email, pk_wallet);
    }
}
