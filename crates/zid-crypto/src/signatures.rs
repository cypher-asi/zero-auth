//! Digital signature operations using Ed25519.

use crate::{constants::*, errors::*};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Challenge for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID
    pub challenge_id: Uuid,
    /// Machine ID or entity ID this challenge is for
    pub entity_id: Uuid,
    /// Entity type (machine, wallet, email)
    pub entity_type: EntityType,
    /// Purpose of the challenge
    pub purpose: String,
    /// Audience (service URL)
    pub aud: String,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiry timestamp
    pub exp: u64,
    /// Random nonce
    pub nonce: [u8; 32],
    /// Whether challenge has been used (replay protection)
    pub used: bool,
}

/// Entity type for challenges
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum EntityType {
    /// Machine key authentication
    Machine = 0x01,
    /// Wallet signature authentication
    Wallet = 0x02,
    /// Email + password authentication
    Email = 0x03,
}

impl Challenge {
    /// Create a new challenge for machine authentication
    pub fn new_for_machine(machine_id: Uuid) -> Self {
        let timestamp = crate::current_timestamp();
        let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        Self {
            challenge_id: Uuid::new_v4(),
            entity_id: machine_id,
            entity_type: EntityType::Machine,
            purpose: "authentication".to_string(),
            aud: "cypher".to_string(),
            iat: timestamp,
            exp: timestamp + CHALLENGE_EXPIRY_SECONDS,
            nonce,
            used: false,
        }
    }

    /// Create a new challenge for wallet authentication
    ///
    /// For wallets, the entity_id is derived from the wallet address hash.
    pub fn new_for_wallet(wallet_address: &str) -> Self {
        let timestamp = crate::current_timestamp();
        let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        // Derive a UUID from wallet address for entity_id
        let address_hash = crate::hashing::blake3_hash(wallet_address.as_bytes());
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&address_hash[..16]);
        let entity_id = Uuid::from_bytes(uuid_bytes);

        Self {
            challenge_id: Uuid::new_v4(),
            entity_id,
            entity_type: EntityType::Wallet,
            purpose: "wallet_auth".to_string(),
            aud: "cypher".to_string(),
            iat: timestamp,
            exp: timestamp + CHALLENGE_EXPIRY_SECONDS,
            nonce,
            used: false,
        }
    }

    /// Create a new challenge for email authentication
    pub fn new_for_email(email: &str) -> Self {
        let timestamp = crate::current_timestamp();
        let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        // Derive a UUID from email for entity_id
        let email_hash = crate::hashing::blake3_hash(email.as_bytes());
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&email_hash[..16]);
        let entity_id = Uuid::from_bytes(uuid_bytes);

        Self {
            challenge_id: Uuid::new_v4(),
            entity_id,
            entity_type: EntityType::Email,
            purpose: "email_auth".to_string(),
            aud: "cypher".to_string(),
            iat: timestamp,
            exp: timestamp + CHALLENGE_EXPIRY_SECONDS,
            nonce,
            used: false,
        }
    }

    /// Get the challenge ID
    pub fn id(&self) -> Uuid {
        self.challenge_id
    }

    /// Check if challenge is expired
    pub fn is_expired(&self) -> bool {
        crate::current_timestamp() > self.exp
    }
}

/// Verify an Ed25519 signature
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key (32 bytes)
/// * `message` - The message that was signed
/// * `signature` - The signature to verify (64 bytes)
///
/// # Returns
///
/// `Ok(())` if signature is valid, `Err` otherwise
pub fn verify_ed25519_signature(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::Ed25519Error(e.to_string()))?;

    let sig = Signature::from_bytes(signature);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Create a canonical binary message for identity creation authorization
///
/// As specified in 03-identity-core.md § 3.3
///
/// Format: version(1) || identity_id(16) || isk_len(2 BE u16) ||
///         identity_signing_public_key(var) || first_machine_id(16) ||
///         machine_signing_key(32) || machine_encryption_key(32) || created_at(8)
pub fn canonicalize_identity_creation_message(
    identity_id: &uuid::Uuid,
    identity_signing_public_key: &[u8],
    first_machine_id: &uuid::Uuid,
    machine_signing_key: &[u8; 32],
    machine_encryption_key: &[u8; 32],
    created_at: u64,
) -> Vec<u8> {
    let isk_len = identity_signing_public_key.len() as u16;
    let total = 1 + 16 + 2 + identity_signing_public_key.len() + 16 + 32 + 32 + 8;
    let mut message = Vec::with_capacity(total);

    message.push(0x01); // Version
    message.extend_from_slice(identity_id.as_bytes());
    message.extend_from_slice(&isk_len.to_be_bytes());
    message.extend_from_slice(identity_signing_public_key);
    message.extend_from_slice(first_machine_id.as_bytes());
    message.extend_from_slice(machine_signing_key);
    message.extend_from_slice(machine_encryption_key);
    message.extend_from_slice(&created_at.to_be_bytes());

    message
}

/// Create a canonical binary message for machine key enrollment authorization
///
/// As specified in 03-identity-core.md § 4.3
///
/// Format: version(1) || machine_id(16) || namespace_id(16) ||
///         signing_public_key(32) || encryption_public_key(32) ||
///         capabilities(4) || created_at(8)
///
/// Total: 109 bytes
pub fn canonicalize_enrollment_message(
    machine_id: &uuid::Uuid,
    namespace_id: &uuid::Uuid,
    signing_public_key: &[u8; 32],
    encryption_public_key: &[u8; 32],
    capabilities: u32,
    created_at: u64,
) -> [u8; 109] {
    let mut message = [0u8; 109];

    message[0] = 0x01; // Version
    message[1..17].copy_from_slice(machine_id.as_bytes());
    message[17..33].copy_from_slice(namespace_id.as_bytes());
    message[33..65].copy_from_slice(signing_public_key);
    message[65..97].copy_from_slice(encryption_public_key);
    message[97..101].copy_from_slice(&capabilities.to_be_bytes());
    message[101..109].copy_from_slice(&created_at.to_be_bytes());

    message
}

/// Create a canonical binary message for recovery approval
///
/// As specified in 03-identity-core.md § 6.4
///
/// Format: version(1) || identity_id(16) || recovery_machine_id(16) ||
///         recovery_signing_key(32) || timestamp(8)
///
/// Total: 73 bytes
pub fn canonicalize_recovery_approval_message(
    identity_id: &uuid::Uuid,
    recovery_machine_id: &uuid::Uuid,
    recovery_signing_key: &[u8; 32],
    timestamp: u64,
) -> [u8; 73] {
    let mut message = [0u8; 73];

    message[0] = 0x01; // Version
    message[1..17].copy_from_slice(identity_id.as_bytes());
    message[17..33].copy_from_slice(recovery_machine_id.as_bytes());
    message[33..65].copy_from_slice(recovery_signing_key);
    message[65..73].copy_from_slice(&timestamp.to_be_bytes());

    message
}

/// Create a canonical binary message for Neural Key rotation approval
///
/// As specified in 03-identity-core.md § 7.3
///
/// Format: version(1) || identity_id(16) || isk_len(2 BE u16) ||
///         new_identity_signing_public_key(var) || timestamp(8)
pub fn canonicalize_rotation_approval_message(
    identity_id: &uuid::Uuid,
    new_identity_signing_public_key: &[u8],
    timestamp: u64,
) -> Vec<u8> {
    let isk_len = new_identity_signing_public_key.len() as u16;
    let total = 1 + 16 + 2 + new_identity_signing_public_key.len() + 8;
    let mut message = Vec::with_capacity(total);

    message.push(0x01); // Version
    message.extend_from_slice(identity_id.as_bytes());
    message.extend_from_slice(&isk_len.to_be_bytes());
    message.extend_from_slice(new_identity_signing_public_key);
    message.extend_from_slice(&timestamp.to_be_bytes());

    message
}

/// Canonicalize challenge into binary format for signing
///
/// Binary layout (130 bytes total):
/// - version: u8 (1 byte)
/// - challenge_id: UUID (16 bytes)
/// - entity_id: UUID (16 bytes)
/// - entity_type: u8 (1 byte)
/// - purpose: [u8; 16] padded (16 bytes)
/// - aud: [u8; 32] padded (32 bytes)
/// - iat: u64 big-endian (8 bytes)
/// - exp: u64 big-endian (8 bytes)
/// - nonce: [u8; 32] (32 bytes)
pub fn canonicalize_challenge(challenge: &Challenge) -> [u8; 130] {
    let mut message = [0u8; 130];

    // Version
    message[0] = 0x01;

    // Challenge ID
    message[1..17].copy_from_slice(challenge.challenge_id.as_bytes());

    // Entity ID
    message[17..33].copy_from_slice(challenge.entity_id.as_bytes());

    // Entity type
    message[33] = challenge.entity_type as u8;

    // Purpose (padded to 16 bytes)
    let purpose_bytes = challenge.purpose.as_bytes();
    let purpose_len = purpose_bytes.len().min(16);
    message[34..(34 + purpose_len)].copy_from_slice(&purpose_bytes[..purpose_len]);

    // Audience (padded to 32 bytes)
    let aud_bytes = challenge.aud.as_bytes();
    let aud_len = aud_bytes.len().min(32);
    message[50..(50 + aud_len)].copy_from_slice(&aud_bytes[..aud_len]);

    // IAT (issued at)
    message[82..90].copy_from_slice(&challenge.iat.to_be_bytes());

    // EXP (expiry)
    message[90..98].copy_from_slice(&challenge.exp.to_be_bytes());

    // Nonce
    message[98..130].copy_from_slice(&challenge.nonce);

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_ed25519_signature() {
        let seed = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";

        use ed25519_dalek::Signer;
        let signature = signing_key.sign(message);
        let pk_bytes = verifying_key.to_bytes();
        let sig_bytes = signature.to_bytes();

        assert!(verify_ed25519_signature(&pk_bytes, message, &sig_bytes).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let seed = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";
        let pk_bytes = verifying_key.to_bytes();

        let wrong_signature = [0u8; SIGNATURE_SIZE];
        assert!(verify_ed25519_signature(&pk_bytes, message, &wrong_signature).is_err());
    }

    #[test]
    fn test_verify_wrong_message() {
        let seed = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let message = b"original message";
        let wrong_message = b"tampered message";

        use ed25519_dalek::Signer;
        let signature = signing_key.sign(message);
        let pk_bytes = verifying_key.to_bytes();
        let sig_bytes = signature.to_bytes();

        assert!(verify_ed25519_signature(&pk_bytes, wrong_message, &sig_bytes).is_err());
    }

    #[test]
    fn test_canonicalize_identity_creation() {
        let identity_id = uuid::Uuid::new_v4();
        let identity_signing_public_key = vec![1u8; 1984];
        let first_machine_id = uuid::Uuid::new_v4();
        let machine_signing_key = [2u8; 32];
        let machine_encryption_key = [3u8; 32];
        let created_at = 1705320000u64;

        let message = canonicalize_identity_creation_message(
            &identity_id,
            &identity_signing_public_key,
            &first_machine_id,
            &machine_signing_key,
            &machine_encryption_key,
            created_at,
        );

        // 1 + 16 + 2 + 1984 + 16 + 32 + 32 + 8 = 2091
        assert_eq!(message.len(), 2091);
        assert_eq!(message[0], 0x01); // Version
    }

    #[test]
    fn test_canonicalize_enrollment() {
        let machine_id = uuid::Uuid::new_v4();
        let namespace_id = uuid::Uuid::new_v4();
        let signing_public_key = [1u8; 32];
        let encryption_public_key = [2u8; 32];
        let capabilities = 0b00111111u32; // FULL_DEVICE
        let created_at = 1705320000u64;

        let message = canonicalize_enrollment_message(
            &machine_id,
            &namespace_id,
            &signing_public_key,
            &encryption_public_key,
            capabilities,
            created_at,
        );

        assert_eq!(message.len(), 109);
        assert_eq!(message[0], 0x01); // Version
    }

    #[test]
    fn test_canonicalize_rotation_approval() {
        let identity_id = uuid::Uuid::new_v4();
        let new_isk = vec![5u8; 1984];
        let timestamp = 1705320000u64;

        let message = canonicalize_rotation_approval_message(
            &identity_id,
            &new_isk,
            timestamp,
        );

        // 1 + 16 + 2 + 1984 + 8 = 2011
        assert_eq!(message.len(), 2011);
        assert_eq!(message[0], 0x01); // Version
    }

    #[test]
    fn test_canonical_messages_are_deterministic() {
        let identity_id = uuid::Uuid::new_v4();
        let identity_signing_public_key = vec![1u8; 1984];
        let first_machine_id = uuid::Uuid::new_v4();
        let machine_signing_key = [2u8; 32];
        let machine_encryption_key = [3u8; 32];
        let created_at = 1705320000u64;

        let message1 = canonicalize_identity_creation_message(
            &identity_id,
            &identity_signing_public_key,
            &first_machine_id,
            &machine_signing_key,
            &machine_encryption_key,
            created_at,
        );

        let message2 = canonicalize_identity_creation_message(
            &identity_id,
            &identity_signing_public_key,
            &first_machine_id,
            &machine_signing_key,
            &machine_encryption_key,
            created_at,
        );

        assert_eq!(message1, message2);
    }
}
