//! Challenge generation and management.

use crate::types::*;
use rand::Rng;
use uuid::Uuid;
use zid_crypto::current_timestamp;

// Re-export canonicalize_challenge from zid-crypto.
// The canonical implementation lives in zid-crypto for use by both client and server.
pub use zid_crypto::canonicalize_challenge;

/// Challenge expiry time in seconds (60 seconds)
pub const CHALLENGE_EXPIRY_SECONDS: u64 = 60;

/// Default audience for challenges
pub const DEFAULT_AUDIENCE: &str = "zid.zero.tech";

/// Generate a new challenge
pub fn generate_challenge(machine_id: Uuid, purpose: Option<String>) -> Challenge {
    let now = current_timestamp();
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce);

    Challenge {
        challenge_id: Uuid::new_v4(),
        entity_id: machine_id,
        entity_type: EntityType::Machine,
        purpose: purpose.unwrap_or_else(|| "machine_auth".to_string()),
        aud: DEFAULT_AUDIENCE.to_string(),
        iat: now,
        exp: now + CHALLENGE_EXPIRY_SECONDS,
        nonce,
        used: false,
    }
}

/// Check if challenge is expired
pub fn is_challenge_expired(challenge: &Challenge) -> bool {
    current_timestamp() >= challenge.exp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let machine_id = Uuid::new_v4();
        let challenge = generate_challenge(machine_id, None);

        assert_eq!(challenge.entity_id, machine_id);
        assert_eq!(challenge.entity_type, EntityType::Machine);
        assert_eq!(challenge.purpose, "machine_auth");
        assert_eq!(challenge.aud, DEFAULT_AUDIENCE);
        assert!(!challenge.used);
        assert!(challenge.exp > challenge.iat);
        assert_eq!(challenge.exp - challenge.iat, CHALLENGE_EXPIRY_SECONDS);
    }

    #[test]
    fn test_canonicalize_challenge() {
        let machine_id = Uuid::new_v4();
        let challenge = Challenge {
            challenge_id: Uuid::new_v4(),
            entity_id: machine_id,
            entity_type: EntityType::Machine,
            purpose: "machine_auth".to_string(),
            aud: DEFAULT_AUDIENCE.to_string(),
            iat: 1700000000,
            exp: 1700000060,
            nonce: [0x42; 32],
            used: false,
        };

        let canonical = canonicalize_challenge(&challenge);

        // Verify structure
        assert_eq!(canonical.len(), 130);
        assert_eq!(canonical[0], 0x01); // Version
        assert_eq!(&canonical[1..17], challenge.challenge_id.as_bytes());
        assert_eq!(&canonical[17..33], challenge.entity_id.as_bytes());
        assert_eq!(canonical[33], EntityType::Machine as u8);
    }

    #[test]
    fn test_challenge_expiry() {
        let machine_id = Uuid::new_v4();
        let mut challenge = generate_challenge(machine_id, None);

        // Fresh challenge should not be expired
        assert!(!is_challenge_expired(&challenge));

        // Set expiry to past
        challenge.exp = current_timestamp() - 10;
        assert!(is_challenge_expired(&challenge));
    }

    #[test]
    fn test_canonicalize_deterministic() {
        let machine_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let challenge_id = Uuid::parse_str("660f9511-f3ac-52e5-b827-557766551111").unwrap();

        let challenge = Challenge {
            challenge_id,
            entity_id: machine_id,
            entity_type: EntityType::Machine,
            purpose: "machine_auth".to_string(),
            aud: "zid.zero.tech".to_string(),
            iat: 1700000000,
            exp: 1700000060,
            nonce: [0x01; 32],
            used: false,
        };

        let canonical1 = canonicalize_challenge(&challenge);
        let canonical2 = canonicalize_challenge(&challenge);

        // Same input should produce same output
        assert_eq!(canonical1, canonical2);
    }
}
