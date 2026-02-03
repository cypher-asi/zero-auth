//! DID (Decentralized Identifier) support.
//!
//! Implements `did:key` method for Ed25519 public keys as specified in:
//! - https://w3c-ccg.github.io/did-method-key/
//! - https://github.com/multiformats/multicodec

use crate::errors::CryptoError;

/// Multicodec prefix for Ed25519 public keys (0xed01 in varint encoding)
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Multibase prefix for base58btc encoding
const MULTIBASE_BASE58BTC_PREFIX: char = 'z';

/// Convert an Ed25519 public key to `did:key` format.
///
/// The encoding follows the did:key specification:
/// 1. Prepend the multicodec prefix (0xed01) for Ed25519
/// 2. Encode with base58btc
/// 3. Prepend multibase prefix 'z'
/// 4. Prepend "did:key:"
///
/// # Example
///
/// ```
/// use zid_crypto::did::ed25519_to_did_key;
///
/// let public_key = [0u8; 32]; // Example key
/// let did = ed25519_to_did_key(&public_key);
/// assert!(did.starts_with("did:key:z6Mk"));
/// ```
pub fn ed25519_to_did_key(public_key: &[u8; 32]) -> String {
    // Combine multicodec prefix with public key
    let mut bytes = Vec::with_capacity(2 + 32);
    bytes.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes.extend_from_slice(public_key);

    // Encode with base58btc and prepend multibase prefix
    let encoded = bs58::encode(&bytes).into_string();

    format!("did:key:{}{}", MULTIBASE_BASE58BTC_PREFIX, encoded)
}

/// Parse a `did:key` back to an Ed25519 public key.
///
/// # Errors
///
/// Returns an error if:
/// - The DID doesn't start with "did:key:z"
/// - The base58 decoding fails
/// - The multicodec prefix is not Ed25519 (0xed01)
/// - The public key is not exactly 32 bytes
///
/// # Example
///
/// ```
/// use zid_crypto::did::{ed25519_to_did_key, did_key_to_ed25519};
///
/// let original_key = [42u8; 32];
/// let did = ed25519_to_did_key(&original_key);
/// let recovered_key = did_key_to_ed25519(&did).unwrap();
/// assert_eq!(original_key, recovered_key);
/// ```
pub fn did_key_to_ed25519(did: &str) -> Result<[u8; 32], CryptoError> {
    // Validate and strip "did:key:" prefix
    let remainder = did
        .strip_prefix("did:key:")
        .ok_or_else(|| CryptoError::InvalidInput("DID must start with 'did:key:'".into()))?;

    // Validate and strip multibase prefix 'z' (base58btc)
    let encoded = remainder
        .strip_prefix(MULTIBASE_BASE58BTC_PREFIX)
        .ok_or_else(|| {
            CryptoError::InvalidInput("did:key must use base58btc encoding (z prefix)".into())
        })?;

    // Decode base58
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| CryptoError::InvalidInput(format!("Invalid base58 encoding: {}", e)))?;

    // Validate length: 2 bytes prefix + 32 bytes key
    if bytes.len() != 34 {
        return Err(CryptoError::InvalidInput(format!(
            "Invalid did:key length: expected 34 bytes, got {}",
            bytes.len()
        )));
    }

    // Validate multicodec prefix
    if bytes[0] != ED25519_MULTICODEC_PREFIX[0] || bytes[1] != ED25519_MULTICODEC_PREFIX[1] {
        return Err(CryptoError::InvalidInput(
            "Invalid multicodec prefix: expected Ed25519 (0xed01)".into(),
        ));
    }

    // Extract public key
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes[2..]);

    Ok(public_key)
}

/// Validate that a string is a valid `did:key` for Ed25519.
///
/// This is a convenience function that attempts to parse the DID
/// and returns true if successful.
pub fn is_valid_ed25519_did_key(did: &str) -> bool {
    did_key_to_ed25519(did).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let public_key = [
            0x8a, 0x88, 0xe3, 0xdd, 0x7b, 0xce, 0x8c, 0xea, 0x72, 0x9e, 0x4d, 0x09, 0x9c, 0x05,
            0x2e, 0x6f, 0x2c, 0x4c, 0x9c, 0x6f, 0x95, 0x32, 0x65, 0x3e, 0xea, 0x1c, 0x5e, 0xa0,
            0x1a, 0xb6, 0x1f, 0xe3,
        ];

        let did = ed25519_to_did_key(&public_key);
        assert!(did.starts_with("did:key:z6Mk"));

        let recovered = did_key_to_ed25519(&did).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_zero_key() {
        let public_key = [0u8; 32];
        let did = ed25519_to_did_key(&public_key);
        assert!(did.starts_with("did:key:z6Mk"));

        let recovered = did_key_to_ed25519(&did).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_all_ones_key() {
        let public_key = [0xff; 32];
        let did = ed25519_to_did_key(&public_key);

        let recovered = did_key_to_ed25519(&did).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_invalid_prefix() {
        let result = did_key_to_ed25519("did:web:example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_multibase() {
        // Using 'm' (base64) instead of 'z' (base58btc)
        let result = did_key_to_ed25519("did:key:mABCD");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base58() {
        // Invalid base58 characters (0, O, I, l are not valid)
        let result = did_key_to_ed25519("did:key:z0OIl");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_multicodec() {
        // Valid base58 but wrong multicodec prefix (not Ed25519)
        let bytes = vec![0x00, 0x00, 0x00, 0x00]; // Wrong prefix
        let encoded = bs58::encode(&bytes).into_string();
        let did = format!("did:key:z{}", encoded);

        let result = did_key_to_ed25519(&did);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid() {
        let public_key = [42u8; 32];
        let did = ed25519_to_did_key(&public_key);

        assert!(is_valid_ed25519_did_key(&did));
        assert!(!is_valid_ed25519_did_key("did:web:example.com"));
        assert!(!is_valid_ed25519_did_key("not-a-did"));
    }

    #[test]
    fn test_known_vector() {
        // Test vector: a known Ed25519 key should produce a predictable DID
        // Using a simple sequential key for reproducibility
        let public_key: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let did = ed25519_to_did_key(&public_key);

        // Verify it starts correctly
        assert!(did.starts_with("did:key:z6Mk"));

        // Verify roundtrip
        let recovered = did_key_to_ed25519(&did).unwrap();
        assert_eq!(public_key, recovered);
    }
}
