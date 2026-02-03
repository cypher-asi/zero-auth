//! Common utility functions for zid cryptographic operations.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
///
/// This is the single source of truth for timestamp generation across the zid system.
///
/// # Panics
///
/// Panics if the system time is set before the Unix epoch (January 1, 1970).
/// This is extremely unlikely in production but can happen if the system clock is misconfigured.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before Unix epoch")
        .as_secs()
}

/// Generate cryptographically secure random bytes.
///
/// Uses the system's CSPRNG to fill a fixed-size array with random bytes.
///
/// # Example
///
/// ```
/// use zid_crypto::generate_random_bytes;
///
/// let nonce: [u8; 24] = generate_random_bytes();
/// let key_material: [u8; 32] = generate_random_bytes();
/// ```
pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Base64url encode data without padding.
///
/// This is the standard encoding for JWTs and other web-safe binary data.
///
/// # Example
///
/// ```
/// use zid_crypto::base64_url_encode;
///
/// let data = b"hello world";
/// let encoded = base64_url_encode(data);
/// assert_eq!(encoded, "aGVsbG8gd29ybGQ");
/// ```
pub fn base64_url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decode data.
///
/// Accepts data with or without padding.
///
/// # Example
///
/// ```
/// use zid_crypto::base64_url_decode;
///
/// let decoded = base64_url_decode("aGVsbG8gd29ybGQ").unwrap();
/// assert_eq!(decoded, b"hello world");
/// ```
pub fn base64_url_decode(data: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e: base64::DecodeError| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let ts1 = current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = current_timestamp();

        assert!(ts2 >= ts1, "Timestamp should increase with time");
        assert!(
            ts1 > 1_600_000_000,
            "Timestamp should be reasonable (after Sep 2020)"
        );
    }

    #[test]
    fn test_generate_random_bytes_different() {
        let bytes1: [u8; 32] = generate_random_bytes();
        let bytes2: [u8; 32] = generate_random_bytes();
        assert_ne!(bytes1, bytes2, "Random bytes should be different");
    }

    #[test]
    fn test_generate_random_bytes_sizes() {
        let _small: [u8; 16] = generate_random_bytes();
        let _medium: [u8; 32] = generate_random_bytes();
        let _large: [u8; 64] = generate_random_bytes();
    }

    #[test]
    fn test_base64_url_roundtrip() {
        let original = b"hello world!";
        let encoded = base64_url_encode(original);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base64_url_no_padding() {
        let data = b"a"; // Would normally have padding
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('='), "Should not contain padding");
    }

    #[test]
    fn test_base64_url_decode_invalid() {
        let result = base64_url_decode("!!invalid!!");
        assert!(result.is_err());
    }
}
