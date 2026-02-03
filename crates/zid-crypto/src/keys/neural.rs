//! Neural Key - the root cryptographic seed.

use crate::{constants::*, errors::*};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Neural Key (root cryptographic seed)
///
/// This is the most sensitive key in the system. It MUST be:
/// - Generated client-side only
/// - Never transmitted over network
/// - Never stored whole on any system
/// - Protected via Shamir Secret Sharing
/// - Zeroized immediately after use
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NeuralKey([u8; NEURAL_KEY_SIZE]);

impl NeuralKey {
    /// Generate a new Neural Key using cryptographically secure RNG
    ///
    /// Uses `getrandom` for WASM compatibility (works in browsers via crypto.getRandomValues())
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; NEURAL_KEY_SIZE];
        getrandom::getrandom(&mut key)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
        Ok(Self(key))
    }

    /// Create from existing bytes (e.g., after Shamir reconstruction)
    ///
    /// # Security
    ///
    /// The input bytes will be zeroized after copying into the NeuralKey.
    pub fn from_bytes(mut bytes: [u8; NEURAL_KEY_SIZE]) -> Self {
        let key = Self(bytes);
        bytes.zeroize();
        key
    }

    /// Get a reference to the key bytes
    ///
    /// # Security
    ///
    /// Use with extreme caution. Never log or persist these bytes.
    pub fn as_bytes(&self) -> &[u8; NEURAL_KEY_SIZE] {
        &self.0
    }

    /// Validate that the Neural Key has sufficient entropy
    ///
    /// This is a basic check to ensure the key isn't obviously weak.
    pub fn validate_entropy(&self) -> Result<()> {
        // Check for all zeros
        if self.0.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidInput(
                "Neural Key cannot be all zeros".to_string(),
            ));
        }

        // Check for simple repeated patterns
        let first_byte = self.0[0];
        if self.0.iter().all(|&b| b == first_byte) {
            return Err(CryptoError::InvalidInput(
                "Neural Key has insufficient entropy".to_string(),
            ));
        }

        Ok(())
    }

    /// Compute a commitment (BLAKE3 hash) of the Neural Key.
    ///
    /// This commitment can be stored to verify that reconstructed Neural Keys
    /// from Shamir shards are correct. Without this verification, any 3 valid-format
    /// shards would reconstruct *some* secret, but not necessarily the correct one.
    ///
    /// # Security
    ///
    /// - The commitment is a one-way hash; it cannot be reversed to obtain the Neural Key
    /// - The commitment should be stored alongside encrypted shards
    /// - When reconstructing, verify: `BLAKE3(reconstructed_key) == stored_commitment`
    ///
    /// # Example
    ///
    /// ```
    /// use zid_crypto::NeuralKey;
    ///
    /// let neural_key = NeuralKey::generate().unwrap();
    /// let commitment = neural_key.compute_commitment();
    ///
    /// // Store commitment with credentials...
    /// // Later, after reconstruction:
    /// // assert_eq!(reconstructed_key.compute_commitment(), stored_commitment);
    /// ```
    pub fn compute_commitment(&self) -> [u8; 32] {
        crate::hashing::blake3_hash(&self.0)
    }

    /// Verify that this Neural Key matches a stored commitment.
    ///
    /// Returns `Ok(())` if the commitment matches, `Err` otherwise.
    ///
    /// # Security
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_commitment(&self, expected_commitment: &[u8; 32]) -> Result<()> {
        let actual_commitment = self.compute_commitment();
        if crate::hashing::constant_time_compare(&actual_commitment, expected_commitment) {
            Ok(())
        } else {
            Err(CryptoError::NeuralKeyCommitmentMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neural_key_generate() {
        let key1 = NeuralKey::generate().unwrap();
        let key2 = NeuralKey::generate().unwrap();

        // Keys should be different (extremely high probability)
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_neural_key_uniqueness_across_many_generations() {
        use std::collections::HashSet;

        const NUM_KEYS: usize = 100;
        let mut keys: HashSet<[u8; NEURAL_KEY_SIZE]> = HashSet::new();

        for i in 0..NUM_KEYS {
            let key = NeuralKey::generate().expect("key generation should succeed");

            // Verify basic entropy
            key.validate_entropy()
                .expect("generated key should have sufficient entropy");

            // Check uniqueness - insert returns false if key already exists
            let is_unique = keys.insert(*key.as_bytes());
            assert!(
                is_unique,
                "Neural key collision detected at iteration {}! This should be astronomically unlikely.",
                i
            );
        }

        // Verify we have the expected number of unique keys
        assert_eq!(
            keys.len(),
            NUM_KEYS,
            "Should have {} unique keys, but got {}",
            NUM_KEYS,
            keys.len()
        );
    }

    #[test]
    fn test_neural_key_commitment_is_deterministic() {
        let key = NeuralKey::generate().unwrap();
        let commitment1 = key.compute_commitment();
        let commitment2 = key.compute_commitment();
        assert_eq!(commitment1, commitment2, "Commitment should be deterministic");
    }

    #[test]
    fn test_neural_key_commitment_differs_for_different_keys() {
        let key1 = NeuralKey::generate().unwrap();
        let key2 = NeuralKey::generate().unwrap();
        let commitment1 = key1.compute_commitment();
        let commitment2 = key2.compute_commitment();
        assert_ne!(
            commitment1, commitment2,
            "Different keys should have different commitments"
        );
    }

    #[test]
    fn test_neural_key_verify_commitment_succeeds_for_correct() {
        let key = NeuralKey::generate().unwrap();
        let commitment = key.compute_commitment();
        assert!(
            key.verify_commitment(&commitment).is_ok(),
            "Verification should succeed for correct commitment"
        );
    }

    #[test]
    fn test_neural_key_verify_commitment_fails_for_wrong() {
        let key = NeuralKey::generate().unwrap();
        let wrong_commitment = [0xABu8; 32]; // arbitrary wrong commitment
        let result = key.verify_commitment(&wrong_commitment);
        assert!(
            result.is_err(),
            "Verification should fail for wrong commitment"
        );
        match result {
            Err(CryptoError::NeuralKeyCommitmentMismatch) => {} // expected
            _ => panic!("Expected NeuralKeyCommitmentMismatch error"),
        }
    }

    #[test]
    fn test_neural_key_verify_commitment_fails_for_different_key() {
        let key1 = NeuralKey::generate().unwrap();
        let key2 = NeuralKey::generate().unwrap();
        let commitment_from_key1 = key1.compute_commitment();

        // key2 should fail verification against key1's commitment
        let result = key2.verify_commitment(&commitment_from_key1);
        assert!(
            result.is_err(),
            "Different key should fail verification against another key's commitment"
        );
    }

    #[test]
    fn test_neural_key_validate_entropy() {
        let good_key = NeuralKey::generate().unwrap();
        assert!(good_key.validate_entropy().is_ok());

        let zero_key = NeuralKey::from_bytes([0u8; 32]);
        assert!(zero_key.validate_entropy().is_err());

        let repeated_key = NeuralKey::from_bytes([42u8; 32]);
        assert!(repeated_key.validate_entropy().is_err());
    }
}
