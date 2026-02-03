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
    /// Uses multiple statistical tests to ensure the key has adequate randomness:
    /// - Shannon entropy estimation (minimum 3.5 bits/byte for 32-byte sample)
    /// - Unique byte count (minimum 16 unique values)
    /// - Run length test for sequential patterns
    /// - Two-byte pattern detection
    ///
    /// Note: For a 32-byte sample, the maximum theoretical Shannon entropy is ~5 bits/byte
    /// (log2(32) when all bytes are unique). Random data typically achieves 4.5-5.0 bits/byte.
    ///
    /// These tests are inspired by NIST SP 800-90B entropy estimation guidelines.
    pub fn validate_entropy(&self) -> Result<()> {
        // Check for all zeros
        if self.0.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidInput(
                "Neural Key cannot be all zeros".to_string(),
            ));
        }

        // Check for simple repeated patterns (all same byte)
        let first_byte = self.0[0];
        if self.0.iter().all(|&b| b == first_byte) {
            return Err(CryptoError::InvalidInput(
                "Neural Key has insufficient entropy: repeated pattern".to_string(),
            ));
        }

        // Shannon entropy estimation
        // For a 32-byte sample, theoretical max is ~5 bits/byte (when all 32 are unique)
        // Random data typically achieves 4.5-5.0 bits/byte
        // Minimum acceptable: 3.5 bits/byte (catches low-diversity patterns)
        let shannon_entropy = self.calculate_shannon_entropy();
        if shannon_entropy < 3.5 {
            return Err(CryptoError::InvalidInput(format!(
                "Neural Key has insufficient Shannon entropy: {:.2} bits/byte (minimum 3.5)",
                shannon_entropy
            )));
        }

        // Unique byte count check
        // For 32 random bytes from uniform distribution, expected unique count is ~28-30
        // Minimum 16 catches pathological cases while avoiding false positives
        let unique_bytes = self.count_unique_bytes();
        if unique_bytes < 16 {
            return Err(CryptoError::InvalidInput(format!(
                "Neural Key has too few unique bytes: {} (minimum 16)",
                unique_bytes
            )));
        }

        // Run length test - detect sequential/arithmetic patterns
        // For 32 random bytes, max run of same direction is typically 3-5
        // Runs > 10 are highly suspicious
        let max_run = self.calculate_max_run_length();
        if max_run > 10 {
            return Err(CryptoError::InvalidInput(format!(
                "Neural Key contains suspicious sequential pattern (run length: {})",
                max_run
            )));
        }

        // Check for two-byte repeating patterns (e.g., 0xAB, 0xCD, 0xAB, 0xCD, ...)
        if self.has_repeating_pattern() {
            return Err(CryptoError::InvalidInput(
                "Neural Key contains repeating pattern".to_string(),
            ));
        }

        Ok(())
    }

    /// Calculate Shannon entropy in bits per byte
    fn calculate_shannon_entropy(&self) -> f64 {
        let mut frequency = [0u32; 256];
        for &byte in &self.0 {
            frequency[byte as usize] += 1;
        }

        let len = self.0.len() as f64;
        let mut entropy = 0.0f64;

        for &count in &frequency {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate maximum run length of consecutive increasing/decreasing bytes
    fn calculate_max_run_length(&self) -> usize {
        if self.0.len() < 2 {
            return 0;
        }

        let mut max_run = 1;
        let mut current_run = 1;
        let mut last_direction: Option<i16> = None;

        for i in 1..self.0.len() {
            let diff = self.0[i] as i16 - self.0[i - 1] as i16;
            let direction = if diff > 0 {
                Some(1)
            } else if diff < 0 {
                Some(-1)
            } else {
                Some(0) // Same value counts as a run
            };

            if direction == last_direction || last_direction.is_none() {
                current_run += 1;
            } else {
                max_run = max_run.max(current_run);
                current_run = 1;
            }
            last_direction = direction;
        }

        max_run.max(current_run)
    }

    /// Count unique bytes in the key
    fn count_unique_bytes(&self) -> usize {
        let mut seen = [false; 256];
        for &byte in &self.0 {
            seen[byte as usize] = true;
        }
        seen.iter().filter(|&&b| b).count()
    }

    /// Check for short repeating patterns (2-4 bytes)
    fn has_repeating_pattern(&self) -> bool {
        // Check for 2-byte patterns
        if self.0.len() >= 4 {
            let pattern = &self.0[0..2];
            let mut all_match = true;
            for chunk in self.0.chunks(2) {
                if chunk.len() == 2 && chunk != pattern {
                    all_match = false;
                    break;
                }
            }
            if all_match {
                return true;
            }
        }

        // Check for 4-byte patterns
        if self.0.len() >= 8 {
            let pattern = &self.0[0..4];
            let mut all_match = true;
            for chunk in self.0.chunks(4) {
                if chunk.len() == 4 && chunk != pattern {
                    all_match = false;
                    break;
                }
            }
            if all_match {
                return true;
            }
        }

        false
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

    #[test]
    fn test_neural_key_entropy_rejects_sequential_pattern() {
        // Sequential bytes (0, 1, 2, 3, ...)
        let mut sequential = [0u8; 32];
        for i in 0..32 {
            sequential[i] = i as u8;
        }
        let key = NeuralKey::from_bytes(sequential);
        // This should be rejected due to sequential pattern
        assert!(
            key.validate_entropy().is_err(),
            "Sequential pattern should be rejected"
        );
    }

    #[test]
    fn test_neural_key_entropy_rejects_low_unique_bytes() {
        // Only uses a few unique byte values (low entropy)
        let mut low_diversity = [0u8; 32];
        for i in 0..32 {
            low_diversity[i] = (i % 4) as u8; // Only uses 0, 1, 2, 3
        }
        let key = NeuralKey::from_bytes(low_diversity);
        assert!(
            key.validate_entropy().is_err(),
            "Low diversity key should be rejected"
        );
    }

    #[test]
    fn test_neural_key_entropy_accepts_random_keys() {
        // Generate many keys and ensure they all pass validation
        for _ in 0..100 {
            let key = NeuralKey::generate().unwrap();
            assert!(
                key.validate_entropy().is_ok(),
                "Randomly generated key should pass entropy validation"
            );
        }
    }

    #[test]
    fn test_neural_key_shannon_entropy_calculation() {
        // A key with all different bytes should have maximum entropy for 32-byte sample
        let mut all_different = [0u8; 32];
        for i in 0..32 {
            all_different[i] = (i * 8) as u8; // Spread across byte range
        }
        let key = NeuralKey::from_bytes(all_different);
        let entropy = key.calculate_shannon_entropy();
        // 32 unique values in 32 bytes = 5 bits/byte (log2(32))
        assert!(
            entropy >= 4.9,
            "Key with 32 unique bytes should have entropy >= 4.9 (theoretical max = 5), got {}",
            entropy
        );
    }

    #[test]
    fn test_neural_key_low_entropy_rejected() {
        // A key with only 2 unique values repeated
        let mut two_values = [0u8; 32];
        for i in 0..32 {
            two_values[i] = if i % 2 == 0 { 0xAA } else { 0xBB };
        }
        let key = NeuralKey::from_bytes(two_values);
        // Shannon entropy = 1.0 bit/byte (log2(2)), should be rejected
        assert!(
            key.validate_entropy().is_err(),
            "Key with only 2 unique values should be rejected"
        );
    }

    #[test]
    fn test_neural_key_repeating_pattern_rejected() {
        // 2-byte repeating pattern: [0xAB, 0xCD] repeated
        let mut pattern_key = [0u8; 32];
        for i in 0..32 {
            pattern_key[i] = if i % 2 == 0 { 0xAB } else { 0xCD };
        }
        let key = NeuralKey::from_bytes(pattern_key);
        assert!(
            key.validate_entropy().is_err(),
            "2-byte repeating pattern should be rejected"
        );

        // 4-byte repeating pattern
        let mut pattern_key_4 = [0u8; 32];
        for i in 0..32 {
            pattern_key_4[i] = [0xDE, 0xAD, 0xBE, 0xEF][i % 4];
        }
        let key_4 = NeuralKey::from_bytes(pattern_key_4);
        assert!(
            key_4.validate_entropy().is_err(),
            "4-byte repeating pattern should be rejected"
        );
    }
}
