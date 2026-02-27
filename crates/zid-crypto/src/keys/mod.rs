//! Key types and capabilities.
//!
//! PQ-Hybrid key generation and derivation is handled by the `zid` crate.
//! This module provides zero-auth specific key types and re-exports zid types.

mod classical;

pub use classical::Ed25519KeyPair;

// Re-export zid types
pub use zid::{
    MachineKeyCapabilities, MachineKeyPair, MachinePublicKey,
    IdentitySigningKey, IdentityVerifyingKey, HybridSignature,
    IdentityId, MachineId, NeuralKey,
};

use crate::{constants::*, errors::*};

/// Generate a new [`NeuralKey`] using the OS CSPRNG.
///
/// Convenience wrapper around [`NeuralKey::generate`] that supplies
/// `rand::thread_rng()` so callers don't need a `rand` import.
pub fn generate_neural_key() -> NeuralKey {
    NeuralKey::generate(&mut rand::thread_rng())
}

/// Generate a cryptographically random nonce for XChaCha20-Poly1305
pub fn generate_nonce() -> Result<[u8; NONCE_SIZE]> {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(nonce)
}

/// Generate a random challenge nonce
pub fn generate_challenge_nonce() -> Result<[u8; CHALLENGE_NONCE_SIZE]> {
    let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_key_capabilities() {
        let full = MachineKeyCapabilities::FULL_DEVICE;
        assert!(full.contains(MachineKeyCapabilities::AUTHENTICATE));
        assert!(full.contains(MachineKeyCapabilities::SIGN));
        assert!(full.contains(MachineKeyCapabilities::ENCRYPT));

        let limited = MachineKeyCapabilities::LIMITED_DEVICE;
        assert!(limited.contains(MachineKeyCapabilities::AUTHENTICATE));
        assert!(!limited.contains(MachineKeyCapabilities::VAULT_OPERATIONS));
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();

        assert_eq!(nonce1.len(), NONCE_SIZE);
        assert_ne!(nonce1, nonce2);
    }
}
