//! Classical Ed25519 signing key pair.
//!
//! Used for server-side operations like managed identity derivation
//! and Ed25519 signature verification.

use crate::{constants::*, errors::*};
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Ed25519 signing key pair
///
/// Used for server-side managed identity signing and backward-compatible
/// signature operations. For PQ-hybrid signing, use `zid::IdentitySigningKey`.
#[derive(Clone)]
pub struct Ed25519KeyPair {
    private_key: SigningKey,
    public_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let private_key = SigningKey::from_bytes(seed);
        let public_key = private_key.verifying_key();
        Ok(Self { private_key, public_key })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key.to_bytes()
    }

    /// Get the private key seed bytes (32 bytes)
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    /// Get a reference to the private key
    pub fn private_key(&self) -> &SigningKey {
        &self.private_key
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair_from_seed() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(keypair.public_key_bytes().len(), PUBLIC_KEY_SIZE);
    }
}
