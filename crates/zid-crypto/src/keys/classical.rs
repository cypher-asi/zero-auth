//! Classical cryptographic key pairs (Ed25519 and X25519).

use crate::{constants::*, errors::*};
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};

/// Ed25519 signing key pair
///
/// # Security
///
/// The underlying `ed25519-dalek` library implements `Zeroize` for `SigningKey`,
/// ensuring that private key material is securely erased from memory on drop.
#[derive(Clone)]
pub struct Ed25519KeyPair {
    /// Private signing key (32 bytes)
    private_key: SigningKey,
    /// Public verification key (32 bytes)
    public_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair from a seed
    ///
    /// The seed MUST be 32 bytes of high-entropy random data.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let private_key = SigningKey::from_bytes(seed);
        let public_key = private_key.verifying_key();

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key.to_bytes()
    }

    /// Get the private key seed bytes (32 bytes)
    ///
    /// # Security
    ///
    /// Use with extreme caution. Only for secure encrypted storage.
    /// These bytes can reconstruct the full keypair via `from_seed()`.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    /// Get a reference to the private key
    ///
    /// # Security
    ///
    /// Use with extreme caution. Never log or persist.
    pub fn private_key(&self) -> &SigningKey {
        &self.private_key
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
}

/// X25519 encryption key pair
///
/// # Security
///
/// The underlying `x25519-dalek` library implements `Zeroize` for `StaticSecret`,
/// ensuring that private key material is securely erased from memory on drop.
#[derive(Clone)]
pub struct X25519KeyPair {
    /// Private encryption key (32 bytes)
    private_key: X25519PrivateKey,
    /// Public encryption key (32 bytes)
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair from a seed
    ///
    /// The seed MUST be 32 bytes of high-entropy random data.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let private_key = X25519PrivateKey::from(*seed);
        let public_key = X25519PublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        *self.public_key.as_bytes()
    }

    /// Get a reference to the private key
    ///
    /// # Security
    ///
    /// Use with extreme caution. Never log or persist.
    pub fn private_key(&self) -> &X25519PrivateKey {
        &self.private_key
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }

    /// Perform Diffie-Hellman key agreement
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        let shared_secret = self.private_key.diffie_hellman(their_public);
        *shared_secret.as_bytes()
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

    #[test]
    fn test_x25519_keypair_from_seed() {
        let seed = [42u8; 32];
        let keypair = X25519KeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair.public_key_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_x25519_diffie_hellman() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let keypair1 = X25519KeyPair::from_seed(&seed1).unwrap();
        let keypair2 = X25519KeyPair::from_seed(&seed2).unwrap();

        let shared1 = keypair1.diffie_hellman(keypair2.public_key());
        let shared2 = keypair2.diffie_hellman(keypair1.public_key());

        assert_eq!(shared1, shared2);
    }
}
