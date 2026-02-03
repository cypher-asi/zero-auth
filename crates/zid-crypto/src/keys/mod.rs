//! Key generation and management.
//!
//! This module handles generation of Neural Keys, Machine Keys, and other cryptographic keys.
//!
//! # Key Schemes
//!
//! The crate supports two key schemes:
//!
//! - **Classical**: Ed25519 + X25519 (OpenMLS compatible)
//! - **PqHybrid**: Classical keys + ML-DSA-65 + ML-KEM-768 (post-quantum protection)
//!
//! Both schemes are always available for runtime selection via `KeyScheme`.

mod classical;
mod machine;
mod neural;
mod pq;

pub use classical::{Ed25519KeyPair, X25519KeyPair};
pub use machine::{
    generate_challenge_nonce, generate_nonce, MachineKeyCapabilities, MachineKeyPair,
};
pub use neural::NeuralKey;
pub use pq::{MlDsaKeyPair, MlKemKeyPair};

use serde::{Deserialize, Serialize};

// =============================================================================
// Key Scheme Selection
// =============================================================================

/// Key scheme selection for machine key derivation
///
/// Determines whether to derive only classical keys (Ed25519 + X25519) or
/// also derive post-quantum keys (ML-DSA-65 + ML-KEM-768) for hybrid security.
///
/// # Examples
///
/// ```
/// use zid_crypto::KeyScheme;
///
/// // Default is classical (backward compatible)
/// let scheme = KeyScheme::default();
/// assert_eq!(scheme, KeyScheme::Classical);
///
/// // Use PqHybrid for post-quantum protection
/// let scheme = KeyScheme::PqHybrid;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyScheme {
    /// Classical only: Ed25519 + X25519
    ///
    /// - OpenMLS compatible
    /// - No post-quantum protection
    /// - Smaller key sizes (32 bytes each)
    #[default]
    Classical,

    /// PQ-Hybrid: Classical + Post-Quantum keys
    ///
    /// - Ed25519 + X25519 (OpenMLS compatible)
    /// - ML-DSA-65 (PQ signing, 1952 byte public key)
    /// - ML-KEM-768 (PQ encryption, 1184 byte public key)
    PqHybrid,
}

impl KeyScheme {
    /// Returns true if this scheme includes post-quantum keys
    pub fn has_post_quantum(&self) -> bool {
        matches!(self, KeyScheme::PqHybrid)
    }

    /// Returns the string representation of the key scheme
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyScheme::Classical => "classical",
            KeyScheme::PqHybrid => "pq_hybrid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_scheme_default_is_classical() {
        let scheme = KeyScheme::default();
        assert_eq!(scheme, KeyScheme::Classical);
        assert!(!scheme.has_post_quantum());
    }

    #[test]
    fn test_key_scheme_pq_hybrid_has_post_quantum() {
        let scheme = KeyScheme::PqHybrid;
        assert!(scheme.has_post_quantum());
    }
}
