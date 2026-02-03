//! Machine key pairs and capabilities.

use crate::{constants::*, errors::*};
use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use super::classical::{Ed25519KeyPair, X25519KeyPair};
use super::pq::{MlDsaKeyPair, MlKemKeyPair};
use super::KeyScheme;

bitflags! {
    /// Machine Key capabilities bitflags
    ///
    /// As specified in cryptographic-constants.md § 5.2
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachineKeyCapabilities: u32 {
        /// Can authenticate to zid
        const AUTHENTICATE = 0b00000001;
        /// Can sign challenges
        const SIGN = 0b00000010;
        /// Can encrypt/decrypt
        const ENCRYPT = 0b00000100;
        /// Can unwrap vault keys (zero-vault)
        const SVK_UNWRAP = 0b00001000;
        /// Can participate in MLS groups
        const MLS_MESSAGING = 0b00010000;
        /// Can access zero-vault operations
        const VAULT_OPERATIONS = 0b00100000;

        /// Full device capabilities (all operations)
        const FULL_DEVICE = Self::AUTHENTICATE.bits()
            | Self::SIGN.bits()
            | Self::ENCRYPT.bits()
            | Self::SVK_UNWRAP.bits()
            | Self::MLS_MESSAGING.bits()
            | Self::VAULT_OPERATIONS.bits();

        /// Service machine capabilities (no MLS)
        const SERVICE_MACHINE = Self::AUTHENTICATE.bits()
            | Self::SIGN.bits()
            | Self::VAULT_OPERATIONS.bits();

        /// Limited device capabilities (no vault access)
        const LIMITED_DEVICE = Self::AUTHENTICATE.bits()
            | Self::SIGN.bits()
            | Self::MLS_MESSAGING.bits();

        /// Service access capability (same as SERVICE_MACHINE for compatibility)
        const SERVICE_ACCESS = Self::SERVICE_MACHINE.bits();
    }
}

impl MachineKeyCapabilities {
    /// Convert capabilities to a vector of string names
    ///
    /// This is useful for JWT claims and API responses where we need
    /// human-readable capability names.
    pub fn to_string_vec(&self) -> Vec<String> {
        let mut capabilities = Vec::new();

        if self.contains(Self::AUTHENTICATE) {
            capabilities.push("AUTHENTICATE".to_string());
        }
        if self.contains(Self::SIGN) {
            capabilities.push("SIGN".to_string());
        }
        if self.contains(Self::ENCRYPT) {
            capabilities.push("ENCRYPT".to_string());
        }
        if self.contains(Self::SVK_UNWRAP) {
            capabilities.push("SVK_UNWRAP".to_string());
        }
        if self.contains(Self::MLS_MESSAGING) {
            capabilities.push("MLS_MESSAGING".to_string());
        }
        if self.contains(Self::VAULT_OPERATIONS) {
            capabilities.push("VAULT_OPERATIONS".to_string());
        }

        capabilities
    }
}

// Manual Serialize/Deserialize for bitflags
impl Serialize for MachineKeyCapabilities {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.bits().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MachineKeyCapabilities {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Ok(MachineKeyCapabilities::from_bits_truncate(bits))
    }
}

/// Machine Key pair (signing + encryption)
///
/// As specified in cryptographic-constants.md § 5
///
/// # Key Schemes
///
/// Machine keys support two schemes:
///
/// - **Classical**: Ed25519 + X25519 only (default, OpenMLS compatible)
/// - **PqHybrid**: Classical keys + ML-DSA-65 + ML-KEM-768 (post-quantum protection)
///
/// In PqHybrid mode, classical keys are always present for backward compatibility
/// with OpenMLS and existing systems. The PQ keys provide additional protection
/// for application-level protocols.
///
/// # Security
///
/// Composed of `Ed25519KeyPair` and `X25519KeyPair`, both of which have their
/// underlying libraries handle zeroization of private key material on drop.
/// PQ keys (when present) are also securely handled.
#[derive(Clone)]
pub struct MachineKeyPair {
    /// Ed25519 signing key pair (always present for OpenMLS compatibility)
    signing_key: Ed25519KeyPair,
    /// X25519 encryption key pair (always present for OpenMLS compatibility)
    encryption_key: X25519KeyPair,
    /// ML-DSA-65 post-quantum signing key pair (only in PqHybrid mode)
    pq_signing_key: Option<MlDsaKeyPair>,
    /// ML-KEM-768 post-quantum encryption key pair (only in PqHybrid mode)
    pq_encryption_key: Option<MlKemKeyPair>,
    /// Key scheme used for this machine key pair
    scheme: KeyScheme,
    /// Machine capabilities
    capabilities: MachineKeyCapabilities,
}

impl MachineKeyPair {
    /// Create a new Machine Key pair from signing and encryption seeds (Classical scheme)
    ///
    /// Both seeds MUST be 32 bytes of high-entropy random data.
    ///
    /// This creates a Classical scheme key pair (Ed25519 + X25519 only).
    /// For PqHybrid scheme, use `from_seeds_with_scheme`.
    pub fn from_seeds(
        signing_seed: &[u8; 32],
        encryption_seed: &[u8; 32],
        capabilities: MachineKeyCapabilities,
    ) -> Result<Self> {
        let signing_key = Ed25519KeyPair::from_seed(signing_seed)?;
        let encryption_key = X25519KeyPair::from_seed(encryption_seed)?;

        Ok(Self {
            signing_key,
            encryption_key,
            pq_signing_key: None,
            pq_encryption_key: None,
            scheme: KeyScheme::Classical,
            capabilities,
        })
    }

    /// Create a new Machine Key pair with explicit scheme selection
    ///
    /// For Classical scheme, only the classical seeds are used.
    /// For PqHybrid scheme, all four seeds are required.
    ///
    /// # Arguments
    ///
    /// * `signing_seed` - 32-byte seed for Ed25519 signing key
    /// * `encryption_seed` - 32-byte seed for X25519 encryption key
    /// * `pq_signing_seed` - 32-byte seed for ML-DSA-65 (only used in PqHybrid)
    /// * `pq_encryption_seed` - 64-byte seed for ML-KEM-768 (only used in PqHybrid)
    /// * `capabilities` - Machine key capabilities
    /// * `scheme` - Key scheme to use
    pub fn from_seeds_with_scheme(
        signing_seed: &[u8; 32],
        encryption_seed: &[u8; 32],
        pq_signing_seed: Option<&[u8; ML_DSA_65_SEED_SIZE]>,
        pq_encryption_seed: Option<&[u8; ML_KEM_768_SEED_SIZE]>,
        capabilities: MachineKeyCapabilities,
        scheme: KeyScheme,
    ) -> Result<Self> {
        let signing_key = Ed25519KeyPair::from_seed(signing_seed)?;
        let encryption_key = X25519KeyPair::from_seed(encryption_seed)?;

        let (pq_signing_key, pq_encryption_key) = match scheme {
            KeyScheme::Classical => (None, None),
            KeyScheme::PqHybrid => {
                let pq_sign = pq_signing_seed
                    .ok_or_else(|| {
                        CryptoError::InvalidInput(
                            "PQ signing seed required for PqHybrid scheme".to_string(),
                        )
                    })
                    .and_then(MlDsaKeyPair::from_seed)?;

                let pq_enc = pq_encryption_seed
                    .ok_or_else(|| {
                        CryptoError::InvalidInput(
                            "PQ encryption seed required for PqHybrid scheme".to_string(),
                        )
                    })
                    .and_then(MlKemKeyPair::from_seed)?;

                (Some(pq_sign), Some(pq_enc))
            }
        };

        Ok(Self {
            signing_key,
            encryption_key,
            pq_signing_key,
            pq_encryption_key,
            scheme,
            capabilities,
        })
    }

    /// Get the signing public key bytes (Ed25519, 32 bytes)
    pub fn signing_public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.signing_key.public_key_bytes()
    }

    /// Get the encryption public key bytes (X25519, 32 bytes)
    pub fn encryption_public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.encryption_key.public_key_bytes()
    }

    /// Get a reference to the signing key pair (Ed25519)
    pub fn signing_key_pair(&self) -> &Ed25519KeyPair {
        &self.signing_key
    }

    /// Get a reference to the encryption key pair (X25519)
    pub fn encryption_key_pair(&self) -> &X25519KeyPair {
        &self.encryption_key
    }

    /// Get the key scheme
    pub fn scheme(&self) -> KeyScheme {
        self.scheme
    }

    /// Get the capabilities
    pub fn capabilities(&self) -> MachineKeyCapabilities {
        self.capabilities
    }

    /// Get the PQ signing public key bytes (ML-DSA-65, 1952 bytes)
    ///
    /// Returns `None` if the key scheme is Classical.
    pub fn pq_signing_public_key(&self) -> Option<[u8; ML_DSA_65_PUBLIC_KEY_SIZE]> {
        self.pq_signing_key.as_ref().map(|k| k.public_key_bytes())
    }

    /// Get the PQ encryption public key bytes (ML-KEM-768, 1184 bytes)
    ///
    /// Returns `None` if the key scheme is Classical.
    pub fn pq_encryption_public_key(&self) -> Option<[u8; ML_KEM_768_PUBLIC_KEY_SIZE]> {
        self.pq_encryption_key
            .as_ref()
            .map(|k| k.public_key_bytes())
    }

    /// Get a reference to the PQ signing key pair (ML-DSA-65)
    ///
    /// Returns `None` if the key scheme is Classical.
    pub fn pq_signing_key_pair(&self) -> Option<&MlDsaKeyPair> {
        self.pq_signing_key.as_ref()
    }

    /// Get a reference to the PQ encryption key pair (ML-KEM-768)
    ///
    /// Returns `None` if the key scheme is Classical.
    pub fn pq_encryption_key_pair(&self) -> Option<&MlKemKeyPair> {
        self.pq_encryption_key.as_ref()
    }

    /// Check if this key pair has post-quantum keys
    pub fn has_post_quantum_keys(&self) -> bool {
        self.pq_signing_key.is_some() && self.pq_encryption_key.is_some()
    }
}

/// Generate a random nonce for encryption
/// Generate a cryptographically random nonce for XChaCha20-Poly1305
///
/// # Security Notes
///
/// - XChaCha20 uses 192-bit (24-byte) nonces, providing a vast nonce space
/// - Birthday bound for collision is at 2^96 operations (~7.9 × 10^28)
/// - Random generation is safe for reasonable usage volumes
/// - Each encrypted value stores its nonce, enabling collision detection
///
/// # Future Enhancement
///
/// For defense-in-depth, consider implementing:
/// - Counter-based nonce generation for deterministic uniqueness
/// - Database-backed nonce counter with atomic increment
/// - Nonce collision detection before encryption
///
/// Current implementation is cryptographically sound for typical usage.
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
    fn test_machine_keypair_from_seeds() {
        let signing_seed = [1u8; 32];
        let encryption_seed = [2u8; 32];

        let machine_key = MachineKeyPair::from_seeds(
            &signing_seed,
            &encryption_seed,
            MachineKeyCapabilities::FULL_DEVICE,
        )
        .unwrap();

        assert_eq!(machine_key.signing_public_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(machine_key.encryption_public_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(
            machine_key.capabilities(),
            MachineKeyCapabilities::FULL_DEVICE
        );
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();

        assert_eq!(nonce1.len(), NONCE_SIZE);
        assert_ne!(nonce1, nonce2); // Should be random
    }

    #[test]
    fn test_machine_keypair_scheme_classical() {
        let signing_seed = [1u8; 32];
        let encryption_seed = [2u8; 32];

        let machine_key = MachineKeyPair::from_seeds(
            &signing_seed,
            &encryption_seed,
            MachineKeyCapabilities::FULL_DEVICE,
        )
        .unwrap();

        assert_eq!(machine_key.scheme(), KeyScheme::Classical);
        assert!(!machine_key.has_post_quantum_keys());
    }

    #[test]
    fn test_machine_keypair_pq_hybrid() {
        let signing_seed = [1u8; 32];
        let encryption_seed = [2u8; 32];
        let pq_signing_seed = [3u8; 32];
        let pq_encryption_seed = [4u8; 64];

        let machine_key = MachineKeyPair::from_seeds_with_scheme(
            &signing_seed,
            &encryption_seed,
            Some(&pq_signing_seed),
            Some(&pq_encryption_seed),
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        assert_eq!(machine_key.scheme(), KeyScheme::PqHybrid);
        assert!(machine_key.has_post_quantum_keys());

        // Classical keys should still be present
        assert_eq!(machine_key.signing_public_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(machine_key.encryption_public_key().len(), PUBLIC_KEY_SIZE);

        // PQ keys should be present
        let pq_sign_pk = machine_key.pq_signing_public_key().unwrap();
        assert_eq!(pq_sign_pk.len(), ML_DSA_65_PUBLIC_KEY_SIZE);

        let pq_enc_pk = machine_key.pq_encryption_public_key().unwrap();
        assert_eq!(pq_enc_pk.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_machine_keypair_pq_hybrid_sign_verify() {
        let signing_seed = [1u8; 32];
        let encryption_seed = [2u8; 32];
        let pq_signing_seed = [3u8; 32];
        let pq_encryption_seed = [4u8; 64];

        let machine_key = MachineKeyPair::from_seeds_with_scheme(
            &signing_seed,
            &encryption_seed,
            Some(&pq_signing_seed),
            Some(&pq_encryption_seed),
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        let message = b"test message for hybrid signing";

        // Sign with PQ key
        let pq_keypair = machine_key.pq_signing_key_pair().unwrap();
        let signature = pq_keypair.sign(message).unwrap();

        // Verify with PQ public key
        let pq_public_key = machine_key.pq_signing_public_key().unwrap();
        assert!(MlDsaKeyPair::verify(&pq_public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_machine_keypair_pq_hybrid_encapsulate_decapsulate() {
        let signing_seed = [1u8; 32];
        let encryption_seed = [2u8; 32];
        let pq_signing_seed = [3u8; 32];
        let pq_encryption_seed = [4u8; 64];

        let machine_key = MachineKeyPair::from_seeds_with_scheme(
            &signing_seed,
            &encryption_seed,
            Some(&pq_signing_seed),
            Some(&pq_encryption_seed),
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        // Encapsulate to the machine's PQ public key
        let pq_public_key = machine_key.pq_encryption_public_key().unwrap();
        let (ciphertext, shared_secret1) = MlKemKeyPair::encapsulate(&pq_public_key).unwrap();

        // Decapsulate with the machine's PQ private key
        let pq_keypair = machine_key.pq_encryption_key_pair().unwrap();
        let shared_secret2 = pq_keypair.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_machine_keypair_classical_no_pq_keys() {
        let signing_seed = [1u8; 32];
        let encryption_seed = [2u8; 32];

        let machine_key = MachineKeyPair::from_seeds_with_scheme(
            &signing_seed,
            &encryption_seed,
            None,
            None,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::Classical,
        )
        .unwrap();

        assert_eq!(machine_key.scheme(), KeyScheme::Classical);
        assert!(!machine_key.has_post_quantum_keys());
        assert!(machine_key.pq_signing_public_key().is_none());
        assert!(machine_key.pq_encryption_public_key().is_none());
    }
}
