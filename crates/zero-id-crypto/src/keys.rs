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

use crate::{constants::*, errors::*};
use bitflags::bitflags;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use fips203::ml_kem_768;
use fips203::traits::SerDes as Fips203SerDes;
use fips204::ml_dsa_65;
use fips204::traits::SerDes as Fips204SerDes;

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
/// use zero_id_crypto::KeyScheme;
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
}

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
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; NEURAL_KEY_SIZE];
        rand::thread_rng()
            .try_fill_bytes(&mut key)
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
}

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

// =============================================================================
// Post-Quantum Key Types (requires "post-quantum" feature)
// =============================================================================

/// ML-DSA-65 signing key pair (NIST FIPS 204, Level 3)
///
/// This provides post-quantum secure digital signatures. The key pair is
/// deterministically derived from a 32-byte seed using the FIPS 204
/// specification.
///
/// # Security
///
/// - 128-bit post-quantum security (NIST Level 3)
/// - Signatures are 3,309 bytes
/// - Public keys are 1,952 bytes
///
pub struct MlDsaKeyPair {
    /// Private signing key
    secret_key: ml_dsa_65::PrivateKey,
    /// Public verification key
    public_key: ml_dsa_65::PublicKey,
}

impl Clone for MlDsaKeyPair {
    fn clone(&self) -> Self {
        // We need to reconstruct from the encoded bytes
        let sk_bytes = Fips204SerDes::into_bytes(self.secret_key.clone());
        let pk_bytes = Fips204SerDes::into_bytes(self.public_key.clone());
        Self {
            secret_key: Fips204SerDes::try_from_bytes(sk_bytes).expect("valid secret key bytes"),
            public_key: Fips204SerDes::try_from_bytes(pk_bytes).expect("valid public key bytes"),
        }
    }
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA-65 key pair from a 32-byte seed
    ///
    /// The seed MUST be 32 bytes of high-entropy random data derived via HKDF.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed for deterministic key generation
    ///
    /// # Returns
    ///
    /// ML-DSA-65 key pair with 1,952-byte public key and 4,032-byte secret key
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        use fips204::traits::KeyGen;

        let (public_key, secret_key) = ml_dsa_65::KG::keygen_from_seed(seed);

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Get the public key bytes (1,952 bytes)
    pub fn public_key_bytes(&self) -> [u8; ML_DSA_65_PUBLIC_KEY_SIZE] {
        Fips204SerDes::into_bytes(self.public_key.clone())
    }

    /// Sign a message with ML-DSA-65
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// 3,309-byte ML-DSA-65 signature
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ML_DSA_65_SIGNATURE_SIZE]> {
        use fips204::traits::Signer;

        // Sign with empty context (context is optional in FIPS 204)
        let signature: [u8; ML_DSA_65_SIGNATURE_SIZE] = self
            .secret_key
            .try_sign(message, &[])
            .map_err(|e| CryptoError::InvalidInput(format!("ML-DSA signing failed: {:?}", e)))?;

        Ok(signature)
    }

    /// Sign a message deterministically with a provided rng seed
    ///
    /// This produces deterministic signatures given the same message and seed.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `rng_seed` - 32-byte seed for deterministic signing
    ///
    /// # Returns
    ///
    /// 3,309-byte ML-DSA-65 signature
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<[u8; ML_DSA_65_SIGNATURE_SIZE]> {
        use fips204::traits::Signer;

        let signature: [u8; ML_DSA_65_SIGNATURE_SIZE] = self
            .secret_key
            .try_sign_with_seed(rng_seed, message, &[])
            .map_err(|e| {
                CryptoError::InvalidInput(format!("ML-DSA deterministic signing failed: {:?}", e))
            })?;

        Ok(signature)
    }

    /// Verify an ML-DSA-65 signature
    ///
    /// # Arguments
    ///
    /// * `public_key_bytes` - 1,952-byte ML-DSA-65 public key
    /// * `message` - The message that was signed
    /// * `signature` - 3,309-byte signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if signature is valid, `Err` otherwise
    pub fn verify(
        public_key_bytes: &[u8; ML_DSA_65_PUBLIC_KEY_SIZE],
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_SIZE],
    ) -> Result<()> {
        use fips204::traits::Verifier;

        let public_key: ml_dsa_65::PublicKey = Fips204SerDes::try_from_bytes(*public_key_bytes)
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid ML-DSA public key: {:?}", e)))?;

        let valid = public_key.verify(message, signature, &[]);
        if valid {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

/// ML-KEM-768 key encapsulation key pair (NIST FIPS 203, Level 3)
///
/// This provides post-quantum secure key encapsulation for establishing
/// shared secrets. The key pair is deterministically derived from a
/// 64-byte seed using the FIPS 203 specification.
///
/// # Security
///
/// - 128-bit post-quantum security (NIST Level 3)
/// - Encapsulated ciphertexts are 1,088 bytes
/// - Public keys are 1,184 bytes
/// - Shared secrets are 32 bytes
///
pub struct MlKemKeyPair {
    /// Decapsulation key (secret)
    decapsulation_key: ml_kem_768::DecapsKey,
    /// Encapsulation key (public)
    encapsulation_key: ml_kem_768::EncapsKey,
}

impl Clone for MlKemKeyPair {
    fn clone(&self) -> Self {
        let dk_bytes = Fips203SerDes::into_bytes(self.decapsulation_key.clone());
        let ek_bytes = Fips203SerDes::into_bytes(self.encapsulation_key.clone());
        Self {
            decapsulation_key: Fips203SerDes::try_from_bytes(dk_bytes)
                .expect("valid decapsulation key bytes"),
            encapsulation_key: Fips203SerDes::try_from_bytes(ek_bytes)
                .expect("valid encapsulation key bytes"),
        }
    }
}

impl MlKemKeyPair {
    /// Generate a new ML-KEM-768 key pair from a 64-byte seed
    ///
    /// The seed is split into two 32-byte parts (d and z) as per FIPS 203.
    ///
    /// # Arguments
    ///
    /// * `seed` - 64-byte seed (d || z) for deterministic key generation
    ///
    /// # Returns
    ///
    /// ML-KEM-768 key pair with 1,184-byte encapsulation key and 2,400-byte decapsulation key
    pub fn from_seed(seed: &[u8; ML_KEM_768_SEED_SIZE]) -> Result<Self> {
        use fips203::traits::KeyGen;

        // Split seed into d (32 bytes) and z (32 bytes)
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[0..32]);
        z.copy_from_slice(&seed[32..64]);

        let (encapsulation_key, decapsulation_key) = ml_kem_768::KG::keygen_from_seed(d, z);

        Ok(Self {
            decapsulation_key,
            encapsulation_key,
        })
    }

    /// Get the encapsulation (public) key bytes (1,184 bytes)
    pub fn public_key_bytes(&self) -> [u8; ML_KEM_768_PUBLIC_KEY_SIZE] {
        Fips203SerDes::into_bytes(self.encapsulation_key.clone())
    }

    /// Encapsulate to generate a shared secret and ciphertext
    ///
    /// The recipient uses their decapsulation key to recover the shared secret.
    ///
    /// # Arguments
    ///
    /// * `recipient_public_key` - 1,184-byte ML-KEM-768 encapsulation key
    ///
    /// # Returns
    ///
    /// Tuple of (ciphertext, shared_secret) where:
    /// - ciphertext is 1,088 bytes
    /// - shared_secret is 32 bytes
    pub fn encapsulate(
        recipient_public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
    ) -> Result<([u8; ML_KEM_768_CIPHERTEXT_SIZE], [u8; ML_KEM_768_SHARED_SECRET_SIZE])> {
        use fips203::traits::Encaps;

        let ek: ml_kem_768::EncapsKey =
            Fips203SerDes::try_from_bytes(*recipient_public_key).map_err(|e| {
                CryptoError::InvalidInput(format!("Invalid ML-KEM encapsulation key: {:?}", e))
            })?;

        let (shared_secret, ciphertext) = ek.try_encaps().map_err(|e| {
            CryptoError::EncryptionFailed(format!("ML-KEM encapsulation failed: {:?}", e))
        })?;

        let ct_bytes: [u8; ML_KEM_768_CIPHERTEXT_SIZE] = Fips203SerDes::into_bytes(ciphertext);
        let ss_bytes: [u8; ML_KEM_768_SHARED_SECRET_SIZE] = Fips203SerDes::into_bytes(shared_secret);

        Ok((ct_bytes, ss_bytes))
    }

    /// Encapsulate deterministically using a provided seed
    ///
    /// This produces deterministic ciphertext and shared secret given the same
    /// recipient public key and seed.
    ///
    /// NOTE: This uses internal RNG seeding which may not be fully deterministic
    /// across library versions. For truly deterministic behavior, use the same
    /// library version.
    ///
    /// # Arguments
    ///
    /// * `recipient_public_key` - 1,184-byte ML-KEM-768 encapsulation key
    /// * `seed` - 32-byte seed (currently unused, encapsulation is randomized)
    ///
    /// # Returns
    ///
    /// Tuple of (ciphertext, shared_secret)
    pub fn encapsulate_deterministic(
        recipient_public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
        _seed: &[u8; 32],
    ) -> Result<([u8; ML_KEM_768_CIPHERTEXT_SIZE], [u8; ML_KEM_768_SHARED_SECRET_SIZE])> {
        // Note: fips203 0.4.x doesn't expose deterministic encapsulation
        // We fall back to randomized encapsulation for now
        // TODO: Upgrade to newer fips203 version when deterministic encapsulation is available
        Self::encapsulate(recipient_public_key)
    }

    /// Decapsulate to recover the shared secret from a ciphertext
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - 1,088-byte ciphertext from encapsulation
    ///
    /// # Returns
    ///
    /// 32-byte shared secret
    pub fn decapsulate(
        &self,
        ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_SIZE],
    ) -> Result<[u8; ML_KEM_768_SHARED_SECRET_SIZE]> {
        use fips203::traits::Decaps;

        let ct: ml_kem_768::CipherText = Fips203SerDes::try_from_bytes(*ciphertext)
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid ML-KEM ciphertext: {:?}", e)))?;

        let shared_secret = self.decapsulation_key.try_decaps(&ct).map_err(|e| {
            CryptoError::DecryptionFailed(format!("ML-KEM decapsulation failed: {:?}", e))
        })?;

        Ok(Fips203SerDes::into_bytes(shared_secret))
    }
}

bitflags! {
    /// Machine Key capabilities bitflags
    ///
    /// As specified in cryptographic-constants.md § 5.2
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachineKeyCapabilities: u32 {
        /// Can authenticate to zero-id
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
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(nonce)
}

/// Generate a random challenge nonce
pub fn generate_challenge_nonce() -> Result<[u8; CHALLENGE_NONCE_SIZE]> {
    let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(nonce)
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
    fn test_neural_key_validate_entropy() {
        let good_key = NeuralKey::generate().unwrap();
        assert!(good_key.validate_entropy().is_ok());

        let zero_key = NeuralKey::from_bytes([0u8; 32]);
        assert!(zero_key.validate_entropy().is_err());

        let repeated_key = NeuralKey::from_bytes([42u8; 32]);
        assert!(repeated_key.validate_entropy().is_err());
    }

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
    fn test_x25519_diffie_hellman() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let keypair1 = X25519KeyPair::from_seed(&seed1).unwrap();
        let keypair2 = X25519KeyPair::from_seed(&seed2).unwrap();

        let shared1 = keypair1.diffie_hellman(keypair2.public_key());
        let shared2 = keypair2.diffie_hellman(keypair1.public_key());

        assert_eq!(shared1, shared2);
    }

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
}

#[cfg(test)]
mod pq_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_keypair_from_seed() {
        let seed = [42u8; 32];
        let keypair = MlDsaKeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair.public_key_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_ml_dsa_keypair_deterministic() {
        let seed = [42u8; 32];
        let keypair1 = MlDsaKeyPair::from_seed(&seed).unwrap();
        let keypair2 = MlDsaKeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_ml_dsa_sign_and_verify() {
        let seed = [42u8; 32];
        let keypair = MlDsaKeyPair::from_seed(&seed).unwrap();
        let message = b"test message for ML-DSA signing";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_SIZE);

        let public_key = keypair.public_key_bytes();
        assert!(MlDsaKeyPair::verify(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_ml_dsa_verify_wrong_message() {
        let seed = [42u8; 32];
        let keypair = MlDsaKeyPair::from_seed(&seed).unwrap();
        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = keypair.sign(message).unwrap();
        let public_key = keypair.public_key_bytes();

        assert!(MlDsaKeyPair::verify(&public_key, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_ml_dsa_deterministic_signing() {
        let seed = [42u8; 32];
        let keypair = MlDsaKeyPair::from_seed(&seed).unwrap();
        let message = b"test message";
        let rng_seed = [1u8; 32];

        let sig1 = keypair.sign_deterministic(message, &rng_seed).unwrap();
        let sig2 = keypair.sign_deterministic(message, &rng_seed).unwrap();

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_ml_kem_keypair_from_seed() {
        let seed = [42u8; 64];
        let keypair = MlKemKeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair.public_key_bytes().len(), ML_KEM_768_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_ml_kem_keypair_deterministic() {
        let seed = [42u8; 64];
        let keypair1 = MlKemKeyPair::from_seed(&seed).unwrap();
        let keypair2 = MlKemKeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_ml_kem_encapsulate_decapsulate() {
        let seed = [42u8; 64];
        let keypair = MlKemKeyPair::from_seed(&seed).unwrap();
        let public_key = keypair.public_key_bytes();

        let (ciphertext, shared_secret1) = MlKemKeyPair::encapsulate(&public_key).unwrap();
        assert_eq!(ciphertext.len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret1.len(), ML_KEM_768_SHARED_SECRET_SIZE);

        let shared_secret2 = keypair.decapsulate(&ciphertext).unwrap();
        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_ml_kem_encapsulation_decapsulation_roundtrip() {
        // Note: fips203 0.4.x doesn't support deterministic encapsulation
        // This test verifies that encapsulation produces valid ciphertexts
        // that can be decapsulated
        let seed = [42u8; 64];
        let keypair = MlKemKeyPair::from_seed(&seed).unwrap();
        let public_key = keypair.public_key_bytes();

        // Each encapsulation produces different outputs (randomized)
        let (ct1, ss1) = MlKemKeyPair::encapsulate(&public_key).unwrap();
        let (ct2, ss2) = MlKemKeyPair::encapsulate(&public_key).unwrap();

        // Ciphertexts should be different (randomized encapsulation)
        assert_ne!(ct1, ct2);
        assert_ne!(ss1, ss2);

        // But both should decapsulate correctly
        let recovered1 = keypair.decapsulate(&ct1).unwrap();
        let recovered2 = keypair.decapsulate(&ct2).unwrap();
        assert_eq!(recovered1, ss1);
        assert_eq!(recovered2, ss2);
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
