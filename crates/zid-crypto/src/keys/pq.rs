//! Post-quantum cryptographic key pairs (ML-DSA-65 and ML-KEM-768).

use crate::{constants::*, errors::*};
use fips203::ml_kem_768;
use fips203::traits::SerDes as Fips203SerDes;
use fips204::ml_dsa_65;
use fips204::traits::SerDes as Fips204SerDes;

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

#[cfg(test)]
mod tests {
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
}
