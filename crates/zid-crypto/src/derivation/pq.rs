//! Post-quantum key derivations.

use crate::{constants::*, errors::*, keys::*};
use zeroize::Zeroizing;

use super::hkdf_derive;
use super::hkdf_derive_32;
use super::machine::{derive_machine_encryption_seed, derive_machine_seed, derive_machine_signing_seed};

/// Derive ML-DSA-65 signing seed from machine seed
///
/// Formula: pq_signing_seed = HKDF(machine_seed, "cypher:shared:machine:pq-sign:v1" || machine_id)
///
/// # Arguments
///
/// * `machine_seed` - 32-byte machine seed derived from Neural Key
/// * `machine_id` - UUID of the machine
///
/// # Returns
///
/// 32-byte seed suitable for ML-DSA-65 key generation
pub fn derive_machine_pq_signing_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:pq-sign:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_PQ_SIGN.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_PQ_SIGN.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    let seed = hkdf_derive_32(machine_seed, &info)?;
    Ok(Zeroizing::new(seed))
}

/// Derive ML-KEM-768 encryption seed from machine seed
///
/// Formula: pq_kem_seed = HKDF(machine_seed, "cypher:shared:machine:pq-kem:v1" || machine_id, 64)
///
/// ML-KEM-768 requires a 64-byte seed (d || z) for deterministic key generation.
///
/// # Arguments
///
/// * `machine_seed` - 32-byte machine seed derived from Neural Key
/// * `machine_id` - UUID of the machine
///
/// # Returns
///
/// 64-byte seed suitable for ML-KEM-768 key generation
pub fn derive_machine_pq_kem_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; ML_KEM_768_SEED_SIZE]>> {
    // Build info: "cypher:shared:machine:pq-kem:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_PQ_KEM.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_PQ_KEM.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    // ML-KEM-768 needs 64 bytes (d || z)
    let seed_vec = hkdf_derive(machine_seed, &info, ML_KEM_768_SEED_SIZE)?;
    let mut seed = [0u8; ML_KEM_768_SEED_SIZE];
    seed.copy_from_slice(&seed_vec);
    Ok(Zeroizing::new(seed))
}

/// Derive complete Machine Key pair with explicit scheme selection
///
/// This function supports both Classical and PqHybrid schemes:
///
/// - **Classical**: Derives Ed25519 + X25519 keys only
/// - **PqHybrid**: Derives classical keys plus ML-DSA-65 + ML-KEM-768
///
/// # Arguments
///
/// * `neural_key` - The root Neural Key
/// * `identity_id` - Identity UUID
/// * `machine_id` - Machine UUID
/// * `epoch` - Key epoch for rotation support
/// * `capabilities` - Machine key capabilities
/// * `scheme` - Key scheme (Classical or PqHybrid)
///
/// # Example
///
/// ```ignore
/// use zid_crypto::{NeuralKey, MachineKeyCapabilities, KeyScheme, derive_machine_keypair_with_scheme};
///
/// let neural_key = NeuralKey::generate()?;
/// let identity_id = uuid::Uuid::new_v4();
/// let machine_id = uuid::Uuid::new_v4();
///
/// // Derive with PqHybrid scheme for post-quantum protection
/// let keypair = derive_machine_keypair_with_scheme(
///     &neural_key,
///     &identity_id,
///     &machine_id,
///     1,
///     MachineKeyCapabilities::FULL_DEVICE,
///     KeyScheme::PqHybrid,
/// )?;
///
/// assert!(keypair.has_post_quantum_keys());
/// ```
pub fn derive_machine_keypair_with_scheme(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    epoch: u64,
    capabilities: MachineKeyCapabilities,
    scheme: KeyScheme,
) -> Result<MachineKeyPair> {
    // Step 1: Derive machine seed
    let machine_seed = derive_machine_seed(neural_key, identity_id, machine_id, epoch)?;

    // Step 2: Derive classical signing seed
    let signing_seed = derive_machine_signing_seed(&machine_seed, machine_id)?;

    // Step 3: Derive classical encryption seed
    let encryption_seed = derive_machine_encryption_seed(&machine_seed, machine_id)?;

    // Step 4: Derive PQ seeds if needed
    let (pq_signing_seed, pq_kem_seed) = match scheme {
        KeyScheme::Classical => (None, None),
        KeyScheme::PqHybrid => {
            let pq_sign_seed = derive_machine_pq_signing_seed(&machine_seed, machine_id)?;
            let pq_kem_seed = derive_machine_pq_kem_seed(&machine_seed, machine_id)?;
            (Some(pq_sign_seed), Some(pq_kem_seed))
        }
    };

    // Step 5: Create keypair with scheme
    let machine_keypair = MachineKeyPair::from_seeds_with_scheme(
        &signing_seed,
        &encryption_seed,
        pq_signing_seed.as_deref(),
        pq_kem_seed.as_deref(),
        capabilities,
        scheme,
    )?;

    Ok(machine_keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_machine_pq_signing_seed() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();
        let pq_signing_seed = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();

        assert_eq!(pq_signing_seed.len(), 32);
    }

    #[test]
    fn test_derive_machine_pq_kem_seed() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();
        let pq_kem_seed = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();

        assert_eq!(pq_kem_seed.len(), ML_KEM_768_SEED_SIZE);
    }

    #[test]
    fn test_pq_seeds_are_deterministic() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();

        let pq_sign_seed1 = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();
        let pq_sign_seed2 = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();
        assert_eq!(*pq_sign_seed1, *pq_sign_seed2);

        let pq_kem_seed1 = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();
        let pq_kem_seed2 = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();
        assert_eq!(*pq_kem_seed1, *pq_kem_seed2);
    }

    #[test]
    fn test_pq_seeds_differ_from_classical() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();

        let signing_seed = derive_machine_signing_seed(&machine_seed, &machine_id).unwrap();
        let encryption_seed = derive_machine_encryption_seed(&machine_seed, &machine_id).unwrap();
        let pq_signing_seed = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();
        let pq_kem_seed = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();

        // All should be different due to domain separation
        assert_ne!(*signing_seed, *encryption_seed);
        assert_ne!(*signing_seed, *pq_signing_seed);
        assert_ne!(*encryption_seed, pq_kem_seed[0..32]);
    }

    #[test]
    fn test_derive_machine_keypair_with_scheme_classical() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::Classical,
        )
        .unwrap();

        assert_eq!(keypair.scheme(), KeyScheme::Classical);
        assert!(!keypair.has_post_quantum_keys());
        assert!(keypair.pq_signing_public_key().is_none());
        assert!(keypair.pq_encryption_public_key().is_none());
    }

    #[test]
    fn test_derive_machine_keypair_with_scheme_pq_hybrid() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        assert_eq!(keypair.scheme(), KeyScheme::PqHybrid);
        assert!(keypair.has_post_quantum_keys());

        // Classical keys should be present
        assert_eq!(keypair.signing_public_key().len(), 32);
        assert_eq!(keypair.encryption_public_key().len(), 32);

        // PQ keys should be present
        let pq_sign_pk = keypair.pq_signing_public_key().unwrap();
        assert_eq!(pq_sign_pk.len(), ML_DSA_65_PUBLIC_KEY_SIZE);

        let pq_enc_pk = keypair.pq_encryption_public_key().unwrap();
        assert_eq!(pq_enc_pk.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_pq_hybrid_derivation_is_deterministic() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair1 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        let keypair2 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        // Classical keys should match
        assert_eq!(keypair1.signing_public_key(), keypair2.signing_public_key());
        assert_eq!(
            keypair1.encryption_public_key(),
            keypair2.encryption_public_key()
        );

        // PQ keys should match
        assert_eq!(
            keypair1.pq_signing_public_key(),
            keypair2.pq_signing_public_key()
        );
        assert_eq!(
            keypair1.pq_encryption_public_key(),
            keypair2.pq_encryption_public_key()
        );
    }

    #[test]
    fn test_different_epochs_produce_different_pq_keys() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair1 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        let keypair2 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            2, // Different epoch
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        // Different epochs should produce different keys
        assert_ne!(
            keypair1.pq_signing_public_key(),
            keypair2.pq_signing_public_key()
        );
        assert_ne!(
            keypair1.pq_encryption_public_key(),
            keypair2.pq_encryption_public_key()
        );
    }
}
