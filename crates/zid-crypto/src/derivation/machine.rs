//! Machine key derivations (classical scheme).

use crate::{constants::*, errors::*, keys::*};
use zeroize::Zeroizing;

use super::hkdf_derive_32;

/// Derive Machine Key seed from Neural Key
///
/// As specified in cryptographic-constants.md § 5.3
///
/// Formula: machine_seed = HKDF(neural_key, "cypher:shared:machine:v1" || identity_id || machine_id || epoch)
pub fn derive_machine_seed(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    epoch: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:v1" || identity_id || machine_id || epoch
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_SEED.len() + 16 + 16 + 8);
    info.extend_from_slice(DOMAIN_MACHINE_SEED.as_bytes());
    info.extend_from_slice(identity_id.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());

    let seed = hkdf_derive_32(neural_key.as_bytes(), &info)?;
    Ok(Zeroizing::new(seed))
}

/// Derive Machine Key signing seed from machine seed
///
/// As specified in cryptographic-constants.md § 5.3
///
/// Formula: signing_seed = HKDF(machine_seed, "cypher:shared:machine:sign:v1" || machine_id)
pub fn derive_machine_signing_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:sign:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_SIGN.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_SIGN.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    let seed = hkdf_derive_32(machine_seed, &info)?;
    Ok(Zeroizing::new(seed))
}

/// Derive Machine Key encryption seed from machine seed
///
/// As specified in cryptographic-constants.md § 5.3
///
/// Formula: encryption_seed = HKDF(machine_seed, "cypher:shared:machine:encrypt:v1" || machine_id)
pub fn derive_machine_encryption_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:encrypt:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_ENCRYPT.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_ENCRYPT.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    let seed = hkdf_derive_32(machine_seed, &info)?;
    Ok(Zeroizing::new(seed))
}

/// Derive complete Machine Key pair from Neural Key (Classical scheme)
///
/// This is the high-level function that combines all machine key derivation steps.
/// It derives only classical keys (Ed25519 + X25519) for backward compatibility.
///
/// For PQ-Hybrid scheme with post-quantum keys, use `derive_machine_keypair_with_scheme`.
///
/// As specified in cryptographic-constants.md § 5.3
pub fn derive_machine_keypair(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    epoch: u64,
    capabilities: MachineKeyCapabilities,
) -> Result<MachineKeyPair> {
    // Step 1: Derive machine seed
    let machine_seed = derive_machine_seed(neural_key, identity_id, machine_id, epoch)?;

    // Step 2: Derive signing seed
    let signing_seed = derive_machine_signing_seed(&machine_seed, machine_id)?;

    // Step 3: Derive encryption seed
    let encryption_seed = derive_machine_encryption_seed(&machine_seed, machine_id)?;

    // Step 4: Create keypair (Classical scheme)
    let machine_keypair =
        MachineKeyPair::from_seeds(&signing_seed, &encryption_seed, capabilities)?;

    Ok(machine_keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_machine_seed() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();
        let epoch = 1u64;

        let seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, epoch).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_derive_machine_seed_different_epochs() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let seed1 = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();
        let seed2 = derive_machine_seed(&neural_key, &identity_id, &machine_id, 2).unwrap();

        assert_ne!(*seed1, *seed2);
    }

    #[test]
    fn test_derive_complete_machine_keypair() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();
        let epoch = 1u64;

        let machine_key = derive_machine_keypair(
            &neural_key,
            &identity_id,
            &machine_id,
            epoch,
            MachineKeyCapabilities::FULL_DEVICE,
        )
        .unwrap();

        assert_eq!(machine_key.signing_public_key().len(), 32);
        assert_eq!(machine_key.encryption_public_key().len(), 32);
        assert_eq!(
            machine_key.capabilities(),
            MachineKeyCapabilities::FULL_DEVICE
        );
    }

    #[test]
    fn test_derivations_use_correct_domains() {
        use crate::derivation::session::derive_mfa_kek;
        use crate::derivation::identity::derive_identity_signing_keypair;

        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        // These should all produce different outputs due to domain separation
        let identity_signing_key = derive_identity_signing_keypair(&neural_key, &identity_id)
            .unwrap()
            .0;
        let mfa_kek = derive_mfa_kek(&neural_key, &identity_id).unwrap();
        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();

        // All should be different
        assert_ne!(identity_signing_key, *mfa_kek);
        assert_ne!(identity_signing_key, *machine_seed);
        assert_ne!(*mfa_kek, *machine_seed);
    }
}
