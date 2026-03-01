use uuid::Uuid;
use zid_crypto::{NeuralKey, ShamirShare};

use crate::error::AppError;
use crate::infra::crypto_adapter;

pub struct ShardSet {
    pub device_shard_1_encrypted: Vec<u8>,
    pub device_shard_2_encrypted: Vec<u8>,
    pub nonce: [u8; 24],
    pub salt: [u8; 32],
    pub user_shards: Vec<ShamirShare>,
    pub neural_key_commitment: [u8; 32],
}

pub struct DerivedKeys {
    pub isk_public: [u8; 32],
    pub isk_keypair: zid_crypto::Ed25519KeyPair,
    pub machine_keypair: zid_crypto::MachineKeyPair,
}

pub fn generate_neural_key() -> NeuralKey {
    crypto_adapter::new_neural_key()
}

pub fn split_and_encrypt(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    passphrase: &str,
) -> Result<ShardSet, AppError> {
    let shards = crypto_adapter::split_shards(neural_key)?;
    if shards.len() != 5 {
        return Err(AppError::CryptoError("Expected 5 shards".into()));
    }

    let salt = crypto_adapter::generate_salt();
    let nonce = crypto_adapter::generate_nonce();
    let kek = crypto_adapter::derive_kek(passphrase, &salt)?;

    let shard_0_bytes = shards[0].to_bytes();
    let shard_1_bytes = shards[1].to_bytes();

    let enc_0 = crypto_adapter::encrypt_shard(&kek, &shard_0_bytes, &nonce, identity_id, 0)?;
    let enc_1 = crypto_adapter::encrypt_shard(&kek, &shard_1_bytes, &nonce, identity_id, 1)?;

    let commitment = crypto_adapter::neural_key_commitment(neural_key);
    let user_shards = shards[2..5].to_vec();

    Ok(ShardSet {
        device_shard_1_encrypted: enc_0,
        device_shard_2_encrypted: enc_1,
        nonce,
        salt,
        user_shards,
        neural_key_commitment: commitment,
    })
}

pub fn decrypt_device_shards(
    encrypted_1: &[u8],
    encrypted_2: &[u8],
    nonce: &[u8; 24],
    salt: &[u8],
    identity_id: &Uuid,
    passphrase: &str,
) -> Result<(ShamirShare, ShamirShare), AppError> {
    let kek = crypto_adapter::derive_kek(passphrase, salt)?;
    let raw_0 = crypto_adapter::decrypt_shard(&kek, encrypted_1, nonce, identity_id, 0)?;
    let raw_1 = crypto_adapter::decrypt_shard(&kek, encrypted_2, nonce, identity_id, 1)?;

    let share_0 = ShamirShare::from_bytes(&raw_0)
        .map_err(|e| AppError::CryptoError(format!("Invalid shard data: {e:?}")))?;
    let share_1 = ShamirShare::from_bytes(&raw_1)
        .map_err(|e| AppError::CryptoError(format!("Invalid shard data: {e:?}")))?;
    Ok((share_0, share_1))
}

pub fn combine(shares: &[ShamirShare], expected_commitment: &[u8; 32]) -> Result<NeuralKey, AppError> {
    let neural_key = crypto_adapter::combine_shards(shares)?;
    let actual = crypto_adapter::neural_key_commitment(&neural_key);
    if actual != *expected_commitment {
        return Err(AppError::ShardCombineFailed);
    }
    Ok(neural_key)
}

pub fn derive_keys(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    machine_id: &Uuid,
    epoch: u64,
) -> Result<DerivedKeys, AppError> {
    let (isk_public, isk_keypair) = crypto_adapter::derive_isk(neural_key, identity_id)?;
    let machine_keypair = crypto_adapter::derive_machine(neural_key, identity_id, machine_id, epoch)?;

    Ok(DerivedKeys {
        isk_public,
        isk_keypair,
        machine_keypair,
    })
}

pub fn encrypt_machine_seed_for_storage(
    machine_keypair: &zid_crypto::MachineKeyPair,
    passphrase: &str,
    salt: &[u8],
    identity_id: &Uuid,
) -> Result<(Vec<u8>, [u8; 24]), AppError> {
    let kek = crypto_adapter::derive_kek(passphrase, salt)?;
    let nonce = crypto_adapter::generate_nonce();
    let seed = crypto_adapter::machine_signing_seed(machine_keypair);
    let encrypted = crypto_adapter::encrypt_machine_seed(&kek, &seed, &nonce, identity_id)?;
    Ok((encrypted, nonce))
}
