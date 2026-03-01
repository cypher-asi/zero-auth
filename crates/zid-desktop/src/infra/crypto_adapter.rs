use uuid::Uuid;
use zeroize::Zeroizing;
use zid_crypto::{
    canonicalize_enrollment_message, canonicalize_identity_creation_message,
    derive_identity_signing_keypair, derive_machine_keypair, generate_neural_key,
    sign_message, Ed25519KeyPair, MachineKeyCapabilities, MachineKeyPair, NeuralKey, ShamirShare,
};

use crate::error::AppError;

const SHARD_ENCRYPTION_DOMAIN: &[u8] = b"zid:client:neural-shard-encryption:v1";
const MACHINE_KEY_ENCRYPTION_DOMAIN: &[u8] = b"zid:client:machine-key-encryption:v1";

const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

pub fn new_neural_key() -> NeuralKey {
    generate_neural_key()
}

pub fn split_shards(neural_key: &NeuralKey) -> Result<Vec<ShamirShare>, AppError> {
    zid_crypto::shamir_split(neural_key.as_bytes(), 5, 3, &mut rand::thread_rng())
        .map_err(|e| AppError::CryptoError(format!("Shamir split failed: {e}")))
}

pub fn combine_shards(shares: &[ShamirShare]) -> Result<NeuralKey, AppError> {
    let bytes: [u8; 32] = zid_crypto::shamir_combine(shares)
        .map_err(|_| AppError::ShardCombineFailed)?;
    Ok(NeuralKey::from_bytes(bytes))
}

pub fn derive_isk(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
) -> Result<([u8; 32], Ed25519KeyPair), AppError> {
    derive_identity_signing_keypair(neural_key, identity_id)
        .map_err(|e| AppError::CryptoError(format!("ISK derivation failed: {e}")))
}

pub fn derive_machine(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    machine_id: &Uuid,
    epoch: u64,
) -> Result<MachineKeyPair, AppError> {
    let caps = MachineKeyCapabilities::all();
    derive_machine_keypair(neural_key, identity_id, machine_id, epoch, caps)
        .map_err(|e| AppError::CryptoError(format!("Machine key derivation failed: {e}")))
}

pub struct MachinePublicKeys {
    pub signing: [u8; 32],
    pub encryption: [u8; 32],
    pub pq_signing: Vec<u8>,
    pub pq_encryption: Vec<u8>,
}

pub fn extract_machine_public_keys(keypair: &MachineKeyPair) -> MachinePublicKeys {
    let pk = keypair.public_key();
    MachinePublicKeys {
        signing: pk.ed25519_bytes(),
        encryption: pk.x25519_bytes(),
        pq_signing: pk.ml_dsa_bytes(),
        pq_encryption: pk.ml_kem_bytes(),
    }
}

pub fn machine_signing_seed(keypair: &MachineKeyPair) -> [u8; 32] {
    keypair.ed25519_signing_key().to_bytes()
}

pub fn sign_creation_message(
    keypair: &Ed25519KeyPair,
    identity_id: &Uuid,
    machine_id: &Uuid,
    isk_pub: &[u8; 32],
    machine_signing_pub: &[u8; 32],
    machine_encryption_pub: &[u8; 32],
) -> ([u8; 64], Vec<u8>) {
    let created_at = chrono::Utc::now().timestamp() as u64;
    let message = canonicalize_identity_creation_message(
        identity_id,
        isk_pub,
        machine_id,
        machine_signing_pub,
        machine_encryption_pub,
        created_at,
    );
    let sig = sign_message(keypair, &message);
    (sig, message.to_vec())
}

pub fn sign_enrollment_message(
    keypair: &Ed25519KeyPair,
    identity_id: &Uuid,
    machine_id: &Uuid,
    machine_signing_pub: &[u8; 32],
    machine_encryption_pub: &[u8; 32],
) -> ([u8; 64], Vec<u8>) {
    let created_at = chrono::Utc::now().timestamp() as u64;
    let caps = MachineKeyCapabilities::all().bits();
    let message = canonicalize_enrollment_message(
        machine_id,
        identity_id,
        machine_signing_pub,
        machine_encryption_pub,
        caps,
        created_at,
    );
    let sig = sign_message(keypair, &message);
    (sig, message.to_vec())
}

pub fn sign_bytes(keypair: &Ed25519KeyPair, data: &[u8]) -> [u8; 64] {
    sign_message(keypair, data)
}

pub fn neural_key_commitment(neural_key: &NeuralKey) -> [u8; 32] {
    zid_crypto::blake3_hash(neural_key.as_bytes())
}

pub fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| AppError::CryptoError(format!("Invalid Argon2 parameters: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| AppError::CryptoError(format!("Key derivation failed: {e}")))?;
    Ok(Zeroizing::new(kek))
}

pub fn encrypt_shard(
    kek: &[u8; 32],
    shard_bytes: &[u8],
    nonce: &[u8; 24],
    identity_id: &Uuid,
    shard_index: u8,
) -> Result<Vec<u8>, AppError> {
    let mut aad = Vec::with_capacity(SHARD_ENCRYPTION_DOMAIN.len() + 16 + 1);
    aad.extend_from_slice(SHARD_ENCRYPTION_DOMAIN);
    aad.extend_from_slice(identity_id.as_bytes());
    aad.push(shard_index);

    zid_crypto::encrypt(kek, shard_bytes, nonce, &aad)
        .map_err(|e| AppError::CryptoError(format!("Shard encryption failed: {e}")))
}

pub fn decrypt_shard(
    kek: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 24],
    identity_id: &Uuid,
    shard_index: u8,
) -> Result<Vec<u8>, AppError> {
    let mut aad = Vec::with_capacity(SHARD_ENCRYPTION_DOMAIN.len() + 16 + 1);
    aad.extend_from_slice(SHARD_ENCRYPTION_DOMAIN);
    aad.extend_from_slice(identity_id.as_bytes());
    aad.push(shard_index);

    zid_crypto::decrypt(kek, ciphertext, nonce, &aad)
        .map_err(|_| AppError::PassphraseIncorrect)
}

pub fn encrypt_machine_seed(
    kek: &[u8; 32],
    seed: &[u8],
    nonce: &[u8; 24],
    identity_id: &Uuid,
) -> Result<Vec<u8>, AppError> {
    let mut aad = Vec::with_capacity(MACHINE_KEY_ENCRYPTION_DOMAIN.len() + 16);
    aad.extend_from_slice(MACHINE_KEY_ENCRYPTION_DOMAIN);
    aad.extend_from_slice(identity_id.as_bytes());

    zid_crypto::encrypt(kek, seed, nonce, &aad)
        .map_err(|e| AppError::CryptoError(format!("Machine seed encryption failed: {e}")))
}

pub fn decrypt_machine_seed(
    kek: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 24],
    identity_id: &Uuid,
) -> Result<Vec<u8>, AppError> {
    let mut aad = Vec::with_capacity(MACHINE_KEY_ENCRYPTION_DOMAIN.len() + 16);
    aad.extend_from_slice(MACHINE_KEY_ENCRYPTION_DOMAIN);
    aad.extend_from_slice(identity_id.as_bytes());

    zid_crypto::decrypt(kek, ciphertext, nonce, &aad)
        .map_err(|_| AppError::PassphraseIncorrect)
}

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}
