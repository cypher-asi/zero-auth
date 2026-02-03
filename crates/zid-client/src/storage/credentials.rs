//! Credential storage and retrieval.

use anyhow::{Context, Result};
use std::fs;
use zeroize::Zeroize;
use zid_crypto::{combine_shards, decrypt, encrypt, Ed25519KeyPair, MachineKeyPair, NeuralShard};

use super::kek::derive_kek_from_passphrase;
use super::{get_credentials_path, MACHINE_KEY_ENCRYPTION_DOMAIN, SHARD_ENCRYPTION_DOMAIN};
use crate::types::ClientCredentials;

/// Save credentials with 2 Neural Shards and machine signing key encrypted on device.
///
/// # Arguments
///
/// * `shards` - All 5 Neural Shards (shards 0-1 will be stored, 2-4 returned to user)
/// * `neural_key_commitment` - BLAKE3 hash of the Neural Key (for verification during reconstruction)
/// * `machine_keypair` - Machine keypair (signing seed will be encrypted for fast login)
/// * `identity_id` - Identity UUID
/// * `machine_id` - Machine UUID
/// * `identity_signing_public_key` - Identity signing public key (hex-encoded)
/// * `device_name` - Human-readable device name
/// * `device_platform` - Platform identifier (e.g., "windows", "linux", "macos")
/// * `passphrase` - User-provided passphrase to derive KEK
///
/// # Returns
///
/// The 3 user shards that must be displayed and saved by the user.
///
/// # Security
///
/// The `neural_key_commitment` is stored to verify that reconstructed Neural Keys
/// from shards are correct. Without this, any 3 valid-format shards would reconstruct
/// *some* secret, but not necessarily the correct one.
#[allow(clippy::too_many_arguments)]
pub fn save_credentials_with_shards(
    shards: &[NeuralShard; 5],
    neural_key_commitment: &[u8; 32],
    machine_keypair: &MachineKeyPair,
    identity_id: uuid::Uuid,
    machine_id: uuid::Uuid,
    identity_signing_public_key: &str,
    device_name: &str,
    device_platform: &str,
    passphrase: &str,
) -> Result<[NeuralShard; 3]> {
    // Generate random salt (32 bytes)
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow::anyhow!("Failed to generate salt: {}", e))?;

    // Generate random nonce (24 bytes for XChaCha20)
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| anyhow::anyhow!("Failed to generate nonce: {}", e))?;

    // Derive KEK from passphrase
    let mut kek = derive_kek_from_passphrase(passphrase, &salt)?;

    // Encrypt shards 0 and 1 (stored on device)
    // Each shard is 33 bytes (1 byte index + 32 bytes data)
    let shard_1_bytes = shards[0].to_bytes();
    let shard_2_bytes = shards[1].to_bytes();

    let encrypted_shard_1 = encrypt(&kek, &shard_1_bytes, &nonce, SHARD_ENCRYPTION_DOMAIN)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt Neural Shard 1: {}", e))?;

    // Use a different nonce for second shard (increment last byte)
    let mut nonce_2 = nonce;
    nonce_2[23] = nonce_2[23].wrapping_add(1);

    let encrypted_shard_2 = encrypt(&kek, &shard_2_bytes, &nonce_2, SHARD_ENCRYPTION_DOMAIN)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt Neural Shard 2: {}", e))?;

    // Generate separate nonce for machine key encryption
    let mut machine_key_nonce = [0u8; 24];
    getrandom::getrandom(&mut machine_key_nonce)
        .map_err(|e| anyhow::anyhow!("Failed to generate machine key nonce: {}", e))?;

    // Encrypt machine signing seed (32 bytes)
    let signing_seed = machine_keypair.signing_key_pair().seed_bytes();
    let encrypted_machine_signing_seed =
        encrypt(&kek, &signing_seed, &machine_key_nonce, MACHINE_KEY_ENCRYPTION_DOMAIN)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt machine signing seed: {}", e))?;

    // Zeroize KEK after use
    kek.zeroize();

    // Create credentials with encrypted shards, machine key, and commitment
    let credentials = ClientCredentials {
        encrypted_shard_1,
        encrypted_shard_2,
        shards_nonce: nonce.to_vec(),
        kek_salt: salt.to_vec(),
        encrypted_machine_signing_seed,
        machine_key_nonce: machine_key_nonce.to_vec(),
        neural_key_commitment: neural_key_commitment.to_vec(),
        identity_id,
        machine_id,
        identity_signing_public_key: identity_signing_public_key.to_string(),
        machine_signing_public_key: hex::encode(machine_keypair.signing_public_key()),
        machine_encryption_public_key: hex::encode(machine_keypair.encryption_public_key()),
        device_name: device_name.to_string(),
        device_platform: device_platform.to_string(),
    };

    // Ensure the .session directory exists
    let path = get_credentials_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&credentials)?;
    fs::write(path, json)?;

    // Return the 3 user shards (indices 2, 3, 4)
    Ok([shards[2].clone(), shards[3].clone(), shards[4].clone()])
}

/// Load credentials and reconstruct the Neural Key from 2 stored shards + 1 user shard.
///
/// # Arguments
///
/// * `passphrase` - User-provided passphrase to derive KEK and decrypt stored shards
/// * `user_shard` - One of the user's 3 Neural Shards
///
/// # Returns
///
/// Tuple of (NeuralKey, ClientCredentials)
///
/// # Security
///
/// This function verifies the reconstructed Neural Key against the stored commitment.
/// If the commitment doesn't match (e.g., wrong shards provided), an error is returned.
/// This prevents attackers from using arbitrary shards to derive wrong keys.
pub fn load_and_reconstruct_neural_key(
    passphrase: &str,
    user_shard: &NeuralShard,
) -> Result<(zid_crypto::NeuralKey, ClientCredentials)> {
    let json = fs::read_to_string(get_credentials_path())
        .context("Failed to load credentials. Run 'create-identity' first.")?;
    let credentials: ClientCredentials = serde_json::from_str(&json)?;

    // Derive KEK from passphrase using stored salt
    let mut kek = derive_kek_from_passphrase(passphrase, &credentials.kek_salt)?;

    // Convert nonce to fixed-size array
    let nonce: [u8; 24] = credentials
        .shards_nonce
        .as_slice()
        .try_into()
        .context("Invalid nonce length")?;

    // Decrypt shard 1
    let decrypted_shard_1_bytes = decrypt(
        &kek,
        &credentials.encrypted_shard_1,
        &nonce,
        SHARD_ENCRYPTION_DOMAIN,
    )
    .map_err(|_| anyhow::anyhow!("Failed to decrypt Neural Shard 1. Wrong passphrase?"))?;

    // Decrypt shard 2 (uses incremented nonce)
    let mut nonce_2 = nonce;
    nonce_2[23] = nonce_2[23].wrapping_add(1);

    let decrypted_shard_2_bytes = decrypt(
        &kek,
        &credentials.encrypted_shard_2,
        &nonce_2,
        SHARD_ENCRYPTION_DOMAIN,
    )
    .map_err(|_| anyhow::anyhow!("Failed to decrypt Neural Shard 2. Wrong passphrase?"))?;

    // Zeroize KEK after use
    kek.zeroize();

    // Parse decrypted bytes back into NeuralShard
    let shard_1 = NeuralShard::from_bytes(&decrypted_shard_1_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Neural Shard 1 format: {}", e))?;
    let shard_2 = NeuralShard::from_bytes(&decrypted_shard_2_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Neural Shard 2 format: {}", e))?;

    // Combine 3 shards to reconstruct Neural Key
    let shards = [shard_1, shard_2, user_shard.clone()];
    let neural_key = combine_shards(&shards)
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct Neural Key: {}", e))?;

    // Verify the reconstructed key against stored commitment
    // This prevents using fake shards to derive wrong keys
    if !credentials.neural_key_commitment.is_empty() {
        let expected_commitment: [u8; 32] = credentials
            .neural_key_commitment
            .as_slice()
            .try_into()
            .context("Invalid neural key commitment length")?;

        neural_key
            .verify_commitment(&expected_commitment)
            .map_err(|_| {
                anyhow::anyhow!(
                    "Neural Key commitment mismatch: the provided shard does not match this identity. \
                     Ensure you are using a shard from this identity's original set."
                )
            })?;
    }

    Ok((neural_key, credentials))
}

/// Load and decrypt machine signing key for authentication.
///
/// This is the simplified login flow - only requires passphrase, no Neural Shard needed.
/// The Neural Key reconstruction via shards is only needed for privileged operations
/// like enrolling new machines.
///
/// # Arguments
///
/// * `passphrase` - User-provided passphrase to derive KEK and decrypt machine key
///
/// # Returns
///
/// Tuple of (Ed25519KeyPair, ClientCredentials)
pub fn load_machine_signing_key(passphrase: &str) -> Result<(Ed25519KeyPair, ClientCredentials)> {
    let json = fs::read_to_string(get_credentials_path())
        .context("Failed to load credentials. Run 'create-identity' first.")?;
    let credentials: ClientCredentials = serde_json::from_str(&json)?;

    // Check if machine key is stored (new format)
    if credentials.encrypted_machine_signing_seed.is_empty() {
        anyhow::bail!(
            "Credentials are in old format without stored machine key. \
             Please run migration or re-enroll this device."
        );
    }

    // Derive KEK from passphrase using stored salt
    let mut kek = derive_kek_from_passphrase(passphrase, &credentials.kek_salt)?;

    // Convert nonce to fixed-size array
    let nonce: [u8; 24] = credentials
        .machine_key_nonce
        .as_slice()
        .try_into()
        .context("Invalid machine key nonce length")?;

    // Decrypt machine signing seed
    let decrypted_seed = decrypt(
        &kek,
        &credentials.encrypted_machine_signing_seed,
        &nonce,
        MACHINE_KEY_ENCRYPTION_DOMAIN,
    )
    .map_err(|_| anyhow::anyhow!("Failed to decrypt machine signing key. Wrong passphrase?"))?;

    // Zeroize KEK after use
    kek.zeroize();

    // Convert to fixed-size array and create keypair
    let seed: [u8; 32] = decrypted_seed
        .as_slice()
        .try_into()
        .context("Invalid machine signing seed length")?;

    let keypair = Ed25519KeyPair::from_seed(&seed)
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct machine signing key: {}", e))?;

    Ok((keypair, credentials))
}

/// Check if credentials have stored machine key (new format)
pub fn has_stored_machine_key() -> bool {
    let path = get_credentials_path();
    if !path.exists() {
        return false;
    }

    let json = match fs::read_to_string(&path) {
        Ok(j) => j,
        Err(_) => return false,
    };

    let credentials: ClientCredentials = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(_) => return false,
    };

    !credentials.encrypted_machine_signing_seed.is_empty()
}

/// Load credentials without decryption (for operations that don't need the Neural Key)
pub fn load_credentials() -> Result<ClientCredentials> {
    let json = fs::read_to_string(get_credentials_path())
        .context("Failed to load credentials. Run 'create-identity' first.")?;
    let credentials = serde_json::from_str(&json)?;
    Ok(credentials)
}
