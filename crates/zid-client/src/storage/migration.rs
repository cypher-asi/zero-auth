//! Legacy credentials migration support.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use zeroize::Zeroize;
use zid_crypto::{decrypt, NeuralKey, ShamirShare};

use super::credentials::save_credentials_with_shards;
use super::kek::derive_kek_from_passphrase;
use super::session::prompt_passphrase;
use super::get_credentials_path;

/// Domain separation for legacy Neural Key encryption (for migration only)
const LEGACY_NEURAL_KEY_ENCRYPTION_DOMAIN: &[u8] = b"cypher:auth:neural-key-encryption:v1";

/// Legacy credentials format (encrypted whole Neural Key)
#[derive(Deserialize)]
struct LegacyClientCredentials {
    #[serde(with = "legacy_hex_serde")]
    encrypted_neural_key: Vec<u8>,
    #[serde(with = "legacy_hex_serde")]
    neural_key_nonce: Vec<u8>,
    #[serde(with = "legacy_hex_serde")]
    neural_key_salt: Vec<u8>,
    identity_id: uuid::Uuid,
    machine_id: uuid::Uuid,
    identity_signing_public_key: String,
    #[allow(dead_code)]
    machine_signing_public_key: String,
    #[allow(dead_code)]
    machine_encryption_public_key: String,
    device_name: String,
    device_platform: String,
}

/// Helper module for hex deserialization (legacy format)
mod legacy_hex_serde {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Check if credentials file is in legacy format (encrypted whole Neural Key)
pub fn is_legacy_credentials() -> bool {
    let path = get_credentials_path();
    if !path.exists() {
        return false;
    }

    let json = match fs::read_to_string(&path) {
        Ok(j) => j,
        Err(_) => return false,
    };

    // Try to parse as JSON and check for legacy field
    let value: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Legacy format has "encrypted_neural_key" field
    value.get("encrypted_neural_key").is_some()
}

/// Migrate legacy credentials to new 2+1 Neural Shard format.
///
/// This function:
/// 1. Decrypts the legacy Neural Key
/// 2. Splits it into 5 Neural Shards
/// 3. Saves 2 shards encrypted, returns 3 user shards
///
/// The caller MUST display the returned shards to the user, as they are needed for login.
pub fn migrate_legacy_credentials(passphrase: &str) -> Result<Vec<ShamirShare>> {
    use colored::*;
    use std::io::{self, Write};

    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════════╗"
            .yellow()
            .bold()
    );
    println!(
        "{}",
        "║                    CREDENTIAL MIGRATION REQUIRED                      ║"
            .yellow()
            .bold()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .yellow()
    );
    println!(
        "{}",
        "║  Your credentials are in an older format that stored the Neural Key   ║"
            .white()
    );
    println!(
        "{}",
        "║  encrypted on disk. The new format uses Neural Shards for enhanced    ║"
            .white()
    );
    println!(
        "{}",
        "║  security - even if your device is compromised, attackers cannot      ║"
            .white()
    );
    println!(
        "{}",
        "║  access your Neural Key.                                              ║"
            .white()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════════════╝"
            .yellow()
            .bold()
    );
    println!();

    // Load legacy credentials
    let json = fs::read_to_string(get_credentials_path())
        .context("Failed to load legacy credentials")?;
    let legacy: LegacyClientCredentials =
        serde_json::from_str(&json).context("Failed to parse legacy credentials")?;

    // Derive KEK from passphrase using legacy salt
    let mut kek = derive_kek_from_passphrase(passphrase, &legacy.neural_key_salt)?;

    // Convert nonce to fixed-size array
    let nonce: [u8; 24] = legacy
        .neural_key_nonce
        .as_slice()
        .try_into()
        .context("Invalid legacy nonce length")?;

    // Decrypt the Neural Key
    let decrypted = decrypt(
        &kek,
        &legacy.encrypted_neural_key,
        &nonce,
        LEGACY_NEURAL_KEY_ENCRYPTION_DOMAIN,
    )
    .map_err(|_| anyhow::anyhow!("Failed to decrypt Neural Key. Wrong passphrase?"))?;

    // Zeroize KEK after use
    kek.zeroize();

    // Convert decrypted bytes to Neural Key
    let neural_key_bytes: [u8; 32] = decrypted
        .as_slice()
        .try_into()
        .context("Invalid Neural Key length")?;

    let neural_key = NeuralKey::from_bytes(neural_key_bytes);

    println!("{}", "✓ Legacy Neural Key decrypted".green());

    // Derive machine keypair from Neural Key
    println!("{}", "Deriving machine keypair...".yellow());
    let machine_keypair = zid_crypto::derive_machine_keypair(
        &neural_key,
        &legacy.identity_id,
        &legacy.machine_id,
        0,
        zid_crypto::MachineKeyCapabilities::AUTHENTICATE
            | zid_crypto::MachineKeyCapabilities::SIGN
            | zid_crypto::MachineKeyCapabilities::ENCRYPT,
    )
    .map_err(|e| anyhow::anyhow!("Failed to derive machine keypair: {}", e))?;

    // Compute commitment before splitting (for verification during reconstruction)
    let neural_key_commitment = neural_key.compute_commitment();

    // Split into 5 Neural Shards
    println!(
        "{}",
        "Splitting Neural Key into Neural Shards...".yellow()
    );
    let mut rng = rand::thread_rng();
    let shards: Vec<ShamirShare> = zid::shamir_split(neural_key.as_bytes(), 5, 3, &mut rng)
        .map_err(|e| anyhow::anyhow!("Failed to split Neural Key: {:?}", e))?;

    // Prompt for new passphrase (can be same or different)
    println!();
    println!(
        "{}",
        "You can keep your current passphrase or set a new one:".white()
    );
    print!("Press Enter to keep current passphrase, or type a new one: ");
    io::stdout().flush()?;

    let mut new_passphrase_input = String::new();
    io::stdin().read_line(&mut new_passphrase_input)?;
    let new_passphrase_input = new_passphrase_input.trim();

    let final_passphrase = if new_passphrase_input.is_empty() {
        passphrase.to_string()
    } else {
        // Confirm new passphrase
        let confirm = prompt_passphrase("Confirm new passphrase: ")?;
        if new_passphrase_input != confirm {
            anyhow::bail!("Passphrases do not match");
        }
        new_passphrase_input.to_string()
    };

    // Save in new format with machine signing key and commitment
    let user_shards = save_credentials_with_shards(
        &shards,
        &neural_key_commitment,
        &machine_keypair,
        legacy.identity_id,
        legacy.machine_id,
        &legacy.identity_signing_public_key,
        &legacy.device_name,
        &legacy.device_platform,
        &final_passphrase,
    )?;

    println!(
        "{}",
        "✓ Credentials migrated to new format".green().bold()
    );

    Ok(user_shards)
}
