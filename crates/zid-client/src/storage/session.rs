//! Session storage and user prompts.

use anyhow::{Context, Result};
use std::fs;
use zid_crypto::NeuralShard;

use super::get_session_path;
use crate::types::SessionData;

pub fn save_session(session: &SessionData) -> Result<()> {
    let path = get_session_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(session)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn load_session() -> Result<SessionData> {
    let json = fs::read_to_string(get_session_path())
        .context("Failed to load session. Run 'login' first.")?;
    let session = serde_json::from_str(&json)?;
    Ok(session)
}

/// Prompt user for passphrase (hidden input)
pub fn prompt_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("Failed to read passphrase")
}

/// Prompt user for passphrase with confirmation (for new credentials)
pub fn prompt_new_passphrase() -> Result<String> {
    loop {
        let passphrase = prompt_passphrase("Enter passphrase to protect your credentials: ")?;

        if passphrase.len() < 8 {
            println!("Passphrase must be at least 8 characters. Please try again.");
            continue;
        }

        let confirm = prompt_passphrase("Confirm passphrase: ")?;

        if passphrase != confirm {
            println!("Passphrases do not match. Please try again.");
            continue;
        }

        return Ok(passphrase);
    }
}

/// Prompt user to enter one of their Neural Shards (hex format)
pub fn prompt_neural_shard() -> Result<NeuralShard> {
    use std::io::{self, Write};

    print!("Enter one of your Neural Shards: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    NeuralShard::from_hex(input).map_err(|e| anyhow::anyhow!("Invalid Neural Shard format: {}", e))
}
