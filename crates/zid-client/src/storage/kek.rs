//! KEK derivation from passphrase using Argon2id.

use anyhow::Result;

/// Argon2id parameters for KEK derivation
/// These match the server-side parameters from cryptographic-constants.md § 10
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Derive a 32-byte KEK from a passphrase using Argon2id
pub fn derive_kek_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;

    Ok(kek)
}
