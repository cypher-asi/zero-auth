/*!
 * Neural Key recovery commands using Neural Shards
 *
 * Recovery is performed by providing 3+ Neural Shards to reconstruct
 * the Neural Key, then setting up a new device with the 2+1 split storage.
 */

use anyhow::{Context, Result};
use colored::*;
use std::io::{self, Write};
use uuid::Uuid;
use zid_crypto::{
    derive_identity_signing_keypair, derive_machine_keypair,
    MachineKeyCapabilities, NeuralKey, ShamirShare,
};

use super::create_http_client;
use crate::storage::{prompt_new_passphrase, save_credentials_with_shards};

/// Recover Neural Key from Neural Shards.
///
/// Combines 3-5 shards to reconstruct the Neural Key, then sets up
/// this device with the 2+1 Neural Shard split storage model.
pub async fn recover(
    server: &str,
    shards_hex: &[String],
    device_name: &str,
    platform: &str,
) -> Result<()> {
    println!("{}", "=== Neural Key Recovery ===".bold().cyan());
    println!();

    // Step 1: Parse and validate shards
    println!("{}", "Step 1: Parsing Neural Shards...".yellow());
    let shards = parse_shards(shards_hex)?;
    println!(
        "{}",
        format!("✓ Parsed {} valid Neural Shards", shards.len()).green()
    );
    println!();

    // Step 2: Combine shards
    println!("{}", "Step 2: Combining Neural Shards...".yellow());
    let neural_key_bytes = zid::shamir_combine(&shards)
        .map_err(|e| anyhow::anyhow!("Failed to combine Neural Shards: {:?}", e))?;
    let neural_key = NeuralKey::from_bytes(neural_key_bytes);
    println!("{}", "✓ Neural Key reconstructed in memory".green());
    println!();

    // Step 3: Prompt for a new passphrase
    println!(
        "{}",
        "Step 3: Set a passphrase to protect your credentials".yellow()
    );
    let passphrase = prompt_new_passphrase()?;
    println!();

    // Step 4: Prompt for identity ID or create new
    println!("{}", "Step 4: Recovery options".yellow());
    println!("  Enter your Identity ID to recover existing identity,");
    println!("  or press Enter to create a new identity:");
    print!("  > ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input.is_empty() {
        // Create new identity
        create_new_identity(server, &neural_key, device_name, platform, &passphrase).await
    } else {
        // Recover existing identity
        let identity_id = Uuid::parse_str(input).context(
            "Invalid Identity ID format. Expected UUID (e.g., 550e8400-e29b-41d4-a716-446655440000)",
        )?;
        recover_existing_identity(
            server,
            &neural_key,
            &identity_id,
            device_name,
            platform,
            &passphrase,
        )
        .await
    }
}

fn parse_shards(shards_hex: &[String]) -> Result<Vec<ShamirShare>> {
    if shards_hex.len() < 3 {
        anyhow::bail!(
            "Need at least 3 Neural Shards for recovery, got {}",
            shards_hex.len()
        );
    }

    if shards_hex.len() > 5 {
        anyhow::bail!(
            "Maximum 5 Neural Shards allowed, got {}",
            shards_hex.len()
        );
    }

    let mut shards = Vec::with_capacity(shards_hex.len());
    for (i, hex_str) in shards_hex.iter().enumerate() {
        let shard = ShamirShare::from_hex(hex_str)
            .map_err(|e| anyhow::anyhow!("Invalid Neural Shard {}: {:?}", i + 1, e))?;
        shards.push(shard);
    }

    Ok(shards)
}

async fn create_new_identity(
    server: &str,
    neural_key: &NeuralKey,
    device_name: &str,
    platform: &str,
    passphrase: &str,
) -> Result<()> {
    println!();
    println!("{}", "Step 5: Creating new identity...".yellow());

    // Generate new IDs
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();

    println!("  Identity ID: {}", identity_id);
    println!("  Machine ID: {}", machine_id);

    // Derive keys
    let (identity_signing_public_key, identity_signing_keypair) =
        derive_identity_signing_keypair(neural_key, &identity_id)
            .map_err(|e| anyhow::anyhow!("Failed to derive identity signing key: {}", e))?;

    let machine_keypair = derive_machine_keypair(
        neural_key,
        &identity_id,
        &machine_id,
        0,
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )
    .map_err(|e| anyhow::anyhow!("Failed to derive machine key: {}", e))?;

    // Create authorization signature
    let created_at = chrono::Utc::now().timestamp() as u64;
    let pk = machine_keypair.public_key();
    let message = zid_crypto::canonicalize_identity_creation_message(
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &pk.ed25519_bytes(),
        &pk.x25519_bytes(),
        created_at,
    );
    let signature = zid_crypto::sign_message(&identity_signing_keypair, &message);

    // Send creation request
    println!();
    println!("{}", "Step 6: Registering with server...".yellow());

    let request = serde_json::json!({
        "identity_id": identity_id,
        "identity_signing_public_key": hex::encode(identity_signing_public_key),
        "authorization_signature": hex::encode(signature),
        "machine_key": {
            "machine_id": machine_id,
            "signing_public_key": hex::encode(pk.ed25519_bytes()),
            "encryption_public_key": hex::encode(pk.x25519_bytes()),
            "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
            "device_name": device_name,
            "device_platform": platform,
            "pq_signing_public_key": hex::encode(pk.ml_dsa_bytes()),
            "pq_encryption_public_key": hex::encode(pk.ml_kem_bytes())
        },
        "namespace_name": "Personal",
        "created_at": created_at
    });

    let client = create_http_client()?;
    let response = client
        .post(format!("{}/v1/identity", server))
        .json(&request)
        .send()
        .await
        .context("Failed to send request to server")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Server returned error {}: {}", status, error_text);
    }

    println!("{}", "✓ Identity created successfully!".green().bold());

    // Save credentials with 2+1 Neural Shard split
    save_recovered_credentials(
        neural_key,
        &identity_id,
        &machine_id,
        &identity_signing_public_key,
        &machine_keypair,
        device_name,
        platform,
        passphrase,
    )?;

    Ok(())
}

async fn recover_existing_identity(
    server: &str,
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    device_name: &str,
    platform: &str,
    passphrase: &str,
) -> Result<()> {
    println!();
    println!(
        "{}",
        format!("Step 5: Recovering identity {}...", identity_id).yellow()
    );

    // Generate new machine ID for recovery device
    let machine_id = Uuid::new_v4();
    println!("  New Machine ID: {}", machine_id);

    // Derive keys
    let (identity_signing_public_key, _identity_signing_keypair) =
        derive_identity_signing_keypair(neural_key, identity_id)
            .map_err(|e| anyhow::anyhow!("Failed to derive identity signing key: {}", e))?;

    let machine_keypair = derive_machine_keypair(
        neural_key,
        identity_id,
        &machine_id,
        1, // epoch 1 for recovery
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )
    .map_err(|e| anyhow::anyhow!("Failed to derive machine key: {}", e))?;

    println!("{}", "✓ Keys derived".green());

    // Note: In a full implementation, this would call the recovery endpoint
    // with proper approvals from existing machines.
    println!();
    println!(
        "{}",
        "Note: Full recovery requires approval from existing machines.".yellow()
    );
    println!(
        "{}",
        "Saving credentials locally for manual recovery process.".yellow()
    );

    // Try to verify the identity exists
    println!();
    println!("{}", "Step 6: Verifying identity...".yellow());

    match create_http_client() {
        Ok(client) => {
            match client
                .get(format!("{}/v1/identity/{}", server, identity_id))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    println!("{}", "✓ Identity verified on server".green());
                }
                Ok(resp) => {
                    println!(
                        "{}",
                        format!("⚠ Could not verify identity: {}", resp.status()).yellow()
                    );
                }
                Err(e) => {
                    println!(
                        "{}",
                        format!("⚠ Could not connect to server: {}", e).yellow()
                    );
                }
            }
        }
        Err(e) => {
            println!(
                "{}",
                format!("⚠ Could not create HTTP client: {}", e).yellow()
            );
        }
    }

    // Save credentials with 2+1 Neural Shard split
    save_recovered_credentials(
        neural_key,
        identity_id,
        &machine_id,
        &identity_signing_public_key,
        &machine_keypair,
        device_name,
        platform,
        passphrase,
    )?;

    println!();
    println!(
        "{}",
        "Recovery credentials saved. You may need to complete".green()
    );
    println!(
        "{}",
        "the recovery process by enrolling this machine with".green()
    );
    println!("{}", "approval from existing machines.".green());

    Ok(())
}

fn save_recovered_credentials(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    machine_id: &Uuid,
    identity_signing_public_key: &[u8; 32],
    machine_keypair: &zid_crypto::MachineKeyPair,
    device_name: &str,
    platform: &str,
    passphrase: &str,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "Step 7: Securing Neural Key with Neural Shards...".yellow()
    );

    // Compute commitment before splitting (for verification during reconstruction)
    let neural_key_commitment = neural_key.compute_commitment();

    // Split neural key into 5 shards
    let mut rng = rand::thread_rng();
    let shards: Vec<ShamirShare> = zid::shamir_split(neural_key.as_bytes(), 5, 3, &mut rng)
        .map_err(|e| anyhow::anyhow!("Failed to split Neural Key: {:?}", e))?;

    // Save 2 shards encrypted + machine signing key + commitment, get back 3 user shards
    let user_shards = save_credentials_with_shards(
        &shards,
        &neural_key_commitment,
        machine_keypair,
        *identity_id,
        *machine_id,
        &hex::encode(identity_signing_public_key),
        device_name,
        platform,
        passphrase,
    )?;

    // Display user shards
    display_user_shards(&user_shards)?;

    println!();
    println!(
        "{}",
        "✓ Credentials saved (2 Neural Shards encrypted on device)".green()
    );
    println!(
        "{}",
        "✓ Your Neural Key was NEVER written to disk".green().bold()
    );

    Ok(())
}

fn display_user_shards(shards: &[ShamirShare]) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════════╗"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║                    YOUR NEW NEURAL SHARDS                             ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}",
        "║  Login only requires your PASSPHRASE (no shard needed).               ║"
            .white()
            .bold()
    );
    println!(
        "{}",
        "║  Store these shards in separate secure locations for RECOVERY.        ║"
            .white()
    );
    println!(
        "{}",
        "║  Any 3 shards can recover your identity if you lose this device.      ║"
            .white()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════════════════╣"
            .red()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );

    // Display each shard
    println!(
        "{}  {}",
        "║".red(),
        format!("Shard A: {}", shards[0].to_hex()).bright_white()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}  {}",
        "║".red(),
        format!("Shard B: {}", shards[1].to_hex()).bright_white()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}  {}",
        "║".red(),
        format!("Shard C: {}", shards[2].to_hex()).bright_white()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════════════════╣"
            .red()
    );
    println!(
        "{}",
        "║  NOTE: These are NEW shards for this device setup.                    ║"
            .yellow()
            .bold()
    );
    println!(
        "{}",
        "║  WARNING: These Neural Shards will NOT be shown again!                ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════════════╝"
            .red()
            .bold()
    );

    // Wait for user acknowledgment
    println!();
    print!(
        "{}",
        "Press Enter when you have saved your Neural Shards...".yellow()
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(())
}
