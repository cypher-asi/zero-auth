/*!
 * Identity creation command
 */

use anyhow::{Context, Result};
use colored::*;
use std::io::{self, Write};
use uuid::Uuid;
use zid_crypto::{
    canonicalize_identity_creation_message, derive_identity_signing_keypair, derive_machine_keypair,
    sign_message, Ed25519KeyPair, MachineKeyCapabilities,
    NeuralKey, ShamirShare,
};

use super::create_http_client;
use crate::storage::{prompt_new_passphrase, save_credentials_with_shards};
use crate::types::CreateIdentityResponse;

pub async fn create_identity(server: &str, device_name: &str, platform: &str) -> Result<()> {
    println!("{}", "=== Creating New Identity ===".bold().cyan());

    // Generate neural key and derive all keys first
    let neural_key = generate_neural_key()?;
    let (identity_id, machine_id) = generate_ids();
    let (identity_signing_public_key, identity_signing_keypair) =
        derive_identity_signing_keypair(&neural_key, &identity_id)?;

    let machine_keypair = create_machine_keypair(&neural_key, &identity_id, &machine_id)?;
    let pk = machine_keypair.public_key();
    let signature = create_authorization_signature(
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &pk.ed25519_bytes(),
        &pk.x25519_bytes(),
        &identity_signing_keypair,
    )?;

    // Send creation request to server
    let response = send_creation_request(
        server,
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &machine_keypair,
        &signature,
        device_name,
        platform,
    )
    .await?;

    print_success(&response);

    // Now secure the Neural Key with Neural Shards
    println!(
        "\n{}",
        "Step 6: Securing your Neural Key with Neural Shards..."
            .yellow()
            .bold()
    );

    // Compute commitment before splitting (for verification during reconstruction)
    let neural_key_commitment = neural_key.compute_commitment();

    // Split neural key into 5 shards (threshold=3, total=5)
    let mut rng = rand::thread_rng();
    let shards: Vec<ShamirShare> = zid::shamir_split(neural_key.as_bytes(), 5, 3, &mut rng)
        .map_err(|e| anyhow::anyhow!("Failed to split Neural Key: {:?}", e))?;

    // Prompt for passphrase
    println!();
    let passphrase = prompt_new_passphrase()?;

    // Save 2 shards encrypted + machine signing key + commitment, get back 3 user shards
    let user_shards = save_credentials_with_shards(
        &shards,
        &neural_key_commitment,
        &machine_keypair,
        identity_id,
        machine_id,
        &hex::encode(identity_signing_public_key),
        device_name,
        platform,
        &passphrase,
    )?;

    // Display user shards with warnings
    display_user_shards(&user_shards)?;

    // Final confirmation
    println!(
        "\n{}",
        "✓ Credentials saved (2 Neural Shards encrypted on device)".green()
    );
    println!(
        "{}",
        "✓ Your Neural Key was NEVER written to disk".green().bold()
    );

    Ok(())
}

fn generate_neural_key() -> Result<NeuralKey> {
    println!("\n{}", "Step 1: Generating Neural Key...".yellow());
    let mut key_bytes = [0u8; 32];
    getrandom::getrandom(&mut key_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate random bytes: {}", e))?;
    let neural_key = NeuralKey::from_bytes(key_bytes);
    println!("{}", "✓ Neural Key generated (in memory only)".green());
    Ok(neural_key)
}

fn generate_ids() -> (Uuid, Uuid) {
    println!("\n{}", "Step 2: Generating IDs...".yellow());
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();
    println!("  Identity ID: {}", identity_id);
    println!("  Machine ID: {}", machine_id);
    (identity_id, machine_id)
}

fn create_machine_keypair(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    machine_id: &Uuid,
) -> Result<zid_crypto::MachineKeyPair> {
    println!("\n{}", "Step 3: Deriving machine keypair...".yellow());
    let keypair = derive_machine_keypair(
        neural_key,
        identity_id,
        machine_id,
        0,
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )?;

    let pk = keypair.public_key();
    println!(
        "  Machine Signing Key: {}",
        hex::encode(pk.ed25519_bytes())
    );
    println!(
        "  Machine Encryption Key: {}",
        hex::encode(pk.x25519_bytes())
    );
    println!("  PQ Signing Key: {} bytes", pk.ml_dsa_bytes().len());
    println!("  PQ Encryption Key: {} bytes", pk.ml_kem_bytes().len());
    Ok(keypair)
}

fn create_authorization_signature(
    identity_id: &Uuid,
    identity_signing_public_key: &[u8],
    machine_id: &Uuid,
    machine_signing_pk: &[u8],
    machine_encryption_pk: &[u8],
    identity_signing_keypair: &Ed25519KeyPair,
) -> Result<Vec<u8>> {
    println!(
        "\n{}",
        "Step 4: Creating authorization signature...".yellow()
    );
    let created_at = chrono::Utc::now().timestamp() as u64;

    // Convert slices to fixed-size arrays
    let identity_signing_pk: [u8; 32] = identity_signing_public_key
        .try_into()
        .context("Invalid identity signing public key length")?;
    let machine_sign_pk: [u8; 32] = machine_signing_pk
        .try_into()
        .context("Invalid machine signing public key length")?;
    let machine_enc_pk: [u8; 32] = machine_encryption_pk
        .try_into()
        .context("Invalid machine encryption public key length")?;

    let message = canonicalize_identity_creation_message(
        identity_id,
        &identity_signing_pk,
        machine_id,
        &machine_sign_pk,
        &machine_enc_pk,
        created_at,
    );
    let signature = sign_message(identity_signing_keypair, &message);
    println!("{}", "✓ Signature created".green());
    Ok(signature.to_vec())
}

#[allow(clippy::too_many_arguments)]
async fn send_creation_request(
    server: &str,
    identity_id: &Uuid,
    identity_signing_public_key: &[u8],
    machine_id: &Uuid,
    machine_keypair: &zid_crypto::MachineKeyPair,
    signature: &[u8],
    device_name: &str,
    platform: &str,
) -> Result<CreateIdentityResponse> {
    println!("\n{}", "Step 5: Sending creation request...".yellow());

    let created_at = chrono::Utc::now().timestamp() as u64;
    let request = build_creation_request(
        identity_id,
        identity_signing_public_key,
        machine_id,
        machine_keypair,
        signature,
        device_name,
        platform,
        created_at,
    );

    let client = create_http_client()?;
    let response = client
        .post(format!("{}/v1/identity", server))
        .json(&request)
        .send()
        .await
        .context("Failed to send request to server")?;

    handle_response(response).await
}

#[allow(clippy::too_many_arguments)]
fn build_creation_request(
    identity_id: &Uuid,
    identity_signing_public_key: &[u8],
    machine_id: &Uuid,
    machine_keypair: &zid_crypto::MachineKeyPair,
    signature: &[u8],
    device_name: &str,
    platform: &str,
    created_at: u64,
) -> serde_json::Value {
    let pk = machine_keypair.public_key();

    let machine_key = serde_json::json!({
        "machine_id": machine_id,
        "signing_public_key": hex::encode(pk.ed25519_bytes()),
        "encryption_public_key": hex::encode(pk.x25519_bytes()),
        "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
        "device_name": device_name,
        "device_platform": platform,
        "pq_signing_public_key": hex::encode(pk.ml_dsa_bytes()),
        "pq_encryption_public_key": hex::encode(pk.ml_kem_bytes())
    });

    serde_json::json!({
        "identity_id": identity_id,
        "identity_signing_public_key": hex::encode(identity_signing_public_key),
        "authorization_signature": hex::encode(signature),
        "machine_key": machine_key,
        "namespace_name": "Personal",
        "created_at": created_at
    })
}

async fn handle_response(response: reqwest::Response) -> Result<CreateIdentityResponse> {
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Server returned error {}: {}", status, error_text);
    }
    Ok(response.json().await?)
}

fn print_success(result: &CreateIdentityResponse) {
    println!("{}", "✓ Identity created successfully!".green().bold());
    println!("\n{}", "Server Response:".bold());
    println!("  Identity ID: {}", result.identity_id);
    println!("  Machine ID: {}", result.machine_id);
    println!("  Namespace ID: {}", result.namespace_id);
    println!("  Key Scheme: PQ-Hybrid (Ed25519 + ML-DSA-65 + X25519 + ML-KEM-768)");
    println!("  Created At: {}", result.created_at);
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
        "║                       YOUR NEURAL SHARDS                              ║"
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
        "║  WARNING: These Neural Shards will NOT be shown again!                ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║  WARNING: If you lose all 3 shards AND this device, recovery is       ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║           IMPOSSIBLE.                                                 ║"
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
