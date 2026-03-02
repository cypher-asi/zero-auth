/*!
 * Authentication commands
 */

use anyhow::{Context, Result};
use base64::Engine;
use colored::*;
use std::io::{self, Write};
use uuid::Uuid;
use zid_crypto::{
    derive_machine_keypair, IdentitySigningKey, MachineKeyCapabilities, NeuralKey,
    ZeroAuthOpaque,
};

use super::create_http_client;

use crate::storage::{
    has_stored_machine_key, is_legacy_credentials, load_and_reconstruct_neural_key,
    load_credentials, load_machine_signing_key, migrate_legacy_credentials, prompt_neural_shard,
    prompt_passphrase, save_session,
};
use crate::types::{ChallengeResponse, ClientCredentials, LoginResponse, SessionData};

pub async fn login(server: &str) -> Result<()> {
    println!("{}", "=== Machine Key Authentication ===".bold().cyan());

    if is_legacy_credentials() {
        println!(
            "\n{}",
            "Legacy credentials detected. Migration required.".yellow()
        );
        let passphrase = prompt_passphrase("Enter passphrase: ")?;
        let user_shards = migrate_legacy_credentials(&passphrase)?;
        display_migration_shards(&user_shards)?;

        println!(
            "\n{}",
            "Please run 'login' again with one of your new Neural Shards.".yellow()
        );
        return Ok(());
    }

    let credentials = load_credentials()?;
    print_credentials_info(&credentials.identity_id, &credentials.machine_id);

    let challenge_data = request_challenge(server, &credentials.machine_id).await?;

    if has_stored_machine_key() {
        println!("\n{}", "Step 3: Decrypting machine signing key...".yellow());
        let passphrase = prompt_passphrase("Enter passphrase: ")?;

        let (signing_keypair, _) = load_machine_signing_key(&passphrase)?;
        println!("{}", "✓ Machine signing key decrypted".green());

        let signature = sign_challenge_with_key(&challenge_data, &signing_keypair)?;
        let login_result = submit_login(
            server,
            &challenge_data.challenge_id,
            &credentials.machine_id,
            &signature,
        )
        .await?;

        print_login_success(&login_result);
        save_session_data(&login_result)?;
    } else {
        println!(
            "\n{}",
            "Step 3: Credentials in old format - Neural Key reconstruction required...".yellow()
        );
        println!(
            "{}",
            "  (Tip: Re-enroll this device to enable passphrase-only login)".dimmed()
        );
        let passphrase = prompt_passphrase("Enter passphrase: ")?;
        let user_shard = prompt_neural_shard()?;

        let (neural_key, _) = load_and_reconstruct_neural_key(&passphrase, &user_shard)?;
        println!("{}", "✓ Neural Key reconstructed in memory".green());

        let signature = sign_challenge_with_neural_key(&challenge_data, &credentials, &neural_key)?;
        let login_result = submit_login(
            server,
            &challenge_data.challenge_id,
            &credentials.machine_id,
            &signature,
        )
        .await?;

        print_login_success(&login_result);
        save_session_data(&login_result)?;
    }

    Ok(())
}

fn display_migration_shards(shards: &[zid_crypto::ShamirShare]) -> Result<()> {
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════╗".red().bold());
    println!("{}", "║              YOUR NEW NEURAL SHARDS                        ║".red().bold());
    println!("{}", "║                                                            ║".red());
    println!("{}", "║  Login now only requires your PASSPHRASE (no shard).       ║".white().bold());
    println!("{}", "║  Store shards in separate secure locations for RECOVERY.   ║".white());
    println!("{}", "║  Any 3 shards can recover your identity if device lost.    ║".white());
    println!("{}", "╠════════════════════════════════════════════════════════════╣".red());
    println!("{}", "║                                                            ║".red());

    println!("{}  {}", "║".red(), format!("Shard A: {}", shards[0].to_hex()).bright_white());
    println!("{}", "║                                                            ║".red());
    println!("{}  {}", "║".red(), format!("Shard B: {}", shards[1].to_hex()).bright_white());
    println!("{}", "║                                                            ║".red());
    println!("{}  {}", "║".red(), format!("Shard C: {}", shards[2].to_hex()).bright_white());
    println!("{}", "║                                                            ║".red());
    println!("{}", "╠════════════════════════════════════════════════════════════╣".red());
    println!("{}", "║  WARNING: Neural Shards will NOT be shown again!           ║".red().bold());
    println!("{}", "║  WARNING: Lose all 3 shards AND device = recovery          ║".red().bold());
    println!("{}", "║           IMPOSSIBLE.                                      ║".red().bold());
    println!("{}", "╚════════════════════════════════════════════════════════════╝".red().bold());

    println!();
    print!("{}", "Press Enter when you have saved your Neural Shards...".yellow());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(())
}

/// OPAQUE-based email login (2 round-trips, password never leaves client).
pub async fn login_email(
    server: &str,
    email: &str,
    password: &str,
    machine_id: Option<Uuid>,
) -> Result<()> {
    println!("{}", "=== OPAQUE Email Authentication ===".bold().cyan());
    print_email_login_info(email, machine_id.as_ref());

    let login_result = attempt_opaque_email_login(server, email, password, machine_id).await?;
    print_email_login_success(&login_result);
    save_session_data(&login_result)?;
    Ok(())
}

async fn attempt_opaque_email_login(
    server: &str,
    email: &str,
    password: &str,
    machine_id: Option<Uuid>,
) -> Result<LoginResponse> {
    use opaque_ke::{ClientLogin, ClientLoginFinishParameters};

    println!("\n{}", "Step 2: OPAQUE login init...".yellow());

    let mut rng = rand::rngs::OsRng;
    let client_start = ClientLogin::<ZeroAuthOpaque>::start(&mut rng, password.as_bytes())
        .context("OPAQUE client login start failed")?;

    let credential_request = serde_json::to_vec(&client_start.message)
        .context("Failed to serialize CredentialRequest")?;

    let client = create_http_client()?;
    let init_request = serde_json::json!({
        "email": email,
        "credential_request": base64::engine::general_purpose::STANDARD.encode(&credential_request),
    });

    let init_resp = client
        .post(format!("{}/v1/auth/login/email/init", server))
        .json(&init_request)
        .send()
        .await
        .context("Failed to send OPAQUE login init")?;

    if !init_resp.status().is_success() {
        let status = init_resp.status();
        let text = init_resp.text().await?;
        anyhow::bail!("Login init failed {}: {}", status, text);
    }

    let init_data: serde_json::Value = init_resp.json().await?;
    let login_state_id = init_data["login_state_id"]
        .as_str()
        .context("Missing login_state_id")?;
    let cred_resp_b64 = init_data["credential_response"]
        .as_str()
        .context("Missing credential_response")?;

    println!("{}", "  ✓ Received CredentialResponse".green());

    println!("\n{}", "Step 3: OPAQUE login finish...".yellow());

    let cred_resp_bytes = base64::engine::general_purpose::STANDARD
        .decode(cred_resp_b64)
        .context("Invalid base64 for credential_response")?;

    let credential_response: opaque_ke::CredentialResponse<ZeroAuthOpaque> =
        serde_json::from_slice(&cred_resp_bytes)
            .context("Failed to deserialize CredentialResponse")?;

    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| anyhow::anyhow!("Invalid credentials"))?;

    let finalization_bytes = serde_json::to_vec(&client_finish.message)
        .context("Failed to serialize CredentialFinalization")?;

    let finish_request = serde_json::json!({
        "login_state_id": login_state_id,
        "credential_finalization": base64::engine::general_purpose::STANDARD.encode(&finalization_bytes),
        "machine_id": machine_id,
    });

    let finish_resp = client
        .post(format!("{}/v1/auth/login/email/finish", server))
        .json(&finish_request)
        .send()
        .await
        .context("Failed to send OPAQUE login finish")?;

    if !finish_resp.status().is_success() {
        let status = finish_resp.status();
        let text = finish_resp.text().await?;
        anyhow::bail!("Login finish failed {}: {}", status, text);
    }

    println!("{}", "  ✓ OPAQUE key exchange complete".green());
    Ok(finish_resp.json().await?)
}

fn print_credentials_info(identity_id: &Uuid, machine_id: &Uuid) {
    println!("\n{}", "Step 1: Loading credentials...".yellow());
    println!("  Identity ID: {}", identity_id);
    println!("  Machine ID: {}", machine_id);
}

async fn request_challenge(server: &str, machine_id: &Uuid) -> Result<ChallengeResponse> {
    println!(
        "\n{}",
        "Step 2: Requesting authentication challenge...".yellow()
    );

    let client = create_http_client()?;
    let challenge_url = format!("{}/v1/auth/challenge?machine_id={}", server, machine_id);
    let response = client
        .get(&challenge_url)
        .send()
        .await
        .context("Failed to get challenge")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Server returned error {}: {}", status, error_text);
    }

    let challenge_data: ChallengeResponse = response.json().await?;
    println!("  Challenge ID: {}", challenge_data.challenge_id);
    println!("  Expires At: {}", challenge_data.expires_at);
    Ok(challenge_data)
}

fn sign_challenge_with_key(
    challenge_data: &ChallengeResponse,
    signing_keypair: &IdentitySigningKey,
) -> Result<Vec<u8>> {
    println!("\n{}", "Step 4: Signing challenge...".yellow());

    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(&challenge_data.challenge)
        .context("Failed to decode challenge")?;

    let challenge: zid_crypto::Challenge =
        serde_json::from_slice(&challenge_bytes).context("Failed to deserialize challenge")?;

    let canonical_challenge = zid_crypto::canonicalize_challenge(&challenge);
    let signature = signing_keypair.sign(&canonical_challenge);
    println!("{}", "✓ Challenge signed".green());
    Ok(signature.to_bytes().to_vec())
}

fn sign_challenge_with_neural_key(
    challenge_data: &ChallengeResponse,
    credentials: &ClientCredentials,
    neural_key: &NeuralKey,
) -> Result<Vec<u8>> {
    println!("\n{}", "Step 4: Signing challenge...".yellow());

    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(&challenge_data.challenge)
        .context("Failed to decode challenge")?;

    let challenge: zid_crypto::Challenge =
        serde_json::from_slice(&challenge_bytes).context("Failed to deserialize challenge")?;

    let canonical_challenge = zid_crypto::canonicalize_challenge(&challenge);

    let machine_keypair = derive_machine_keypair(
        neural_key,
        &credentials.identity_id,
        &credentials.machine_id,
        0,
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )?;

    use ed25519_dalek::Signer;
    let signature = machine_keypair.ed25519_signing_key().sign(&canonical_challenge);
    println!("{}", "✓ Challenge signed".green());
    Ok(signature.to_bytes().to_vec())
}

async fn submit_login(
    server: &str,
    challenge_id: &Uuid,
    machine_id: &Uuid,
    signature: &[u8],
) -> Result<LoginResponse> {
    println!("\n{}", "Step 5: Submitting login request...".yellow());

    let login_request = serde_json::json!({
        "challenge_id": challenge_id,
        "machine_id": machine_id,
        "signature": hex::encode(signature)
    });

    let client = create_http_client()?;
    let response = client
        .post(format!("{}/v1/auth/login/machine", server))
        .json(&login_request)
        .send()
        .await
        .context("Failed to login")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Login failed {}: {}", status, error_text);
    }

    Ok(response.json().await?)
}

fn print_login_success(login_result: &LoginResponse) {
    println!("{}", "✓ Login successful!".green().bold());
    println!("\n{}", "Session Details:".bold());
    println!("  Session ID: {}", login_result.session_id);
    println!("  Expires At: {}", login_result.expires_at);
    println!(
        "\n  Access Token: {}",
        &login_result.access_token[..50].dimmed()
    );
    println!("  {}...", "...".dimmed());
}

fn print_email_login_info(email: &str, machine_id: Option<&Uuid>) {
    println!("\n{}", "Step 1: Validating credentials...".yellow());
    println!("  Email: {}", email);
    if let Some(mid) = machine_id {
        println!("  Machine ID: {}", mid);
    }
}

fn print_email_login_success(login_result: &LoginResponse) {
    if let Some(warning) = &login_result.warning {
        println!("\n{}", format!("Warning: {}", warning).yellow());
    }

    println!("{}", "✓ Login successful!".green().bold());
    println!("\n{}", "Session Details:".bold());
    println!("  Session ID: {}", login_result.session_id);
    println!("  Machine ID: {}", login_result.machine_id);
    println!("  Expires At: {}", login_result.expires_at);
    println!(
        "\n  Access Token: {}",
        &login_result.access_token[..50].dimmed()
    );
    println!("  {}...", "...".dimmed());

    if login_result.warning.is_some() {
        println!(
            "\n{}",
            "Tip: This session is using a virtual machine. For better security, enroll a real device.".dimmed()
        );
    }
}

fn save_session_data(login_result: &LoginResponse) -> Result<()> {
    let session = SessionData {
        access_token: login_result.access_token.clone(),
        refresh_token: login_result.refresh_token.clone(),
        session_id: login_result.session_id,
        expires_at: login_result.expires_at.clone(),
    };

    save_session(&session)?;
    println!("\n{}", "✓ Session saved to ./.session/session.json".green());
    println!(
        "\n{}",
        "You can now use the access token to make authenticated requests!".green()
    );
    Ok(())
}
