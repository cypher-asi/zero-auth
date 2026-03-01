use egui::{RichText, Ui};

use crate::error::AppError;
use crate::infra::crypto_adapter;
use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::AppState;
use crate::ui::components::core;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, step: LoginStep, rt: &tokio::runtime::Handle) {
    ui.vertical_centered(|ui| {
        ui.set_max_width(500.0);
        ui.add_space(60.0);

        ui.label(RichText::new("Welcome Back").font(theme::heading_font()).color(theme::TEXT_PRIMARY));
        ui.add_space(24.0);

        match step {
            LoginStep::EnterPassphrase => render_passphrase_entry(ui, state, rt),
            LoginStep::Authenticating => render_authenticating(ui),
        }
    });
}

fn render_passphrase_entry(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    ui.label(RichText::new("Enter your passphrase to unlock").color(theme::TEXT_SECONDARY));
    ui.add_space(16.0);

    core::password_input(ui, &mut state.login_passphrase, "Passphrase");
    ui.add_space(12.0);

    let has_stored_machine_key = {
        let cred_path = state.storage.credentials_path();
        state
            .storage
            .read_json::<StoredCredentials>(&cred_path)
            .map(|c| !c.encrypted_machine_signing_seed.is_empty())
            .unwrap_or(false)
    };

    if !has_stored_machine_key {
        ui.label(
            RichText::new("Enter one of your three recovery shards (hex)")
                .color(theme::TEXT_SECONDARY)
                .font(theme::small_font()),
        );
        core::hex_input(ui, &mut state.login_user_shard_hex, "Recovery shard hex");
    }

    ui.add_space(20.0);

    let can_login = !state.login_passphrase.is_empty()
        && (has_stored_machine_key || !state.login_user_shard_hex.is_empty());

    ui.horizontal(|ui| {
        if core::secondary_button(ui, "Recover Identity") {
            state.navigate(Page::Onboarding(OnboardingStep::RecoverIdentity(
                RecoverStep::EnterShards,
            )));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if core::primary_button(ui, "Login", can_login) {
                start_login(state, rt, has_stored_machine_key);
            }
        });
    });
}

fn start_login(state: &mut AppState, rt: &tokio::runtime::Handle, has_stored_machine_key: bool) {
    let passphrase = state.login_passphrase.clone();
    let user_shard_hex = state.login_user_shard_hex.clone();
    let tx = state.tx.clone();
    let client = state.http_client.clone();

    let cred_path = state.storage.credentials_path();
    let creds: StoredCredentials = match state.storage.read_json(&cred_path) {
        Ok(c) => c,
        Err(e) => {
            state.add_toast(ToastLevel::Error, e.to_string());
            return;
        }
    };

    state.current_page = Page::Onboarding(OnboardingStep::Login(LoginStep::Authenticating));

    rt.spawn(async move {
        let login_result = if has_stored_machine_key {
            login_with_machine_seed(&client, &passphrase, &creds).await
        } else {
            login_with_shard(&client, &passphrase, &user_shard_hex, &creds).await
        };

        match login_result {
            Ok((session, identity)) => {
                let stored_session = StoredSession {
                    access_token: session.access_token.clone(),
                    refresh_token: session.refresh_token.clone(),
                    session_id: session.session_id,
                    expires_at: session.expires_at.clone(),
                };
                let _ = tx.send(AppMessage::LoginSuccess {
                    session,
                    identity,
                    stored_session,
                });
            }
            Err(e) => {
                let _ = tx.send(AppMessage::Error(e));
                let _ = tx.send(AppMessage::Navigate(Page::Onboarding(
                    OnboardingStep::Login(LoginStep::EnterPassphrase),
                )));
            }
        }
    });
}

async fn login_with_machine_seed(
    client: &crate::infra::http_client::HttpClient,
    passphrase: &str,
    creds: &StoredCredentials,
) -> Result<(crate::service::session::SessionTokens, IdentityViewModel), AppError> {
    let kek = crypto_adapter::derive_kek(passphrase, &creds.kek_salt)?;
    let nonce: [u8; 24] = creds
        .machine_key_nonce
        .as_slice()
        .try_into()
        .map_err(|_| AppError::StorageError("Invalid nonce length".into()))?;
    let seed_bytes =
        crypto_adapter::decrypt_machine_seed(&kek, &creds.encrypted_machine_signing_seed, &nonce, &creds.identity_id)?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| AppError::CryptoError("Invalid seed length".into()))?;
    let keypair = zid_crypto::Ed25519KeyPair::from_seed(&seed)
        .map_err(|e| AppError::CryptoError(e.to_string()))?;

    let session =
        crate::service::session::login_machine(client, &creds.machine_id, &keypair).await?;

    let mut auth_client = client.clone();
    auth_client.set_access_token(Some(session.access_token.clone()));
    let identity = crate::service::identity::get_current(&auth_client).await?;

    Ok((session, identity))
}

async fn login_with_shard(
    client: &crate::infra::http_client::HttpClient,
    passphrase: &str,
    user_shard_hex: &str,
    creds: &StoredCredentials,
) -> Result<(crate::service::session::SessionTokens, IdentityViewModel), AppError> {
    let user_share = zid_crypto::ShamirShare::from_hex(user_shard_hex)
        .map_err(|e| AppError::InvalidInput(format!("Invalid shard: {e:?}")))?;

    let nonce: [u8; 24] = creds
        .shards_nonce
        .as_slice()
        .try_into()
        .map_err(|_| AppError::StorageError("Invalid nonce".into()))?;
    let commitment: [u8; 32] = creds
        .neural_key_commitment
        .as_slice()
        .try_into()
        .map_err(|_| AppError::StorageError("Invalid commitment".into()))?;

    let (share_0, share_1) = crate::service::key_shard::decrypt_device_shards(
        &creds.encrypted_shard_1,
        &creds.encrypted_shard_2,
        &nonce,
        &creds.kek_salt,
        &creds.identity_id,
        passphrase,
    )?;

    let neural_key =
        crate::service::key_shard::combine(&[share_0, share_1, user_share], &commitment)?;

    let keys = crate::service::key_shard::derive_keys(
        &neural_key,
        &creds.identity_id,
        &creds.machine_id,
        0,
    )?;

    let signing_seed = crate::infra::crypto_adapter::machine_signing_seed(&keys.machine_keypair);
    let keypair = zid_crypto::Ed25519KeyPair::from_seed(&signing_seed)
        .map_err(|e| AppError::CryptoError(e.to_string()))?;

    let session =
        crate::service::session::login_machine(client, &creds.machine_id, &keypair).await?;

    let mut auth_client = client.clone();
    auth_client.set_access_token(Some(session.access_token.clone()));
    let identity = crate::service::identity::get_current(&auth_client).await?;

    Ok((session, identity))
}

fn render_authenticating(ui: &mut Ui) {
    ui.add_space(40.0);
    core::spinner(ui, "Authenticating...");
}
