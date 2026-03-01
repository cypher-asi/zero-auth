use egui::{RichText, Ui};

use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::AppState;
use crate::ui::components::{core, domain};
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, step: RecoverStep, rt: &tokio::runtime::Handle) {
    ui.vertical_centered(|ui| {
        ui.set_max_width(600.0);
        ui.add_space(32.0);

        let step_idx = match &step {
            RecoverStep::EnterShards => 0,
            RecoverStep::Recovering => 1,
            RecoverStep::NewPassphrase => 2,
            RecoverStep::NewShardBackup => 3,
            RecoverStep::Done => 4,
        };
        core::progress_stepper(
            ui,
            &["Enter Shards", "Recovering", "New Passphrase", "New Backup", "Done"],
            step_idx,
        );
        ui.add_space(24.0);

        match step {
            RecoverStep::EnterShards => render_enter_shards(ui, state),
            RecoverStep::Recovering => render_recovering(ui),
            RecoverStep::NewPassphrase => render_new_passphrase(ui, state, rt),
            RecoverStep::NewShardBackup => render_new_shard_backup(ui, state),
            RecoverStep::Done => render_done(ui, state),
        }
    });
}

fn render_enter_shards(ui: &mut Ui, state: &mut AppState) {
    let frame = egui::Frame::none()
        .fill(theme::DANGER.linear_multiply(0.1))
        .inner_margin(egui::Margin::same(12.0))
        .rounding(egui::Rounding::same(8.0))
        .stroke(egui::Stroke::new(1.0, theme::DANGER));
    frame.show(ui, |ui| {
        ui.label(
            RichText::new(
                "Identity recovery requires at least 3 of your 5 recovery shards. \
                 This will revoke all existing machines and create a new one.",
            )
            .color(theme::DANGER),
        );
    });

    ui.add_space(16.0);
    core::section_label(ui, "Enter Recovery Shards");

    while state.recovery_shard_inputs.len() < 3 {
        state.recovery_shard_inputs.push(String::new());
    }

    for i in 0..state.recovery_shard_inputs.len() {
        let label = format!("Shard {} (hex)", i + 1);
        core::hex_input(ui, &mut state.recovery_shard_inputs[i], &label);
        ui.add_space(4.0);
    }

    if state.recovery_shard_inputs.len() < 5 {
        if core::secondary_button(ui, "+ Add another shard") {
            state.recovery_shard_inputs.push(String::new());
        }
    }

    let valid_count = state
        .recovery_shard_inputs
        .iter()
        .filter(|s| !s.trim().is_empty())
        .count();

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if core::secondary_button(ui, "Back") {
            state.go_back();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if core::primary_button(ui, "Begin Recovery", valid_count >= 3) {
                state.current_page = Page::Onboarding(OnboardingStep::RecoverIdentity(
                    RecoverStep::NewPassphrase,
                ));
            }
        });
    });
}

fn render_recovering(ui: &mut Ui) {
    ui.add_space(40.0);
    core::spinner(ui, "Recovering identity...");
}

fn render_new_passphrase(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    core::section_label(ui, "Set New Passphrase");
    ui.label(
        RichText::new("Choose a new passphrase to protect your recovery shards.")
            .color(theme::TEXT_SECONDARY),
    );
    ui.add_space(12.0);

    let valid = domain::passphrase_input(
        ui,
        &mut state.recovery_passphrase,
        Some(&mut state.recovery_passphrase_confirm),
        true,
    );

    ui.add_space(20.0);
    ui.horizontal(|ui| {
        if core::secondary_button(ui, "Back") {
            state.current_page = Page::Onboarding(OnboardingStep::RecoverIdentity(
                RecoverStep::EnterShards,
            ));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if core::primary_button(ui, "Recover", valid) {
                start_recovery(state, rt);
            }
        });
    });
}

fn start_recovery(state: &mut AppState, rt: &tokio::runtime::Handle) {
    let shard_hexes: Vec<String> = state
        .recovery_shard_inputs
        .iter()
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .collect();
    let passphrase = state.recovery_passphrase.clone();
    let tx = state.tx.clone();
    let client = state.http_client.clone();

    state.current_page = Page::Onboarding(OnboardingStep::RecoverIdentity(
        RecoverStep::Recovering,
    ));

    rt.spawn(async move {
        let shares: Vec<zid_crypto::ShamirShare> = match shard_hexes
            .iter()
            .map(|h| {
                zid_crypto::ShamirShare::from_hex(h.trim())
                    .map_err(|e| crate::error::AppError::InvalidInput(format!("Invalid shard: {e:?}")))
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(AppMessage::Error(e));
                let _ = tx.send(AppMessage::Navigate(Page::Onboarding(
                    OnboardingStep::RecoverIdentity(RecoverStep::EnterShards),
                )));
                return;
            }
        };

        let neural_key_bytes: [u8; 32] = match zid_crypto::shamir_combine(&shares) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = tx.send(AppMessage::Error(crate::error::AppError::ShardCombineFailed));
                let _ = tx.send(AppMessage::Navigate(Page::Onboarding(
                    OnboardingStep::RecoverIdentity(RecoverStep::EnterShards),
                )));
                return;
            }
        };
        let neural_key = zid_crypto::NeuralKey::from_bytes(neural_key_bytes);

        let identity_id = uuid::Uuid::new_v4();

        match crate::service::ceremonies::recover(
            &client,
            &neural_key,
            &identity_id,
            "Desktop App",
            std::env::consts::OS,
        )
        .await
        {
            Ok(response) => {
                let shard_set = match crate::service::key_shard::split_and_encrypt(
                    &neural_key,
                    &response.identity_id,
                    &passphrase,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(e));
                        return;
                    }
                };

                let keys = match crate::service::key_shard::derive_keys(
                    &neural_key,
                    &response.identity_id,
                    &response.machine_id,
                    0,
                ) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(e));
                        return;
                    }
                };

                let (enc_seed, mk_nonce) = match crate::service::key_shard::encrypt_machine_seed_for_storage(
                    &keys.machine_keypair,
                    &passphrase,
                    &shard_set.salt,
                    &response.identity_id,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(e));
                        return;
                    }
                };

                let user_shard_hexes: Vec<String> = shard_set
                    .user_shards
                    .iter()
                    .map(|s| hex::encode(s.to_bytes()))
                    .collect();

                let pk = crate::infra::crypto_adapter::extract_machine_public_keys(&keys.machine_keypair);

                let stored_creds = StoredCredentials {
                    encrypted_shard_1: shard_set.device_shard_1_encrypted,
                    encrypted_shard_2: shard_set.device_shard_2_encrypted,
                    shards_nonce: shard_set.nonce.to_vec(),
                    kek_salt: shard_set.salt.to_vec(),
                    encrypted_machine_signing_seed: enc_seed,
                    machine_key_nonce: mk_nonce.to_vec(),
                    neural_key_commitment: shard_set.neural_key_commitment.to_vec(),
                    identity_id: response.identity_id,
                    machine_id: response.machine_id,
                    identity_signing_public_key: hex::encode(keys.isk_public),
                    machine_signing_public_key: hex::encode(pk.signing),
                    machine_encryption_public_key: hex::encode(pk.encryption),
                    device_name: "Desktop App".into(),
                    device_platform: std::env::consts::OS.into(),
                };

                let seed = crate::infra::crypto_adapter::machine_signing_seed(&keys.machine_keypair);
                let keypair = match zid_crypto::Ed25519KeyPair::from_seed(&seed) {
                    Ok(kp) => kp,
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(crate::error::AppError::CryptoError(e.to_string())));
                        return;
                    }
                };

                match crate::service::session::login_machine(&client, &response.machine_id, &keypair).await {
                    Ok(session) => {
                        let stored_session = StoredSession {
                            access_token: session.access_token.clone(),
                            refresh_token: session.refresh_token.clone(),
                            session_id: session.session_id,
                            expires_at: session.expires_at.clone(),
                        };

                        let identity = IdentityViewModel {
                            identity_id: response.identity_id,
                            did: String::new(),
                            tier: "SelfSovereign".into(),
                            status: "Active".into(),
                            created_at: response.created_at.clone(),
                            updated_at: response.created_at,
                            frozen: false,
                            freeze_reason: None,
                        };

                        let _ = tx.send(AppMessage::RecoveryComplete {
                            identity,
                            session,
                            user_shard_hexes,
                            stored_credentials: stored_creds,
                            stored_session,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(e));
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(AppMessage::Error(e));
                let _ = tx.send(AppMessage::Navigate(Page::Onboarding(
                    OnboardingStep::RecoverIdentity(RecoverStep::EnterShards),
                )));
            }
        }
    });
}

fn render_new_shard_backup(ui: &mut Ui, state: &mut AppState) {
    core::section_label(ui, "New Recovery Shards");

    let frame = egui::Frame::none()
        .fill(theme::WARNING.linear_multiply(0.1))
        .inner_margin(egui::Margin::same(12.0))
        .rounding(egui::Rounding::same(8.0))
        .stroke(egui::Stroke::new(1.0, theme::WARNING));
    frame.show(ui, |ui| {
        ui.label(
            RichText::new(
                "Your OLD shards are now invalid. Store these NEW shards securely.",
            )
            .color(theme::WARNING),
        );
    });

    ui.add_space(12.0);
    for (i, shard_hex) in state.recovery_new_shards.clone().iter().enumerate() {
        domain::shard_card(ui, i, shard_hex);
        ui.add_space(4.0);
    }

    ui.add_space(12.0);
    core::acknowledge_checkbox(
        ui,
        &mut state.recovery_shards_acknowledged,
        "I have securely stored all new shards",
    );

    ui.add_space(16.0);
    if core::primary_button(ui, "Continue to Dashboard", state.recovery_shards_acknowledged) {
        state.recovery_shard_inputs = vec![String::new(); 3];
        state.recovery_passphrase.clear();
        state.recovery_passphrase_confirm.clear();
        state.recovery_new_shards.clear();
        state.recovery_shards_acknowledged = false;
        state.current_page = Page::Dashboard;
    }
}

fn render_done(ui: &mut Ui, state: &mut AppState) {
    ui.add_space(40.0);
    ui.label(
        RichText::new("Identity Recovered!")
            .font(theme::heading_font())
            .color(theme::SUCCESS),
    );
    ui.add_space(16.0);
    if core::primary_button(ui, "Go to Dashboard", true) {
        state.current_page = Page::Dashboard;
    }
}
