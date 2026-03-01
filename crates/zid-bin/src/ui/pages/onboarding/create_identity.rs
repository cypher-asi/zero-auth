use egui::{RichText, Ui};

use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::AppState;
use crate::ui::components::{core, domain};
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, step: CreateStep, rt: &tokio::runtime::Handle) {
    ui.vertical_centered(|ui| {
        ui.set_max_width(600.0);
        ui.add_space(32.0);

        let step_idx = match &step {
            CreateStep::Generating => 0,
            CreateStep::Passphrase => 1,
            CreateStep::ShardBackup => 2,
            CreateStep::Done => 3,
        };
        core::progress_stepper(ui, &["Generate", "Passphrase", "Backup", "Done"], step_idx);
        ui.add_space(24.0);

        match step {
            CreateStep::Passphrase => render_passphrase(ui, state, rt),
            CreateStep::Generating => render_generating(ui),
            CreateStep::ShardBackup => render_shard_backup(ui, state),
            CreateStep::Done => render_done(ui, state),
        }
    });
}

fn render_passphrase(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    core::section_label(ui, "Protect Your Identity");
    ui.label(
        RichText::new("Choose a strong passphrase to protect your backup shard.")
            .color(theme::TEXT_SECONDARY),
    );
    ui.add_space(16.0);

    let valid = domain::passphrase_input(
        ui,
        &mut state.create_passphrase,
        Some(&mut state.create_passphrase_confirm),
        true,
    );

    ui.add_space(24.0);
    ui.horizontal(|ui| {
        if core::secondary_button(ui, "Back") {
            state.go_back();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if core::primary_button(ui, "Create Identity", valid) {
                let passphrase = state.create_passphrase.clone();
                let tx = state.tx.clone();
                let client = state.http_client.clone();

                state.current_page = Page::Onboarding(OnboardingStep::CreateIdentity(
                    CreateStep::Generating,
                ));

                rt.spawn(async move {
                    match crate::service::identity::create_self_sovereign(
                        &client,
                        &passphrase,
                        "Desktop App",
                        &std::env::consts::OS,
                    )
                    .await
                    {
                        Ok(result) => {
                            let user_shard_hexes: Vec<String> = result
                                .shard_set
                                .user_shards
                                .iter()
                                .map(|s| hex::encode(s.to_bytes()))
                                .collect();

                            let stored_creds = StoredCredentials {
                                encrypted_shard_1: result.shard_set.device_shard_1_encrypted,
                                encrypted_shard_2: result.shard_set.device_shard_2_encrypted,
                                shards_nonce: result.shard_set.nonce.to_vec(),
                                kek_salt: result.shard_set.salt.to_vec(),
                                encrypted_machine_signing_seed: result.encrypted_machine_seed,
                                machine_key_nonce: result.machine_key_nonce.to_vec(),
                                neural_key_commitment: result.shard_set.neural_key_commitment.to_vec(),
                                identity_id: result.response.identity_id,
                                machine_id: result.response.machine_id,
                                identity_signing_public_key: hex::encode(result.isk_public),
                                machine_signing_public_key: result.machine_signing_pub,
                                machine_encryption_public_key: result.machine_encryption_pub,
                                device_name: "Desktop App".into(),
                                device_platform: std::env::consts::OS.into(),
                            };

                            let session_tokens = crate::service::session::login_machine_after_create(
                                &client,
                                &result.response.machine_id,
                                &passphrase,
                                &stored_creds,
                            ).await;

                            match session_tokens {
                                Ok(session) => {
                                    let stored_session = StoredSession {
                                        access_token: session.access_token.clone(),
                                        refresh_token: session.refresh_token.clone(),
                                        session_id: session.session_id,
                                        expires_at: session.expires_at.clone(),
                                    };

                                    let identity = IdentityViewModel {
                                        identity_id: result.response.identity_id,
                                        did: String::new(),
                                        tier: "SelfSovereign".into(),
                                        status: "Active".into(),
                                        created_at: result.response.created_at.clone(),
                                        updated_at: result.response.created_at,
                                        frozen: false,
                                        freeze_reason: None,
                                    };

                                    let _ = tx.send(AppMessage::IdentityCreated {
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
                        }
                    }
                });
            }
        });
    });
}

fn render_generating(ui: &mut Ui) {
    ui.add_space(40.0);
    core::spinner(ui, "Generating Neural Key and creating identity...");
    ui.add_space(8.0);
    ui.label(
        RichText::new("This may take a moment (Argon2id key derivation)")
            .color(theme::TEXT_MUTED)
            .font(theme::small_font()),
    );
}

fn render_shard_backup(ui: &mut Ui, state: &mut AppState) {
    core::section_label(ui, "Recovery Shards");

    let frame = egui::Frame::none()
        .fill(theme::WARNING.linear_multiply(0.1))
        .inner_margin(egui::Margin::same(12.0))
        .rounding(egui::Rounding::same(8.0))
        .stroke(egui::Stroke::new(1.0, theme::WARNING));
    frame.show(ui, |ui| {
        ui.label(
            RichText::new(
                "These recovery shards are the ONLY way to recover your identity. \
                 Store each shard in a different secure location. They will NOT be shown again.",
            )
            .color(theme::WARNING),
        );
    });
    ui.add_space(12.0);

    for (i, shard_hex) in state.create_user_shards.clone().iter().enumerate() {
        domain::shard_card(ui, i, shard_hex);
        ui.add_space(4.0);
    }

    ui.add_space(12.0);
    core::acknowledge_checkbox(
        ui,
        &mut state.create_shards_acknowledged,
        "I have securely stored all three shards",
    );

    ui.add_space(16.0);
    if core::primary_button(ui, "Continue to Dashboard", state.create_shards_acknowledged) {
        state.create_passphrase.clear();
        state.create_passphrase_confirm.clear();
        state.create_user_shards.clear();
        state.create_shards_acknowledged = false;
        state.current_page = Page::Dashboard;
    }
}

fn render_done(ui: &mut Ui, state: &mut AppState) {
    ui.add_space(40.0);
    ui.label(
        RichText::new("Identity Created Successfully!")
            .font(theme::heading_font())
            .color(theme::SUCCESS),
    );
    ui.add_space(16.0);
    if core::primary_button(ui, "Go to Dashboard", true) {
        state.current_page = Page::Dashboard;
    }
}
