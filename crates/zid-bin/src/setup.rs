use egui::{RichText, Ui};

use crate::components::tokens::{self, colors, font_size, spacing};
use crate::components::{buttons, domain, feedback, inputs, labels, layout};
use crate::error::AppError;
use crate::infra::crypto_adapter;
use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::AppState;

pub fn render(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    match &state.current_page {
        Page::Onboarding(step) => match step {
            OnboardingStep::Welcome => render_welcome(ui, state),
            OnboardingStep::CreateIdentity(step) => {
                render_create(ui, state, step.clone(), rt);
            }
            OnboardingStep::RecoverIdentity(step) => {
                render_recover(ui, state, step.clone(), rt);
            }
            OnboardingStep::Login(step) => {
                render_login(ui, state, step.clone(), rt);
            }
        },
        _ => {}
    }
}

fn render_welcome(ui: &mut Ui, state: &mut AppState) {
    layout::auth_screen_panel(ui, 500.0, |ui| {
        ui.add_space(60.0);
        ui.label(
            RichText::new("ZERO-ID")
                .size(24.0)
                .color(colors::ACCENT),
        );
        ui.add_space(spacing::MD);
        labels::field_label(ui, "Self-sovereign identity, post-quantum ready");
        ui.add_space(spacing::XXXL);

        render_welcome_profile_selector(ui, state);
        ui.add_space(spacing::XXL);

        if buttons::action_button(ui, "Create New Identity", true) {
            state.navigate(Page::Onboarding(OnboardingStep::CreateIdentity(
                CreateStep::Passphrase,
            )));
        }
        ui.add_space(spacing::LG);
        if buttons::std_button(ui, "Recover Existing Identity") {
            state.navigate(Page::Onboarding(OnboardingStep::RecoverIdentity(
                RecoverStep::EnterShards,
            )));
        }
    });
}

fn render_welcome_profile_selector(ui: &mut Ui, state: &mut AppState) {
    if state.profiles.len() <= 1 {
        return;
    }

    let profiles: Vec<&ProfileInfo> = state.profiles.iter().collect();
    let selected = state.active_profile.clone();

    ui.horizontal(|ui| {
        labels::hint_label(ui, "Profile");

        let combo = egui::ComboBox::from_id_salt("welcome_profile_selector")
            .selected_text(
                RichText::new(&selected)
                    .color(colors::TEXT_SECONDARY)
                    .size(font_size::BODY),
            )
            .width(140.0);

        let response = combo.show_ui(ui, |ui| {
            let mut switched_to: Option<String> = None;
            for p in &profiles {
                let label = if p.has_credentials {
                    format!("{} ●", p.name)
                } else {
                    p.name.clone()
                };
                if ui.selectable_label(p.name == selected, label).clicked() && p.name != selected {
                    switched_to = Some(p.name.clone());
                }
            }
            switched_to
        });

        if let Some(inner) = response.inner {
            if let Some(name) = inner {
                let _ = state.tx.send(AppMessage::ProfileSwitched(name));
            }
        }
    });

    let has_configured = profiles.iter().any(|p| p.has_credentials && !p.is_active);
    if has_configured {
        ui.add_space(spacing::SM);
        labels::hint_label(ui, "● = has identity");
    }
}

// --- Login ---

fn render_login(ui: &mut Ui, state: &mut AppState, step: LoginStep, rt: &tokio::runtime::Handle) {
    layout::auth_screen_panel(ui, 500.0, |ui| {
        ui.add_space(40.0);

        ui.label(
            RichText::new("WELCOME BACK")
                .size(font_size::SUBTITLE)
                .color(colors::TEXT_HEADING),
        );
        ui.add_space(spacing::XXL);

        match step {
            LoginStep::EnterPassphrase => render_passphrase_entry(ui, state, rt),
            LoginStep::Authenticating => render_authenticating(ui),
        }
    });
}

fn render_passphrase_entry(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    render_profile_switcher(ui, state);
    ui.add_space(spacing::LG);

    labels::field_label(ui, "Enter your passphrase to unlock");
    ui.add_space(spacing::XL);

    inputs::text_input_password(ui, &mut state.login_passphrase, "Passphrase");
    ui.add_space(spacing::LG);

    let has_stored_machine_key = {
        let cred_path = state.storage.credentials_path();
        state
            .storage
            .read_json::<StoredCredentials>(&cred_path)
            .map(|c| !c.encrypted_machine_signing_seed.is_empty())
            .unwrap_or(false)
    };

    if !has_stored_machine_key {
        labels::hint_label(ui, "Enter one of your three recovery shards (hex)");
        inputs::hex_input(ui, &mut state.login_user_shard_hex, "Recovery shard hex");
    }

    ui.add_space(spacing::XL);
    render_login_help(ui, state);
    ui.add_space(spacing::XL);

    let can_login = !state.login_passphrase.is_empty()
        && (has_stored_machine_key || !state.login_user_shard_hex.is_empty());

    ui.horizontal(|ui| {
        if buttons::std_button(ui, "Recover Identity") {
            state.navigate(Page::Onboarding(OnboardingStep::RecoverIdentity(
                RecoverStep::EnterShards,
            )));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if buttons::action_button(ui, "Login", can_login) {
                start_login(state, rt, has_stored_machine_key);
            }
        });
    });
}

fn render_profile_switcher(ui: &mut Ui, state: &mut AppState) {
    let profiles: Vec<String> = state.profiles.iter().map(|p| p.name.clone()).collect();
    if profiles.is_empty() {
        return;
    }

    ui.horizontal(|ui| {
        labels::hint_label(ui, "Profile");

        let mut selected = state.active_profile.clone();
        let response = egui::ComboBox::from_id_salt("onboarding_profile_selector")
            .selected_text(
                RichText::new(selected.clone())
                    .color(colors::TEXT_SECONDARY)
                    .size(font_size::BODY),
            )
            .show_ui(ui, |ui| {
                let mut switched_to: Option<String> = None;
                for name in &profiles {
                    if ui.selectable_label(*name == selected, name).clicked() && *name != selected {
                        switched_to = Some(name.clone());
                    }
                }
                switched_to
            });

        if let Some(inner) = response.inner {
            if let Some(name) = inner {
                selected = name.clone();
                let _ = state.tx.send(AppMessage::ProfileSwitched(name));
            }
        }

        let _ = selected;
    });
}

fn render_login_help(ui: &mut Ui, state: &AppState) {
    layout::card_frame().show(ui, |ui| {
        labels::hint_label(
            ui,
            "If this device was revoked, passphrase login will fail.",
        );
        labels::hint_label(
            ui,
            "Use Recover Identity to re-enroll this machine, or switch Profile to access another identity.",
        );
        if !state.profiles.is_empty() {
            labels::hint_label(
                ui,
                &format!("Current profile: {}", state.active_profile),
            );
        }
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
    let seed_bytes = crypto_adapter::decrypt_machine_seed(
        &kek,
        &creds.encrypted_machine_signing_seed,
        &nonce,
        &creds.identity_id,
    )?;
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
    feedback::loading_state(ui, "Authenticating...");
}

// --- Create Identity ---

fn render_create(
    ui: &mut Ui,
    state: &mut AppState,
    step: CreateStep,
    rt: &tokio::runtime::Handle,
) {
    layout::auth_screen_panel(ui, 600.0, |ui| {
        let step_idx = match &step {
            CreateStep::Generating => 0,
            CreateStep::Passphrase => 1,
            CreateStep::ShardBackup => 2,
            CreateStep::Done => 3,
        };
        feedback::progress_stepper(ui, &["Generate", "Passphrase", "Backup", "Done"], step_idx);
        ui.add_space(spacing::XXL);

        match step {
            CreateStep::Passphrase => render_create_passphrase(ui, state, rt),
            CreateStep::Generating => render_creating(ui),
            CreateStep::ShardBackup => render_shard_backup(ui, state),
            CreateStep::Done => render_create_done(ui, state),
        }
    });
}

fn render_create_passphrase(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    labels::section_heading(ui, "Protect Your Identity");
    labels::field_label(
        ui,
        "Choose a strong passphrase to protect your backup shard.",
    );
    ui.add_space(spacing::XL);

    let valid = domain::passphrase_input(
        ui,
        &mut state.create_passphrase,
        Some(&mut state.create_passphrase_confirm),
        true,
    );

    ui.add_space(spacing::XXL);
    ui.horizontal(|ui| {
        if buttons::std_button(ui, "Back") {
            state.go_back();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if buttons::action_button(ui, "Create Identity", valid) {
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
                                neural_key_commitment: result
                                    .shard_set
                                    .neural_key_commitment
                                    .to_vec(),
                                identity_id: result.response.identity_id,
                                machine_id: result.response.machine_id,
                                identity_signing_public_key: hex::encode(result.isk_public),
                                machine_signing_public_key: result.machine_signing_pub,
                                machine_encryption_public_key: result.machine_encryption_pub,
                                device_name: "Desktop App".into(),
                                device_platform: std::env::consts::OS.into(),
                            };

                            let session_tokens =
                                crate::service::session::login_machine_after_create(
                                    &client,
                                    &result.response.machine_id,
                                    &passphrase,
                                    &stored_creds,
                                )
                                .await;

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

fn render_creating(ui: &mut Ui) {
    ui.add_space(40.0);
    feedback::loading_state(ui, "Generating Neural Key and creating identity...");
    ui.add_space(spacing::MD);
    labels::hint_label(ui, "This may take a moment (Argon2id key derivation)");
}

fn render_shard_backup(ui: &mut Ui, state: &mut AppState) {
    labels::section_heading(ui, "Recovery Shards");

    layout::warning_frame(
        ui,
        "These recovery shards are the ONLY way to recover your identity. Store each shard in a different secure location. They will NOT be shown again.",
    );
    ui.add_space(spacing::LG);

    for (i, shard_hex) in state.create_user_shards.clone().iter().enumerate() {
        domain::shard_card(ui, i, shard_hex);
        ui.add_space(spacing::SM);
    }

    ui.add_space(spacing::MD);
    domain::copy_all_shards_button(ui, &state.create_user_shards);

    ui.add_space(spacing::LG);
    domain::acknowledge_checkbox(
        ui,
        &mut state.create_shards_acknowledged,
        "I have securely stored all three shards",
    );

    ui.add_space(spacing::XL);
    if buttons::action_button(ui, "Continue to Dashboard", state.create_shards_acknowledged) {
        state.create_passphrase.clear();
        state.create_passphrase_confirm.clear();
        state.create_user_shards.clear();
        state.create_shards_acknowledged = false;
        state.current_page = Page::Dashboard;
    }
}

fn render_create_done(ui: &mut Ui, state: &mut AppState) {
    ui.add_space(40.0);
    ui.label(
        RichText::new("IDENTITY CREATED")
            .size(font_size::SUBTITLE)
            .color(tokens::SUCCESS),
    );
    ui.add_space(spacing::XL);
    if buttons::action_button(ui, "Go to Dashboard", true) {
        state.current_page = Page::Dashboard;
    }
}

// --- Recover Identity ---

fn render_recover(
    ui: &mut Ui,
    state: &mut AppState,
    step: RecoverStep,
    rt: &tokio::runtime::Handle,
) {
    layout::auth_screen_panel(ui, 600.0, |ui| {
        let step_idx = match &step {
            RecoverStep::EnterShards => 0,
            RecoverStep::Recovering => 1,
            RecoverStep::NewPassphrase => 2,
            RecoverStep::NewShardBackup => 3,
            RecoverStep::Done => 4,
        };
        feedback::progress_stepper(
            ui,
            &["Enter Shards", "Recovering", "New Passphrase", "New Backup", "Done"],
            step_idx,
        );
        ui.add_space(spacing::XXL);

        match step {
            RecoverStep::EnterShards => render_enter_shards(ui, state),
            RecoverStep::Recovering => render_recovering(ui),
            RecoverStep::NewPassphrase => render_new_passphrase(ui, state, rt),
            RecoverStep::NewShardBackup => render_new_shard_backup(ui, state),
            RecoverStep::Done => render_recover_done(ui, state),
        }
    });
}

fn render_enter_shards(ui: &mut Ui, state: &mut AppState) {
    layout::danger_frame(
        ui,
        "Identity recovery requires at least 3 of your 5 recovery shards. This will revoke all existing machines and create a new one.",
    );

    ui.add_space(spacing::XL);
    labels::section_heading(ui, "Enter Recovery Shards");

    while state.recovery_shard_inputs.len() < 3 {
        state.recovery_shard_inputs.push(String::new());
    }

    for i in 0..state.recovery_shard_inputs.len() {
        let label = format!("Shard {} (hex)", i + 1);
        inputs::hex_input(ui, &mut state.recovery_shard_inputs[i], &label);
        ui.add_space(spacing::SM);
    }

    if state.recovery_shard_inputs.len() < 5 {
        if buttons::std_button(ui, "+ Add another shard") {
            state.recovery_shard_inputs.push(String::new());
        }
    }

    let valid_count = state
        .recovery_shard_inputs
        .iter()
        .filter(|s| !s.trim().is_empty())
        .count();

    ui.add_space(spacing::XL);
    ui.horizontal(|ui| {
        if buttons::std_button(ui, "Back") {
            state.go_back();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if buttons::action_button(ui, "Begin Recovery", valid_count >= 3) {
                state.current_page = Page::Onboarding(OnboardingStep::RecoverIdentity(
                    RecoverStep::NewPassphrase,
                ));
            }
        });
    });
}

fn render_recovering(ui: &mut Ui) {
    ui.add_space(40.0);
    feedback::loading_state(ui, "Recovering identity...");
}

fn render_new_passphrase(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    labels::section_heading(ui, "Set New Passphrase");
    labels::field_label(
        ui,
        "Choose a new passphrase to protect your recovery shards.",
    );
    ui.add_space(spacing::LG);

    let valid = domain::passphrase_input(
        ui,
        &mut state.recovery_passphrase,
        Some(&mut state.recovery_passphrase_confirm),
        true,
    );

    ui.add_space(spacing::XL);
    ui.horizontal(|ui| {
        if buttons::std_button(ui, "Back") {
            state.current_page = Page::Onboarding(OnboardingStep::RecoverIdentity(
                RecoverStep::EnterShards,
            ));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if buttons::action_button(ui, "Recover", valid) {
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
                    .map_err(|e| AppError::InvalidInput(format!("Invalid shard: {e:?}")))
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
                let _ = tx.send(AppMessage::Error(AppError::ShardCombineFailed));
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

                let (enc_seed, mk_nonce) =
                    match crate::service::key_shard::encrypt_machine_seed_for_storage(
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

                let pk = crypto_adapter::extract_machine_public_keys(&keys.machine_keypair);

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

                let seed = crypto_adapter::machine_signing_seed(&keys.machine_keypair);
                let keypair = match zid_crypto::Ed25519KeyPair::from_seed(&seed) {
                    Ok(kp) => kp,
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(AppError::CryptoError(e.to_string())));
                        return;
                    }
                };

                match crate::service::session::login_machine(
                    &client,
                    &response.machine_id,
                    &keypair,
                )
                .await
                {
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
    labels::section_heading(ui, "New Recovery Shards");

    layout::warning_frame(
        ui,
        "Your OLD shards are now invalid. Store these NEW shards securely.",
    );

    ui.add_space(spacing::LG);
    for (i, shard_hex) in state.recovery_new_shards.clone().iter().enumerate() {
        domain::shard_card(ui, i, shard_hex);
        ui.add_space(spacing::SM);
    }

    ui.add_space(spacing::MD);
    domain::copy_all_shards_button(ui, &state.recovery_new_shards);

    ui.add_space(spacing::LG);
    domain::acknowledge_checkbox(
        ui,
        &mut state.recovery_shards_acknowledged,
        "I have securely stored all new shards",
    );

    ui.add_space(spacing::XL);
    if buttons::action_button(
        ui,
        "Continue to Dashboard",
        state.recovery_shards_acknowledged,
    ) {
        state.recovery_shard_inputs = vec![String::new(); 3];
        state.recovery_passphrase.clear();
        state.recovery_passphrase_confirm.clear();
        state.recovery_new_shards.clear();
        state.recovery_shards_acknowledged = false;
        state.current_page = Page::Dashboard;
    }
}

fn render_recover_done(ui: &mut Ui, state: &mut AppState) {
    ui.add_space(40.0);
    ui.label(
        RichText::new("IDENTITY RECOVERED")
            .size(font_size::SUBTITLE)
            .color(tokens::SUCCESS),
    );
    ui.add_space(spacing::XL);
    if buttons::action_button(ui, "Go to Dashboard", true) {
        state.current_page = Page::Dashboard;
    }
}
