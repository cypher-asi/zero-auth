use egui::{RichText, Ui};

use crate::components::tokens::{self, colors, font_size, spacing};
use crate::components::{buttons, data_display, domain, feedback, inputs, labels, layout};
use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::{AppState, ConfirmAction, ConfirmDialogState};

pub fn render_page(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    match &state.current_page {
        Page::Dashboard => render_dashboard(ui, state, rt),
        Page::Machines => render_machines(ui, state, rt),
        Page::Credentials => render_credentials(ui, state, rt),
        Page::Mfa => render_mfa(ui, state, rt),
        Page::Sessions => render_sessions(ui, state, rt),
        Page::Namespaces => render_namespaces(ui, state, rt),
        Page::Security => render_security(ui, state, rt),
        Page::Settings => render_settings(ui, state, rt),
        Page::Onboarding(_) => unreachable!(),
    }
}

fn render_dashboard(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Dashboard", None);

    if state.identity_status == LoadStatus::Idle {
        state.identity_status = LoadStatus::Loading;
        let tx = state.tx.clone();
        let client = state.http_client.clone();
        rt.spawn(async move {
            match crate::service::identity::get_current(&client).await {
                Ok(id) => {
                    let _ = tx.send(AppMessage::IdentityLoaded(id));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }

    if let Some(identity) = &state.identity.clone() {
        layout::section(ui, "Identity", |ui| {
            domain::identity_badge(ui, identity);
            ui.add_space(spacing::XL);

            data_display::info_grid(ui, "identity_details", |ui| {
                data_display::kv_row(ui, "Identity ID", &identity.identity_id.to_string());
                if !identity.did.is_empty() {
                    data_display::kv_row_mono(ui, "DID", &identity.did);
                }
                data_display::kv_row(ui, "Tier", &identity.tier);
                data_display::kv_row(ui, "Status", &identity.status);
                data_display::kv_row(ui, "Created", &identity.created_at);
            });
        });

        layout::section(ui, "Quick Actions", |ui| {
            ui.horizontal(|ui| {
                if buttons::action_button(ui, "View Machines", true) {
                    state.navigate(Page::Machines);
                }
                if buttons::std_button(ui, "Linked Identities") {
                    state.navigate(Page::Credentials);
                }
                if buttons::std_button(ui, "Security") {
                    state.navigate(Page::Security);
                }
            });
        });
    } else if state.identity_status == LoadStatus::Loading {
        feedback::loading_state(ui, "Loading identity...");
    } else if let LoadStatus::Error(ref e) = state.identity_status {
        labels::error_label(ui, e);
    }

    if let Some(session) = &state.current_session {
        layout::section(ui, "Current Session", |ui| {
            data_display::info_grid(ui, "session_info", |ui| {
                data_display::kv_row(ui, "Session ID", &session.session_id.to_string()[..8]);
                data_display::kv_row(ui, "Expires", &session.expires_at);
            });
        });
    }
}

fn render_machines(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Machines", None);

    if state.machines_status == LoadStatus::Idle {
        state.machines_status = LoadStatus::Loading;
        let tx = state.tx.clone();
        let client = state.http_client.clone();
        rt.spawn(async move {
            match crate::service::machine::list(&client).await {
                Ok(machines) => {
                    let _ = tx.send(AppMessage::MachinesLoaded(machines));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }

    let enroll_clicked = layout::section_with_action(ui, "Enrolled Machines", true, |ui| {
        match &state.machines_status {
            LoadStatus::Loading => feedback::loading_state(ui, "Loading machines..."),
            LoadStatus::Loaded => {
                if state.machines.is_empty() {
                    labels::muted_label(ui, "No machines enrolled");
                } else {
                    let cred_path = state.storage.credentials_path();
                    let current_machine = state
                        .storage
                        .read_json::<StoredCredentials>(&cred_path)
                        .ok()
                        .map(|c| c.machine_id);

                    let machines = state.machines.clone();
                    for machine in &machines {
                        if let Some(action) = domain::machine_card(ui, machine, current_machine) {
                            match action {
                                domain::MachineCardAction::Revoke(id) => {
                                    let is_current = current_machine == Some(id);
                                    let is_last = state.machines.len() == 1;
                                    let msg = if is_current {
                                        "You are about to revoke THIS machine. You will be logged out immediately."
                                    } else if is_last {
                                        "This is your only enrolled machine. Revoking it will require recovery to regain access."
                                    } else {
                                        "This device will immediately lose access. This cannot be undone."
                                    };
                                    state.confirm_dialog = Some(ConfirmDialogState {
                                        title: "Revoke Machine?".into(),
                                        message: msg.into(),
                                        confirm_label: "Revoke".into(),
                                        danger: true,
                                        action: ConfirmAction::RevokeMachine(id),
                                    });
                                }
                            }
                        }
                        ui.add_space(spacing::SM);
                    }
                }
            }
            LoadStatus::Error(e) => labels::error_label(ui, e),
            _ => {}
        }
    });
    if enroll_clicked {
        state.show_enroll_dialog = true;
    }

    if state.show_enroll_dialog {
        render_enroll_dialog(ui, state, rt);
    }
}

fn render_enroll_dialog(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    let mut open = true;
    egui::Window::new("Enroll New Machine")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .fixed_size([400.0, 0.0])
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            labels::field_label(
                ui,
                "Reconstruct your Neural Key to derive a new machine keypair.",
            );
            ui.add_space(spacing::MD);
            inputs::text_input(
                ui,
                &mut state.enroll_machine_name,
                "Machine name (e.g. Work Laptop)",
            );
            ui.add_space(spacing::MD);
            inputs::text_input_password(ui, &mut state.enroll_passphrase, "Passphrase");
            ui.add_space(spacing::MD);
            labels::hint_label(ui, "Enter one of your three recovery shards (hex)");
            inputs::hex_input(ui, &mut state.enroll_user_shard_hex, "Recovery shard hex");
            ui.add_space(spacing::XL);

            ui.horizontal(|ui| {
                if buttons::ghost_button(ui, "Cancel") {
                    state.show_enroll_dialog = false;
                    state.enroll_machine_name.clear();
                    state.enroll_passphrase.clear();
                    state.enroll_user_shard_hex.clear();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can = !state.enroll_machine_name.is_empty()
                        && !state.enroll_passphrase.is_empty()
                        && !state.enroll_user_shard_hex.is_empty();
                    if buttons::action_button(ui, "Enroll", can) {
                        start_enrollment(state, rt);
                    }
                });
            });
        });

    if !open {
        state.show_enroll_dialog = false;
        state.enroll_machine_name.clear();
        state.enroll_passphrase.clear();
        state.enroll_user_shard_hex.clear();
    }
}

fn start_enrollment(state: &mut AppState, rt: &tokio::runtime::Handle) {
    let machine_name = state.enroll_machine_name.clone();
    let passphrase = state.enroll_passphrase.clone();
    let user_shard_hex = state.enroll_user_shard_hex.clone();
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

    rt.spawn(async move {
        let result =
            run_enrollment(&machine_name, &passphrase, &user_shard_hex, &creds, &client).await;
        match result {
            Ok(vm) => {
                let _ = tx.send(AppMessage::MachineEnrolled(vm));
            }
            Err(e) => {
                let _ = tx.send(AppMessage::Error(e));
            }
        }
    });
}

async fn run_enrollment(
    machine_name: &str,
    passphrase: &str,
    user_shard_hex: &str,
    creds: &StoredCredentials,
    client: &crate::infra::http_client::HttpClient,
) -> Result<MachineViewModel, crate::error::AppError> {
    use crate::error::AppError;

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

    let device_platform = std::env::consts::OS;

    let (response, _keypair) = crate::service::machine::enroll(
        client,
        &neural_key,
        &creds.identity_id,
        machine_name,
        device_platform,
    )
    .await?;

    Ok(MachineViewModel {
        machine_id: response.machine_id,
        device_name: machine_name.into(),
        device_platform: device_platform.into(),
        created_at: response.enrolled_at,
        last_used_at: None,
        revoked: false,
        key_scheme: "PQ-Hybrid".into(),
        capabilities: vec!["AUTHENTICATE".into(), "SIGN".into(), "ENCRYPT".into()],
        epoch: 0,
    })
}

fn render_credentials(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Linked Identities", None);

    if state.credentials_status == LoadStatus::Idle {
        state.credentials_status = LoadStatus::Loading;
        let tx = state.tx.clone();
        let client = state.http_client.clone();
        rt.spawn(async move {
            match crate::service::credentials::list(&client).await {
                Ok(creds) => {
                    let _ = tx.send(AppMessage::CredentialsLoaded(creds));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }

    let add_clicked = layout::section_with_action(ui, "Linked Credentials", true, |ui| {
        match &state.credentials_status {
            LoadStatus::Loading => feedback::loading_state(ui, "Loading credentials..."),
            LoadStatus::Loaded => {
                if state.credentials.is_empty() {
                    labels::muted_label(ui, "No linked credentials");
                } else {
                    let creds = state.credentials.clone();
                    for cred in &creds {
                        if let Some(action) = domain::credential_card(ui, cred) {
                            match action {
                                domain::CredentialCardAction::Revoke(method_type, method_id) => {
                                    state.confirm_dialog = Some(ConfirmDialogState {
                                        title: "Remove Credential?".into(),
                                        message: format!(
                                            "Remove {} credential '{}'? You will no longer be able to log in with this method.",
                                            method_type, method_id
                                        ),
                                        confirm_label: "Remove".into(),
                                        danger: true,
                                        action: ConfirmAction::RevokeCredential(
                                            method_type, method_id,
                                        ),
                                    });
                                }
                                domain::CredentialCardAction::SetPrimary(method_type, method_id) => {
                                    let tx = state.tx.clone();
                                    let client = state.http_client.clone();
                                    let mt = method_type.clone();
                                    let mi = method_id.clone();
                                    rt.spawn(async move {
                                        match crate::service::credentials::set_primary(
                                            &client, &mt, &mi,
                                        )
                                        .await
                                        {
                                            Ok(()) => {
                                                let _ = tx.send(AppMessage::CredentialPrimarySet {
                                                    method_type: mt,
                                                    method_id: mi,
                                                });
                                            }
                                            Err(e) => {
                                                let _ = tx.send(AppMessage::Error(e));
                                            }
                                        }
                                    });
                                }
                            }
                        }
                        ui.add_space(spacing::SM);
                    }
                }
            }
            LoadStatus::Error(e) => labels::error_label(ui, e),
            _ => {}
        }
    });
    if add_clicked {
        state.show_add_credential_dialog = true;
    }

    if state.show_add_credential_dialog {
        render_add_credential_dialog(ui, state, rt);
    }
}

fn render_add_credential_dialog(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    let mut open = true;
    egui::Window::new("Add Credential")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .fixed_size([420.0, 0.0])
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                let tabs = ["Email", "OAuth", "Wallet"];
                for (i, label) in tabs.iter().enumerate() {
                    let selected = state.add_cred_tab == i;
                    let color = if selected {
                        colors::ACCENT
                    } else {
                        colors::TEXT_MUTED
                    };
                    if ui
                        .selectable_label(
                            selected,
                            RichText::new(*label).color(color).size(font_size::BODY),
                        )
                        .clicked()
                    {
                        state.add_cred_tab = i;
                    }
                }
            });
            let rect = ui.available_rect_before_wrap();
            let line_rect =
                egui::Rect::from_min_size(rect.min, egui::vec2(rect.width(), 1.0));
            ui.painter()
                .rect_filled(line_rect, 0.0, colors::BORDER);
            ui.add_space(spacing::MD);

            match state.add_cred_tab {
                0 => render_email_tab(ui, state, rt),
                1 => render_oauth_tab(ui, state, rt),
                2 => render_wallet_tab(ui, state, rt),
                _ => {}
            }
        });

    if !open {
        state.show_add_credential_dialog = false;
    }
}

fn render_email_tab(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    inputs::text_input(ui, &mut state.add_email_address, "Email address");
    ui.add_space(spacing::SM);
    inputs::text_input_password(ui, &mut state.add_email_password, "Password");
    feedback::strength_bar(ui, &state.add_email_password);
    ui.add_space(spacing::LG);

    let can = !state.add_email_address.is_empty() && !state.add_email_password.is_empty();
    if buttons::action_button(ui, "Link Email", can) {
        let email = state.add_email_address.clone();
        let password = state.add_email_password.clone();
        let tx = state.tx.clone();
        let client = state.http_client.clone();
        rt.spawn(async move {
            match crate::service::credentials::link_email(&client, &email, &password).await {
                Ok(cred) => {
                    let _ = tx.send(AppMessage::CredentialLinked(cred));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }
}

fn render_oauth_tab(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    labels::field_label(ui, "Select a provider:");
    ui.add_space(spacing::MD);
    for provider in &["google", "x", "epic"] {
        if buttons::std_button(ui, &format!("Link {}", provider.to_uppercase())) {
            let provider = provider.to_string();
            let tx = state.tx.clone();
            let client = state.http_client.clone();
            rt.spawn(async move {
                match crate::service::credentials::initiate_oauth(&client, &provider).await {
                    Ok(url) => {
                        let _ = tx.send(AppMessage::OAuthUrlReady(url));
                    }
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(e));
                    }
                }
            });
        }
        ui.add_space(spacing::SM);
    }
}

fn render_wallet_tab(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    inputs::text_input(ui, &mut state.add_wallet_address, "Wallet address");
    ui.add_space(spacing::SM);
    inputs::hex_input(
        ui,
        &mut state.add_wallet_signature,
        "Paste signature (hex)",
    );
    ui.add_space(spacing::LG);

    let can = !state.add_wallet_address.is_empty() && !state.add_wallet_signature.is_empty();
    if buttons::action_button(ui, "Link Wallet", can) {
        let address = state.add_wallet_address.clone();
        let sig = state.add_wallet_signature.clone();
        let tx = state.tx.clone();
        let client = state.http_client.clone();
        rt.spawn(async move {
            let challenge_id = uuid::Uuid::new_v4();
            match crate::service::credentials::link_wallet(&client, &address, &sig, &challenge_id)
                .await
            {
                Ok(cred) => {
                    let _ = tx.send(AppMessage::CredentialLinked(cred));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }
}

fn render_mfa(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Multi-Factor Authentication", None);

    match &state.mfa_status.clone() {
        MfaState::Disabled => render_mfa_disabled(ui, state, rt),
        MfaState::SetupInProgress(setup) => render_mfa_setup(ui, state, setup.clone(), rt),
        MfaState::Enabled => render_mfa_enabled(ui, state, rt),
    }
}

fn render_mfa_disabled(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    let mut setup_clicked = false;
    layout::section(ui, "MFA Status", |ui| {
        ui.horizontal(|ui| {
            labels::field_label(ui, "Status:");
            labels::badge(ui, "Disabled", colors::TEXT_MUTED);
        });
        ui.add_space(spacing::XL);

        labels::field_label(
            ui,
            "Enable MFA to add an extra layer of security to your identity.",
        );
        ui.add_space(spacing::XL);

        if buttons::action_button(ui, "Setup MFA", true) {
            setup_clicked = true;
        }
    });

    if setup_clicked {
        let tx = state.tx.clone();
        let client = state.http_client.clone();
        rt.spawn(async move {
            match crate::service::mfa::setup(&client).await {
                Ok(setup) => {
                    let _ = tx.send(AppMessage::MfaSetupStarted(setup));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }
}

fn render_mfa_setup(
    ui: &mut Ui,
    state: &mut AppState,
    setup: MfaSetupInfo,
    rt: &tokio::runtime::Handle,
) {
    layout::section(ui, "Scan QR Code", |ui| {
        labels::field_label(
            ui,
            "Scan this QR code with your authenticator app, or enter the secret manually.",
        );
        ui.add_space(spacing::MD);

        layout::card_frame().show(ui, |ui| {
            labels::hint_label(ui, "QR URL:");
            ui.label(
                RichText::new(&setup.qr_url)
                    .font(egui::FontId::monospace(font_size::BODY))
                    .color(tokens::TEXT_PRIMARY),
            );
            ui.add_space(spacing::SM);
            labels::hint_label(ui, "Secret:");
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&setup.secret)
                        .font(egui::FontId::monospace(font_size::BODY))
                        .color(tokens::TEXT_PRIMARY),
                );
                buttons::copy_button(ui, "mfa_secret", &setup.secret);
            });
        });
    });

    layout::section(ui, "Backup Codes", |ui| {
        layout::warning_frame(
            ui,
            "Save these backup codes securely. They will NOT be shown again.",
        );
        ui.add_space(spacing::MD);
        domain::backup_code_grid(ui, &setup.backup_codes);
        ui.add_space(spacing::LG);
        domain::acknowledge_checkbox(
            ui,
            &mut state.mfa_backup_acknowledged,
            "I have saved my backup codes",
        );
    });

    layout::section(ui, "Verify", |ui| {
        let valid = domain::totp_input(ui, &mut state.mfa_setup_code);
        ui.add_space(spacing::LG);
        let can_enable = valid && state.mfa_backup_acknowledged;
        if buttons::action_button(ui, "Enable MFA", can_enable) {
            let code = state.mfa_setup_code.clone();
            let tx = state.tx.clone();
            let client = state.http_client.clone();
            rt.spawn(async move {
                match crate::service::mfa::enable(&client, &code).await {
                    Ok(()) => {
                        let _ = tx.send(AppMessage::MfaEnabled);
                    }
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(e));
                    }
                }
            });
        }
    });
}

fn render_mfa_enabled(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::section(ui, "MFA Status", |ui| {
        ui.horizontal(|ui| {
            labels::field_label(ui, "Status:");
            labels::badge(ui, "Enabled", tokens::SUCCESS);
        });
    });

    layout::section(ui, "Disable MFA", |ui| {
        labels::field_label(
            ui,
            "Enter your current TOTP code or a backup code to disable MFA.",
        );
        ui.add_space(spacing::MD);
        let valid = domain::totp_input(ui, &mut state.mfa_disable_code);
        ui.add_space(spacing::LG);
        if buttons::danger_button(ui, "Disable MFA", valid) {
            state.confirm_dialog = Some(ConfirmDialogState {
                title: "Disable MFA?".into(),
                message: "Your account will be less secure without MFA.".into(),
                confirm_label: "Disable".into(),
                danger: true,
                action: ConfirmAction::DisableMfa,
            });
        }
    });
}

fn render_sessions(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Sessions", None);

    layout::section(ui, "Current Session", |ui| {
        if let Some(session) = &state.current_session {
            let sess = session.clone();
            if domain::session_card(ui, &sess) {
                state.confirm_dialog = Some(ConfirmDialogState {
                    title: "Logout?".into(),
                    message: "This will revoke your current session.".into(),
                    confirm_label: "Logout".into(),
                    danger: false,
                    action: ConfirmAction::Logout,
                });
            }
        } else {
            labels::muted_label(ui, "No active session");
        }
    });
}

fn render_namespaces(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Namespaces", None);

    layout::section(ui, "Memberships", |ui| {
        if state.namespaces.is_empty() {
            labels::muted_label(ui, "No namespace memberships");
            ui.add_space(spacing::MD);
            labels::hint_label(ui, "Namespace management is available in the V1 release.");
        } else {
            for ns in &state.namespaces.clone() {
                layout::card_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(&ns.name)
                                .color(tokens::TEXT_PRIMARY)
                                .size(font_size::BODY)
                                .strong(),
                        );
                        labels::badge(ui, &ns.role, colors::ACCENT);
                    });
                    data_display::info_grid(ui, &format!("ns_{}", ns.namespace_id), |ui| {
                        data_display::kv_row(ui, "ID", &ns.namespace_id.to_string()[..8]);
                        data_display::kv_row(ui, "Joined", &ns.joined_at);
                    });
                });
                ui.add_space(spacing::SM);
            }
        }
    });
}

fn render_security(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Security", None);

    if let Some(frozen) = &state.frozen_state.clone() {
        layout::frozen_banner(ui, &frozen.reason);
        ui.add_space(spacing::XL);

        layout::section(ui, "Unfreeze Identity", |ui| {
            labels::field_label(
                ui,
                "Unfreezing requires signatures from 2+ enrolled machines.",
            );
            ui.add_space(spacing::MD);
            labels::hint_label(ui, "This feature requires the Advanced release.");
        });
    } else {
        layout::section(ui, "Identity Protection", |ui| {
            layout::card_frame().show(ui, |ui| {
                ui.label(
                    RichText::new("FREEZE IDENTITY")
                        .color(tokens::TEXT_PRIMARY)
                        .size(font_size::BODY)
                        .strong(),
                );
                ui.add_space(spacing::SM);
                labels::field_label(
                    ui,
                    "Freezing blocks all authentication immediately. Active sessions will expire naturally but cannot be refreshed. Unfreezing requires multi-machine approval.",
                );
                ui.add_space(spacing::MD);

                ui.horizontal(|ui| {
                    labels::field_label(ui, "Reason:");
                    let reasons = [
                        (FreezeReason::SecurityIncident, "Security Incident"),
                        (FreezeReason::SuspiciousActivity, "Suspicious Activity"),
                        (FreezeReason::UserRequested, "User Requested"),
                    ];
                    for (reason, label) in &reasons {
                        let selected = state.freeze_reason.as_str() == reason.as_str();
                        if ui
                            .selectable_label(
                                selected,
                                RichText::new(*label)
                                    .color(if selected {
                                        egui::Color32::WHITE
                                    } else {
                                        colors::TEXT_SECONDARY
                                    })
                                    .size(font_size::BODY),
                            )
                            .clicked()
                        {
                            state.freeze_reason = reason.clone();
                        }
                    }
                });

                ui.add_space(spacing::MD);
                if buttons::danger_button(ui, "Freeze Identity", true) {
                    state.confirm_dialog = Some(ConfirmDialogState {
                        title: "Freeze Identity?".into(),
                        message: "Freezing will immediately block all authentication. Are you sure?"
                            .into(),
                        confirm_label: "Freeze Now".into(),
                        danger: true,
                        action: ConfirmAction::FreezeIdentity,
                    });
                }
            });
        });

        layout::section(ui, "Advanced Ceremonies", |ui| {
            labels::muted_label(
                ui,
                "Key rotation and multi-machine ceremonies are available in the Advanced release.",
            );
        });
    }
}

fn render_settings(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::page_header(ui, "Settings", None);

    render_profiles_section(ui, state);

    layout::section(ui, "Server", |ui| {
        ui.horizontal(|ui| {
            labels::field_label(ui, "Server URL:");
            inputs::text_input(
                ui,
                &mut state.settings.server_url,
                "http://127.0.0.1:9999",
            );
        });
        ui.add_space(spacing::SM);
        labels::hint_label(ui, "Changes take effect on next login");
    });

    layout::section(ui, "Storage", |ui| {
        data_display::info_grid(ui, "storage_info", |ui| {
            data_display::kv_row(ui, "Active Profile", state.storage.active_profile_name());
            let cred_path = state.storage.credentials_path();
            data_display::kv_row(ui, "Credentials", &cred_path.display().to_string());
            let sess_path = state.storage.session_path();
            data_display::kv_row(ui, "Session", &sess_path.display().to_string());
        });
    });

    layout::section(ui, "About", |ui| {
        data_display::info_grid(ui, "about_info", |ui| {
            data_display::kv_row(ui, "Version", env!("CARGO_PKG_VERSION"));
            data_display::kv_row(ui, "Platform", std::env::consts::OS);
        });
    });
}

fn render_profiles_section(ui: &mut Ui, state: &mut AppState) {
    layout::section(ui, "Profiles", |ui| {
        let profiles = state.profiles.clone();
        for profile in &profiles {
            ui.horizontal(|ui| {
                let label = if profile.is_active {
                    format!("{} (active)", profile.name)
                } else {
                    profile.name.clone()
                };

                let label_color = if profile.is_active {
                    colors::ACCENT
                } else {
                    tokens::TEXT_PRIMARY
                };
                ui.label(
                    RichText::new(&label)
                        .color(label_color)
                        .size(font_size::BODY),
                );

                if profile.has_credentials {
                    labels::hint_label(ui, "has identity");
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !profile.is_active {
                        if profile.name != "default" {
                            if buttons::danger_button(ui, "Delete", true) {
                                state.confirm_dialog = Some(ConfirmDialogState {
                                    title: "Delete Profile".into(),
                                    message: format!(
                                        "Delete profile '{}'? All credentials and session data in this profile will be permanently removed.",
                                        profile.name
                                    ),
                                    confirm_label: "Delete".into(),
                                    danger: true,
                                    action: ConfirmAction::DeleteProfile(profile.name.clone()),
                                });
                            }
                        }

                        if buttons::action_button(ui, "Switch", true) {
                            let _ = state
                                .tx
                                .send(AppMessage::ProfileSwitched(profile.name.clone()));
                        }
                    }
                });
            });
            ui.add_space(spacing::XS);
        }

        ui.add_space(spacing::MD);
        ui.horizontal(|ui| {
            let input_width = (ui.available_width() - 80.0).max(120.0);
            let te = egui::TextEdit::singleline(&mut state.new_profile_name)
                .hint_text(
                    egui::RichText::new("new-profile-name")
                        .color(colors::TEXT_MUTED)
                        .size(font_size::BODY),
                )
                .desired_width(input_width)
                .font(egui::FontId::proportional(font_size::BODY));
            ui.add(te);
            let can_create = !state.new_profile_name.trim().is_empty();
            if buttons::action_button(ui, "Create", can_create) {
                let name = state.new_profile_name.trim().to_string();
                match state.storage.create_profile(&name) {
                    Ok(()) => {
                        let _ = state.tx.send(AppMessage::ProfileCreated(name));
                    }
                    Err(e) => {
                        let _ = state.tx.send(AppMessage::Error(e));
                    }
                }
            }
        });
        ui.add_space(spacing::SM);
        labels::hint_label(ui, "Alphanumeric, hyphens, underscores. Max 32 chars.");
    });
}
