use egui::{RichText, Ui};

use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::{AppState, ConfirmAction, ConfirmDialogState};
use crate::ui::components::{core, domain};
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    layout::render_page_header(ui, "Multi-Factor Authentication", None);

    match &state.mfa_status.clone() {
        MfaState::Disabled => render_disabled(ui, state, rt),
        MfaState::SetupInProgress(setup) => render_setup(ui, state, setup.clone(), rt),
        MfaState::Enabled => render_enabled(ui, state, rt),
    }
}

fn render_disabled(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("MFA Status:").color(theme::TEXT_SECONDARY));
        core::badge(ui, "Disabled", theme::TEXT_MUTED);
    });
    ui.add_space(16.0);

    ui.label(
        RichText::new("Enable MFA to add an extra layer of security to your identity.")
            .color(theme::TEXT_SECONDARY),
    );
    ui.add_space(16.0);

    if core::primary_button(ui, "Setup MFA", true) {
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

fn render_setup(ui: &mut Ui, state: &mut AppState, setup: MfaSetupInfo, rt: &tokio::runtime::Handle) {
    core::section_label(ui, "Scan QR Code");
    ui.label(
        RichText::new("Scan this QR code with your authenticator app, or enter the secret manually.")
            .color(theme::TEXT_SECONDARY),
    );
    ui.add_space(8.0);

    core::card_frame().show(ui, |ui| {
        ui.label(RichText::new("QR URL:").color(theme::TEXT_MUTED).font(theme::small_font()));
        ui.label(RichText::new(&setup.qr_url).font(theme::mono_font()).color(theme::TEXT_PRIMARY));
        ui.add_space(4.0);
        ui.label(RichText::new("Secret:").color(theme::TEXT_MUTED).font(theme::small_font()));
        ui.label(RichText::new(&setup.secret).font(theme::mono_font()).color(theme::TEXT_PRIMARY));
        if core::secondary_button(ui, "Copy Secret") {
            let _ = crate::infra::os_integration::copy_to_clipboard(&setup.secret);
        }
    });

    ui.add_space(16.0);
    core::section_label(ui, "Backup Codes");

    let frame = egui::Frame::none()
        .fill(theme::WARNING.linear_multiply(0.1))
        .inner_margin(egui::Margin::same(12.0))
        .rounding(egui::Rounding::same(8.0))
        .stroke(egui::Stroke::new(1.0, theme::WARNING));
    frame.show(ui, |ui| {
        ui.label(
            RichText::new("Save these backup codes securely. They will NOT be shown again.")
                .color(theme::WARNING),
        );
    });

    ui.add_space(8.0);
    domain::backup_code_grid(ui, &setup.backup_codes);

    ui.add_space(12.0);
    core::acknowledge_checkbox(
        ui,
        &mut state.mfa_backup_acknowledged,
        "I have saved my backup codes",
    );

    ui.add_space(16.0);
    core::section_label(ui, "Verify");
    let valid = domain::totp_input(ui, &mut state.mfa_setup_code);

    ui.add_space(12.0);
    let can_enable = valid && state.mfa_backup_acknowledged;
    if core::primary_button(ui, "Enable MFA", can_enable) {
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
}

fn render_enabled(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("MFA Status:").color(theme::TEXT_SECONDARY));
        core::badge(ui, "Enabled", theme::SUCCESS);
    });
    ui.add_space(24.0);

    core::section_label(ui, "Disable MFA");
    ui.label(
        RichText::new("Enter your current TOTP code or a backup code to disable MFA.")
            .color(theme::TEXT_SECONDARY),
    );
    ui.add_space(8.0);

    let valid = domain::totp_input(ui, &mut state.mfa_disable_code);
    ui.add_space(12.0);

    if core::danger_button(ui, "Disable MFA", valid) {
        state.confirm_dialog = Some(ConfirmDialogState {
            title: "Disable MFA?".into(),
            message: "Your account will be less secure without MFA.".into(),
            confirm_label: "Disable".into(),
            danger: true,
            action: ConfirmAction::DisableMfa,
        });
    }
}
