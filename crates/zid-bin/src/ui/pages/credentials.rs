use egui::{RichText, Ui};

use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::{AppState, ConfirmAction, ConfirmDialogState};
use crate::ui::components::{core, domain};
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    let add_clicked = layout::render_page_header(ui, "Linked Identities", Some(("Add Credential", true)));
    if add_clicked {
        state.show_add_credential_dialog = true;
    }

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

    match &state.credentials_status {
        LoadStatus::Loading => core::spinner(ui, "Loading credentials..."),
        LoadStatus::Loaded => {
            if state.credentials.is_empty() {
                ui.label(RichText::new("No linked credentials").color(theme::TEXT_MUTED));
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
                                    action: ConfirmAction::RevokeCredential(method_type, method_id),
                                });
                            }
                            domain::CredentialCardAction::SetPrimary(method_type, method_id) => {
                                let tx = state.tx.clone();
                                let client = state.http_client.clone();
                                let mt = method_type.clone();
                                let mi = method_id.clone();
                                rt.spawn(async move {
                                    match crate::service::credentials::set_primary(&client, &mt, &mi).await {
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
                    ui.add_space(4.0);
                }
            }
        }
        LoadStatus::Error(e) => {
            ui.label(RichText::new(e).color(theme::DANGER));
        }
        _ => {}
    }

    if state.show_add_credential_dialog {
        render_add_dialog(ui, state, rt);
    }
}

fn render_add_dialog(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
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
                    let color = if selected { theme::BRAND_PRIMARY } else { theme::TEXT_MUTED };
                    if ui
                        .selectable_label(selected, RichText::new(*label).color(color))
                        .clicked()
                    {
                        state.add_cred_tab = i;
                    }
                }
            });
            ui.separator();
            ui.add_space(8.0);

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
    core::text_input(ui, &mut state.add_email_address, "Email address");
    ui.add_space(4.0);
    core::password_input(ui, &mut state.add_email_password, "Password");
    core::strength_bar(ui, &state.add_email_password);
    ui.add_space(12.0);

    let can = !state.add_email_address.is_empty() && !state.add_email_password.is_empty();
    if core::primary_button(ui, "Link Email", can) {
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
    ui.label(RichText::new("Select a provider:").color(theme::TEXT_SECONDARY));
    ui.add_space(8.0);
    for provider in &["google", "x", "epic"] {
        if core::secondary_button(ui, &format!("Link {}", provider.to_uppercase())) {
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
        ui.add_space(4.0);
    }
}

fn render_wallet_tab(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    core::text_input(ui, &mut state.add_wallet_address, "Wallet address");
    ui.add_space(4.0);
    core::hex_input(ui, &mut state.add_wallet_signature, "Paste signature (hex)");
    ui.add_space(12.0);

    let can = !state.add_wallet_address.is_empty() && !state.add_wallet_signature.is_empty();
    if core::primary_button(ui, "Link Wallet", can) {
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
