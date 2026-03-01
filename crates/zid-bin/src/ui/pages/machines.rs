use egui::{RichText, Ui};


use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::{AppState, ConfirmAction, ConfirmDialogState};
use crate::ui::components::{core, domain};
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    let enroll_clicked = layout::render_page_header(ui, "Machines", Some(("Enroll New Machine", true)));
    if enroll_clicked {
        state.show_enroll_dialog = true;
    }

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

    match &state.machines_status {
        LoadStatus::Loading => {
            core::spinner(ui, "Loading machines...");
        }
        LoadStatus::Loaded => {
            if state.machines.is_empty() {
                ui.label(RichText::new("No machines enrolled").color(theme::TEXT_MUTED));
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
                                    title: format!("Revoke Machine?"),
                                    message: msg.to_string(),
                                    confirm_label: "Revoke".into(),
                                    danger: true,
                                    action: ConfirmAction::RevokeMachine(id),
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
            ui.label(
                RichText::new("Reconstruct your Neural Key to derive a new machine keypair.")
                    .color(theme::TEXT_SECONDARY),
            );
            ui.add_space(8.0);
            core::password_input(ui, &mut state.enroll_passphrase, "Passphrase");
            ui.add_space(8.0);
            ui.label(
                RichText::new("Enter one of your recovery shards (hex)")
                    .color(theme::TEXT_SECONDARY)
                    .font(theme::small_font()),
            );
            core::hex_input(ui, &mut state.enroll_user_shard_hex, "Recovery shard hex");
            ui.add_space(16.0);

            ui.horizontal(|ui| {
                if core::secondary_button(ui, "Cancel") {
                    state.show_enroll_dialog = false;
                    state.enroll_passphrase.clear();
                    state.enroll_user_shard_hex.clear();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can = !state.enroll_passphrase.is_empty()
                        && !state.enroll_user_shard_hex.is_empty();
                    if core::primary_button(ui, "Enroll", can) {
                        start_enrollment(state, rt);
                    }
                });
            });
        });

    if !open {
        state.show_enroll_dialog = false;
        state.enroll_passphrase.clear();
        state.enroll_user_shard_hex.clear();
    }
}

fn start_enrollment(state: &mut AppState, rt: &tokio::runtime::Handle) {
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
        let result = run_enrollment(&passphrase, &user_shard_hex, &creds, &client).await;
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

    let device_name = "Desktop App";
    let device_platform = std::env::consts::OS;

    let (response, _keypair) = crate::service::machine::enroll(
        client,
        &neural_key,
        &creds.identity_id,
        device_name,
        device_platform,
    )
    .await?;

    Ok(MachineViewModel {
        machine_id: response.machine_id,
        device_name: device_name.into(),
        device_platform: device_platform.into(),
        created_at: response.enrolled_at,
        last_used_at: None,
        revoked: false,
        key_scheme: "PQ-Hybrid".into(),
        capabilities: vec!["AUTHENTICATE".into(), "SIGN".into(), "ENCRYPT".into()],
        epoch: 0,
    })
}
