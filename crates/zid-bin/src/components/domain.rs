use egui::{RichText, Ui};
use uuid::Uuid;

use crate::state::types::*;
use super::tokens::{self, colors, font_size, spacing};
use super::{buttons, labels, layout, data_display, feedback, inputs};

pub fn identity_badge(ui: &mut Ui, identity: &IdentityViewModel) {
    layout::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            let did_display = if identity.did.is_empty() {
                identity.identity_id.to_string()
            } else {
                identity.did.clone()
            };
            ui.label(
                RichText::new(&did_display)
                    .font(egui::FontId::monospace(font_size::BODY))
                    .color(tokens::TEXT_PRIMARY),
            );

            let tier_color = if identity.tier == "SelfSovereign" {
                colors::ACCENT
            } else {
                colors::TEXT_SECONDARY
            };
            labels::badge(ui, &identity.tier, tier_color);

            let status_color = match identity.status.as_str() {
                "Active" => tokens::SUCCESS,
                "Frozen" => tokens::DANGER,
                "Disabled" => tokens::WARNING,
                _ => colors::TEXT_MUTED,
            };
            labels::badge(ui, &identity.status, status_color);
        });
    });
}

pub fn machine_card(
    ui: &mut Ui,
    machine: &MachineViewModel,
    current_machine_id: Option<Uuid>,
) -> Option<MachineCardAction> {
    let mut action = None;

    layout::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&machine.device_name)
                            .color(tokens::TEXT_PRIMARY)
                            .size(font_size::BODY)
                            .strong(),
                    );
                    if Some(machine.machine_id) == current_machine_id {
                        labels::badge(ui, "Current", tokens::SUCCESS);
                    }
                    if machine.revoked {
                        labels::badge(ui, "Revoked", tokens::DANGER);
                    }
                });
                ui.horizontal(|ui| {
                    labels::badge(ui, &machine.key_scheme, tokens::INFO);
                    ui.label(
                        RichText::new(&machine.device_platform)
                            .color(colors::TEXT_MUTED)
                            .size(font_size::SMALL),
                    );
                });
                data_display::info_grid(ui, &format!("machine_{}", machine.machine_id), |ui| {
                    data_display::kv_row(ui, "ID", &machine.machine_id.to_string()[..8]);
                    data_display::kv_row(ui, "Created", &machine.created_at);
                    if let Some(last) = &machine.last_used_at {
                        data_display::kv_row(ui, "Last used", last);
                    }
                });
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !machine.revoked && buttons::danger_button(ui, "Revoke", true) {
                    action = Some(MachineCardAction::Revoke(machine.machine_id));
                }
            });
        });
    });

    action
}

pub enum MachineCardAction {
    Revoke(Uuid),
}

pub fn credential_card(ui: &mut Ui, cred: &CredentialViewModel) -> Option<CredentialCardAction> {
    let mut action = None;

    layout::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let type_color = match cred.method_type.as_str() {
                        "email" => tokens::INFO,
                        "oauth" => tokens::WARNING,
                        "wallet" => colors::ACCENT,
                        _ => colors::TEXT_MUTED,
                    };
                    labels::badge(ui, &cred.method_type, type_color);
                    if cred.primary {
                        labels::badge(ui, "Primary", tokens::SUCCESS);
                    }
                    if cred.verified {
                        labels::badge(ui, "Verified", tokens::SUCCESS);
                    }
                });
                data_display::info_grid(ui, &format!("cred_{}", cred.method_id), |ui| {
                    data_display::kv_row(ui, "ID", &cred.method_id);
                });
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if buttons::danger_button(ui, "Revoke", !cred.primary) {
                    action = Some(CredentialCardAction::Revoke(
                        cred.method_type.clone(),
                        cred.method_id.clone(),
                    ));
                }
                if !cred.primary && buttons::std_button(ui, "Set Primary") {
                    action = Some(CredentialCardAction::SetPrimary(
                        cred.method_type.clone(),
                        cred.method_id.clone(),
                    ));
                }
            });
        });
    });

    action
}

pub enum CredentialCardAction {
    Revoke(String, String),
    SetPrimary(String, String),
}

pub fn shard_card(ui: &mut Ui, index: usize, hex_value: &str) {
    layout::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            let label = match index {
                0 => "Shard A",
                1 => "Shard B",
                2 => "Shard C",
                _ => "Shard",
            };
            ui.label(
                RichText::new(label)
                    .color(colors::ACCENT)
                    .size(font_size::BODY)
                    .strong(),
            );

            let short = if hex_value.len() > 24 {
                format!(
                    "{}...{}",
                    &hex_value[..12],
                    &hex_value[hex_value.len() - 12..]
                )
            } else {
                hex_value.to_string()
            };
            ui.label(
                RichText::new(&short)
                    .font(egui::FontId::monospace(font_size::BODY))
                    .color(tokens::TEXT_PRIMARY),
            );

            buttons::copy_button(ui, &format!("shard_{}", index), hex_value);
        });
    });
}

pub fn copy_all_shards_button(ui: &mut Ui, shards: &[String]) {
    if shards.is_empty() {
        return;
    }

    if buttons::std_button(ui, "Copy All Shards") {
        let combined = shards
            .iter()
            .enumerate()
            .map(|(i, hex)| {
                let label = match i {
                    0 => "Shard A",
                    1 => "Shard B",
                    2 => "Shard C",
                    _ => "Shard",
                };
                format!("{label}: {hex}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let _ = crate::infra::os_integration::copy_to_clipboard(&combined);
    }
}

pub fn session_card(ui: &mut Ui, session: &SessionViewModel) -> bool {
    let mut revoked = false;
    layout::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&format!("Session {}", &session.session_id.to_string()[..8]))
                            .color(tokens::TEXT_PRIMARY)
                            .size(font_size::BODY),
                    );
                    if session.is_current {
                        labels::badge(ui, "Current", tokens::SUCCESS);
                    }
                });
                data_display::info_grid(ui, &format!("sess_{}", session.session_id), |ui| {
                    data_display::kv_row(ui, "Expires", &session.expires_at);
                    if let Some(mid) = &session.machine_id {
                        data_display::kv_row(ui, "Machine", &mid.to_string()[..8]);
                    }
                });
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if buttons::danger_button(ui, "Revoke", true) {
                    revoked = true;
                }
            });
        });
    });
    revoked
}

pub fn passphrase_input(
    ui: &mut Ui,
    passphrase: &mut String,
    confirm: Option<&mut String>,
    show_strength: bool,
) -> bool {
    inputs::text_input_password(ui, passphrase, "Enter passphrase");

    if show_strength {
        feedback::strength_bar(ui, passphrase);
    }

    let mut valid = passphrase.len() >= 8;

    if let Some(conf) = confirm {
        ui.add_space(spacing::SM);
        inputs::text_input_password(ui, conf, "Confirm passphrase");
        if !conf.is_empty() && passphrase != conf {
            labels::error_label(ui, "Passphrases do not match");
            valid = false;
        }
    }

    valid
}

pub fn totp_input(ui: &mut Ui, code: &mut String) -> bool {
    ui.horizontal(|ui| {
        labels::field_label(ui, "TOTP Code:");
        let te = egui::TextEdit::singleline(code)
            .desired_width(120.0)
            .hint_text("000000")
            .font(egui::FontId::monospace(font_size::BODY));
        ui.add(te);
    });
    code.len() == 6 && code.chars().all(|c| c.is_ascii_digit())
}

pub fn backup_code_grid(ui: &mut Ui, codes: &[String]) {
    egui::Grid::new("backup_codes")
        .num_columns(2)
        .spacing([spacing::XXL, spacing::SM])
        .show(ui, |ui| {
            for (i, code) in codes.iter().enumerate() {
                ui.label(
                    RichText::new(format!("{}. {}", i + 1, code))
                        .font(egui::FontId::monospace(font_size::BODY))
                        .color(tokens::TEXT_PRIMARY),
                );
                if i % 2 == 1 {
                    ui.end_row();
                }
            }
        });
}

pub fn acknowledge_checkbox(ui: &mut Ui, checked: &mut bool, label: &str) -> bool {
    ui.checkbox(
        checked,
        RichText::new(label)
            .color(tokens::TEXT_PRIMARY)
            .size(font_size::BODY),
    );
    *checked
}
