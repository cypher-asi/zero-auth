use egui::{RichText, Ui};
use uuid::Uuid;

use crate::state::types::*;
use crate::ui::components::core;
use crate::ui::theme;

pub fn identity_badge(ui: &mut Ui, identity: &IdentityViewModel) {
    core::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            let did_display = if identity.did.is_empty() {
                identity.identity_id.to_string()
            } else {
                identity.did.clone()
            };
            ui.label(RichText::new(&did_display).font(theme::mono_font()).color(theme::TEXT_PRIMARY));

            let tier_color = if identity.tier == "SelfSovereign" {
                theme::BRAND_PRIMARY
            } else {
                theme::TEXT_SECONDARY
            };
            core::badge(ui, &identity.tier, tier_color);

            let status_color = match identity.status.as_str() {
                "Active" => theme::SUCCESS,
                "Frozen" => theme::DANGER,
                "Disabled" => theme::WARNING,
                _ => theme::TEXT_MUTED,
            };
            core::badge(ui, &identity.status, status_color);
        });
    });
}

pub fn machine_card(ui: &mut Ui, machine: &MachineViewModel, current_machine_id: Option<Uuid>) -> Option<MachineCardAction> {
    let mut action = None;

    core::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&machine.device_name).color(theme::TEXT_PRIMARY).strong());
                    if Some(machine.machine_id) == current_machine_id {
                        core::badge(ui, "Current", theme::SUCCESS);
                    }
                    if machine.revoked {
                        core::badge(ui, "Revoked", theme::DANGER);
                    }
                });
                ui.horizontal(|ui| {
                    core::badge(ui, &machine.key_scheme, theme::INFO);
                    ui.label(RichText::new(&machine.device_platform).color(theme::TEXT_MUTED).font(theme::small_font()));
                });
                core::data_field(ui, "ID", &machine.machine_id.to_string()[..8]);
                core::data_field(ui, "Created", &machine.created_at);
                if let Some(last) = &machine.last_used_at {
                    core::data_field(ui, "Last used", last);
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !machine.revoked && core::danger_button(ui, "Revoke", true) {
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

    core::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let type_color = match cred.method_type.as_str() {
                        "email" => theme::INFO,
                        "oauth" => theme::WARNING,
                        "wallet" => theme::BRAND_PRIMARY,
                        _ => theme::TEXT_MUTED,
                    };
                    core::badge(ui, &cred.method_type, type_color);
                    if cred.primary {
                        core::badge(ui, "Primary", theme::SUCCESS);
                    }
                    if cred.verified {
                        core::badge(ui, "Verified", theme::SUCCESS);
                    }
                });
                core::data_field(ui, "ID", &cred.method_id);
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if core::danger_button(ui, "Revoke", !cred.primary) {
                    action = Some(CredentialCardAction::Revoke(
                        cred.method_type.clone(),
                        cred.method_id.clone(),
                    ));
                }
                if !cred.primary && core::secondary_button(ui, "Set Primary") {
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
    core::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            let label = match index {
                0 => "Shard A",
                1 => "Shard B",
                2 => "Shard C",
                _ => "Shard",
            };
            ui.label(RichText::new(label).color(theme::BRAND_PRIMARY).strong());

            let short = if hex_value.len() > 24 {
                format!("{}...{}", &hex_value[..12], &hex_value[hex_value.len()-12..])
            } else {
                hex_value.to_string()
            };
            ui.label(RichText::new(&short).font(theme::mono_font()).color(theme::TEXT_PRIMARY));

            if core::secondary_button(ui, "Copy") {
                let _ = crate::infra::os_integration::copy_to_clipboard(hex_value);
            }
        });
    });
}

pub fn session_card(ui: &mut Ui, session: &SessionViewModel) -> bool {
    let mut revoked = false;
    core::card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    core::data_field(ui, "Session", &session.session_id.to_string()[..8]);
                    if session.is_current {
                        core::badge(ui, "Current", theme::SUCCESS);
                    }
                });
                core::data_field(ui, "Expires", &session.expires_at);
                if let Some(mid) = &session.machine_id {
                    core::data_field(ui, "Machine", &mid.to_string()[..8]);
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if core::danger_button(ui, "Revoke", true) {
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
    core::password_input(ui, passphrase, "Enter passphrase");

    if show_strength {
        core::strength_bar(ui, passphrase);
    }

    let mut valid = passphrase.len() >= 8;

    if let Some(conf) = confirm {
        ui.add_space(4.0);
        core::password_input(ui, conf, "Confirm passphrase");
        if !conf.is_empty() && passphrase != conf {
            ui.label(RichText::new("Passphrases do not match").color(theme::DANGER).font(theme::small_font()));
            valid = false;
        }
    }

    valid
}

pub fn totp_input(ui: &mut Ui, code: &mut String) -> bool {
    ui.horizontal(|ui| {
        ui.label(RichText::new("TOTP Code:").color(theme::TEXT_SECONDARY));
        let te = egui::TextEdit::singleline(code)
            .desired_width(120.0)
            .hint_text("000000")
            .font(theme::mono_font());
        ui.add(te);
    });
    code.len() == 6 && code.chars().all(|c| c.is_ascii_digit())
}

pub fn backup_code_grid(ui: &mut Ui, codes: &[String]) {
    egui::Grid::new("backup_codes")
        .num_columns(2)
        .spacing([24.0, 4.0])
        .show(ui, |ui| {
            for (i, code) in codes.iter().enumerate() {
                ui.label(
                    RichText::new(format!("{}. {}", i + 1, code))
                        .font(theme::mono_font())
                        .color(theme::TEXT_PRIMARY),
                );
                if i % 2 == 1 {
                    ui.end_row();
                }
            }
        });
}
