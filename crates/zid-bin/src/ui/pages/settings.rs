use egui::{RichText, Ui};

use crate::state::actions::AppMessage;
use crate::state::{AppState, ConfirmAction, ConfirmDialogState};
use crate::ui::components::core;
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::render_page_header(ui, "Settings", None);

    render_profiles_section(ui, state);

    ui.add_space(24.0);
    core::section_label(ui, "Server");
    ui.horizontal(|ui| {
        ui.label(RichText::new("Server URL:").color(theme::TEXT_SECONDARY));
        core::text_input(ui, &mut state.settings.server_url, "http://127.0.0.1:9999");
    });
    ui.add_space(4.0);
    ui.label(
        RichText::new("Changes take effect on next login")
            .color(theme::TEXT_MUTED)
            .font(theme::small_font()),
    );

    ui.add_space(24.0);
    core::section_label(ui, "Storage");
    core::data_field(ui, "Active Profile", state.storage.active_profile_name());
    let cred_path = state.storage.credentials_path();
    core::data_field(ui, "Credentials", &cred_path.display().to_string());
    let sess_path = state.storage.session_path();
    core::data_field(ui, "Session", &sess_path.display().to_string());

    ui.add_space(24.0);
    core::section_label(ui, "About");
    core::data_field(ui, "Version", env!("CARGO_PKG_VERSION"));
    core::data_field(ui, "Platform", std::env::consts::OS);
}

fn render_profiles_section(ui: &mut Ui, state: &mut AppState) {
    core::section_label(ui, "Profiles");

    let profiles = state.profiles.clone();
    for profile in &profiles {
        ui.horizontal(|ui| {
            let label = if profile.is_active {
                format!("{} (active)", profile.name)
            } else {
                profile.name.clone()
            };

            let label_color = if profile.is_active {
                theme::BRAND_PRIMARY
            } else {
                theme::TEXT_PRIMARY
            };
            ui.label(RichText::new(&label).color(label_color));

            if profile.has_credentials {
                ui.label(
                    RichText::new("has identity")
                        .color(theme::TEXT_MUTED)
                        .font(theme::small_font()),
                );
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !profile.is_active {
                    if profile.name != "default" {
                        let del_btn = egui::Button::new(
                            RichText::new("Delete").color(theme::DANGER),
                        )
                        .fill(egui::Color32::TRANSPARENT)
                        .stroke(egui::Stroke::new(1.0, theme::DANGER));
                        if ui.add(del_btn).clicked() {
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

                    let switch_btn = egui::Button::new(
                        RichText::new("Switch").color(egui::Color32::WHITE),
                    )
                    .fill(theme::BRAND_PRIMARY)
                    .rounding(egui::Rounding::same(4.0));
                    if ui.add(switch_btn).clicked() {
                        let _ = state
                            .tx
                            .send(AppMessage::ProfileSwitched(profile.name.clone()));
                    }
                }
            });
        });
        ui.add_space(2.0);
    }

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        core::text_input(ui, &mut state.new_profile_name, "new-profile-name");
        let can_create = !state.new_profile_name.trim().is_empty();
        let create_btn = egui::Button::new(
            RichText::new("Create").color(egui::Color32::WHITE),
        )
        .fill(if can_create {
            theme::BRAND_PRIMARY
        } else {
            theme::TEXT_MUTED
        })
        .rounding(egui::Rounding::same(4.0));
        if ui.add_enabled(can_create, create_btn).clicked() {
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
    ui.add_space(4.0);
    ui.label(
        RichText::new("Alphanumeric, hyphens, underscores. Max 32 chars.")
            .color(theme::TEXT_MUTED)
            .font(theme::small_font()),
    );
}
