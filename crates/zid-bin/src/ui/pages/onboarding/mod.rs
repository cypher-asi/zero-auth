mod create_identity;
mod login;
mod recover_identity;

use egui::{RichText, Ui};

use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::AppState;
use crate::ui::components::core;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    match &state.current_page {
        Page::Onboarding(step) => match step {
            OnboardingStep::Welcome => render_welcome(ui, state),
            OnboardingStep::CreateIdentity(step) => {
                create_identity::render(ui, state, step.clone(), rt);
            }
            OnboardingStep::RecoverIdentity(step) => {
                recover_identity::render(ui, state, step.clone(), rt);
            }
            OnboardingStep::Login(step) => {
                login::render(ui, state, step.clone(), rt);
            }
        },
        _ => {}
    }
}

fn render_welcome(ui: &mut Ui, state: &mut AppState) {
    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        ui.label(RichText::new("Zero-ID").font(egui::FontId::proportional(48.0)).color(theme::BRAND_PRIMARY));
        ui.add_space(8.0);
        ui.label(
            RichText::new("Self-sovereign identity, post-quantum ready")
                .font(theme::subheading_font())
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(48.0);

        render_welcome_profile_selector(ui, state);
        ui.add_space(24.0);

        if core::primary_button(ui, "Create New Identity", true) {
            state.navigate(Page::Onboarding(OnboardingStep::CreateIdentity(
                CreateStep::Passphrase,
            )));
        }
        ui.add_space(12.0);
        if core::secondary_button(ui, "Recover Existing Identity") {
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
        let total_width = 220.0;
        let available = ui.available_width();
        if available > total_width {
            ui.add_space((available - total_width) / 2.0);
        }

        ui.label(
            RichText::new("Profile")
                .color(theme::TEXT_MUTED)
                .font(theme::small_font()),
        );

        let combo = egui::ComboBox::from_id_salt("welcome_profile_selector")
            .selected_text(
                RichText::new(&selected)
                    .color(theme::TEXT_SECONDARY)
                    .font(theme::small_font()),
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
        ui.add_space(4.0);
        ui.label(
            RichText::new("● = has identity")
                .color(theme::TEXT_MUTED)
                .font(theme::small_font()),
        );
    }
}
