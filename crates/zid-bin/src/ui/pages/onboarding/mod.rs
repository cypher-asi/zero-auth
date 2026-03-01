mod create_identity;
mod login;
mod recover_identity;

use egui::{RichText, Ui};

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
