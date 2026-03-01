use egui::{RichText, Ui};

use crate::state::types::*;
use crate::state::{AppState, ConfirmAction, ConfirmDialogState};
use crate::ui::components::core;
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::render_page_header(ui, "Security", None);

    if let Some(frozen) = &state.frozen_state.clone() {
        layout::render_frozen_banner(ui, frozen);
        ui.add_space(16.0);

        core::section_label(ui, "Unfreeze Identity");
        ui.label(
            RichText::new("Unfreezing requires signatures from 2+ enrolled machines.")
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("This feature requires the Advanced release.")
                .color(theme::TEXT_MUTED)
                .font(theme::small_font()),
        );
    } else {
        core::section_label(ui, "Identity Protection");

        core::card_frame().show(ui, |ui| {
            ui.label(RichText::new("Freeze Identity").color(theme::TEXT_PRIMARY).strong());
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Freezing blocks all authentication immediately. \
                     Active sessions will expire naturally but cannot be refreshed. \
                     Unfreezing requires multi-machine approval.",
                )
                .color(theme::TEXT_SECONDARY),
            );
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Reason:").color(theme::TEXT_MUTED));
                let reasons = [
                    (FreezeReason::SecurityIncident, "Security Incident"),
                    (FreezeReason::SuspiciousActivity, "Suspicious Activity"),
                    (FreezeReason::UserRequested, "User Requested"),
                ];
                for (reason, label) in &reasons {
                    let selected = state.freeze_reason.as_str() == reason.as_str();
                    if ui.selectable_label(selected, *label).clicked() {
                        state.freeze_reason = reason.clone();
                    }
                }
            });

            ui.add_space(8.0);
            if core::danger_button(ui, "Freeze Identity", true) {
                state.confirm_dialog = Some(ConfirmDialogState {
                    title: "Freeze Identity?".into(),
                    message: "Freezing will immediately block all authentication. Are you sure?".into(),
                    confirm_label: "Freeze Now".into(),
                    danger: true,
                    action: ConfirmAction::FreezeIdentity,
                });
            }
        });

        ui.add_space(24.0);
        core::section_label(ui, "Advanced Ceremonies");
        ui.label(
            RichText::new("Key rotation and multi-machine ceremonies are available in the Advanced release.")
                .color(theme::TEXT_MUTED),
        );
    }
}
