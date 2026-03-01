use egui::{RichText, Ui};

use crate::state::AppState;
use crate::ui::components::core;
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::render_page_header(ui, "Namespaces", None);

    if state.namespaces.is_empty() {
        ui.label(RichText::new("No namespace memberships").color(theme::TEXT_MUTED));
        ui.add_space(8.0);
        ui.label(
            RichText::new("Namespace management is available in the V1 release.")
                .color(theme::TEXT_MUTED)
                .font(theme::small_font()),
        );
    } else {
        for ns in &state.namespaces.clone() {
            core::card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&ns.name).color(theme::TEXT_PRIMARY).strong());
                    core::badge(ui, &ns.role, theme::BRAND_PRIMARY);
                });
                core::data_field(ui, "ID", &ns.namespace_id.to_string()[..8]);
                core::data_field(ui, "Joined", &ns.joined_at);
            });
            ui.add_space(4.0);
        }
    }
}
