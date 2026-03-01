use egui::{RichText, Ui};

use crate::state::AppState;
use crate::ui::components::core;
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::render_page_header(ui, "Settings", None);

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
    let cred_path = state.storage.credentials_path();
    core::data_field(ui, "Credentials", &cred_path.display().to_string());
    let sess_path = state.storage.session_path();
    core::data_field(ui, "Session", &sess_path.display().to_string());

    ui.add_space(24.0);
    core::section_label(ui, "About");
    core::data_field(ui, "Version", env!("CARGO_PKG_VERSION"));
    core::data_field(ui, "Platform", std::env::consts::OS);
}
