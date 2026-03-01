use egui::{RichText, Ui};

use crate::state::{AppState, ConfirmAction, ConfirmDialogState};
use crate::ui::components::{core, domain};
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, _rt: &tokio::runtime::Handle) {
    layout::render_page_header(ui, "Sessions", None);

    if let Some(session) = &state.current_session {
        core::section_label(ui, "Current Session");
        let sess = session.clone();
        if domain::session_card(ui, &sess) {
            state.confirm_dialog = Some(ConfirmDialogState {
                title: "Logout?".into(),
                message: "This will revoke your current session.".into(),
                confirm_label: "Logout".into(),
                danger: false,
                action: ConfirmAction::Logout,
            });
        }
    } else {
        ui.label(RichText::new("No active session").color(theme::TEXT_MUTED));
    }
}
