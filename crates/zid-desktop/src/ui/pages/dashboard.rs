use egui::{RichText, Ui};

use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::AppState;
use crate::ui::components::{core, domain};
use crate::ui::layout;
use crate::ui::theme;

pub fn render(ui: &mut Ui, state: &mut AppState, rt: &tokio::runtime::Handle) {
    layout::render_page_header(ui, "Dashboard", None);

    if state.identity_status == LoadStatus::Idle {
        state.identity_status = LoadStatus::Loading;
        let tx = state.tx.clone();
        let client = state.http_client.clone();
        rt.spawn(async move {
            match crate::service::identity::get_current(&client).await {
                Ok(id) => {
                    let _ = tx.send(AppMessage::IdentityLoaded(id));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }

    if let Some(identity) = &state.identity.clone() {
        domain::identity_badge(ui, identity);
        ui.add_space(16.0);

        egui::Grid::new("identity_details")
            .num_columns(2)
            .spacing([24.0, 8.0])
            .show(ui, |ui| {
                core::data_field(ui, "Identity ID", &identity.identity_id.to_string());
                ui.end_row();
                if !identity.did.is_empty() {
                    core::data_field_mono(ui, "DID", &identity.did);
                    ui.end_row();
                }
                core::data_field(ui, "Tier", &identity.tier);
                ui.end_row();
                core::data_field(ui, "Status", &identity.status);
                ui.end_row();
                core::data_field(ui, "Created", &identity.created_at);
                ui.end_row();
            });

        ui.add_space(24.0);
        core::section_label(ui, "Quick Actions");
        ui.horizontal(|ui| {
            if core::primary_button(ui, "View Machines", true) {
                state.navigate(Page::Machines);
            }
            if core::secondary_button(ui, "Linked Identities") {
                state.navigate(Page::Credentials);
            }
            if core::secondary_button(ui, "Security") {
                state.navigate(Page::Security);
            }
        });
    } else if state.identity_status == LoadStatus::Loading {
        core::spinner(ui, "Loading identity...");
    } else if let LoadStatus::Error(ref e) = state.identity_status {
        ui.label(RichText::new(e).color(theme::DANGER));
    }

    if let Some(session) = &state.current_session {
        ui.add_space(24.0);
        core::section_label(ui, "Current Session");
        core::data_field(ui, "Session ID", &session.session_id.to_string()[..8]);
        core::data_field(ui, "Expires", &session.expires_at);
    }
}
