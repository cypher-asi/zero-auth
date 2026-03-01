use egui::{RichText, Ui};

use super::tokens::{colors, font_size, spacing};

pub fn section(ui: &mut Ui, heading: &str, content: impl FnOnce(&mut Ui)) {
    super::labels::section_heading(ui, heading);
    content(ui);
    ui.add_space(spacing::XXL);
}

pub fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(colors::SURFACE_DARK)
        .inner_margin(egui::Margin::same(spacing::LG as i8))
        .corner_radius(0.0)
        .stroke(egui::Stroke::new(1.0, colors::BORDER))
}

pub fn auth_screen_panel(ui: &mut Ui, max_width: f32, content: impl FnOnce(&mut Ui)) {
    ui.vertical_centered(|ui| {
        ui.set_max_width(max_width);
        ui.add_space(spacing::XXXL);
        content(ui);
    });
}

pub fn form_grid(ui: &mut Ui, id: &str, content: impl FnOnce(&mut Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([spacing::XL, spacing::MD])
        .show(ui, |ui| {
            content(ui);
        });
}

pub fn warning_frame(ui: &mut Ui, text: &str) {
    let color = super::tokens::WARNING;
    let frame = egui::Frame::new()
        .fill(color.linear_multiply(0.08))
        .inner_margin(egui::Margin::same(spacing::LG as i8))
        .corner_radius(0.0)
        .stroke(egui::Stroke::new(1.0, color.linear_multiply(0.3)));
    frame.show(ui, |ui| {
        ui.label(RichText::new(text).color(color).size(font_size::BODY));
    });
}

pub fn danger_frame(ui: &mut Ui, text: &str) {
    let color = super::tokens::DANGER;
    let frame = egui::Frame::new()
        .fill(color.linear_multiply(0.08))
        .inner_margin(egui::Margin::same(spacing::LG as i8))
        .corner_radius(0.0)
        .stroke(egui::Stroke::new(1.0, color.linear_multiply(0.3)));
    frame.show(ui, |ui| {
        ui.label(RichText::new(text).color(color).size(font_size::BODY));
    });
}

pub fn frozen_banner(ui: &mut Ui, reason: &str) {
    let frame = egui::Frame::new()
        .fill(super::tokens::DANGER.linear_multiply(0.1))
        .inner_margin(egui::Margin::symmetric(spacing::XL as i8, spacing::MD as i8))
        .corner_radius(0.0)
        .stroke(egui::Stroke::new(1.0, super::tokens::DANGER));

    frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("IDENTITY FROZEN")
                    .color(super::tokens::DANGER)
                    .size(font_size::BUTTON)
                    .strong(),
            );
            ui.label(
                RichText::new(format!("Reason: {}", reason))
                    .color(colors::TEXT_SECONDARY)
                    .size(font_size::BODY),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new("Authentication blocked. Go to Security to unfreeze.")
                        .color(colors::TEXT_MUTED)
                        .size(font_size::SMALL),
                );
            });
        });
    });
}

pub fn page_header(ui: &mut Ui, _title: &str, action: Option<(&str, bool)>) -> bool {
    let mut clicked = false;
    if let Some((label, enabled)) = action {
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                clicked = super::buttons::action_button(ui, label, enabled);
            });
        });
        ui.add_space(spacing::SM);
    }
    clicked
}

pub fn confirm_dialog(
    ui: &mut Ui,
    dialog: &crate::state::ConfirmDialogState,
) -> (bool, bool) {
    let mut confirmed = false;
    let mut closed = false;

    egui::Window::new(&dialog.title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .fixed_size([400.0, 0.0])
        .show(ui.ctx(), |ui| {
            ui.add_space(spacing::MD);
            ui.label(
                RichText::new(&dialog.message)
                    .color(super::tokens::TEXT_PRIMARY)
                    .size(font_size::BODY),
            );
            ui.add_space(spacing::XL);
            ui.horizontal(|ui| {
                if super::buttons::ghost_button(ui, "Cancel") {
                    closed = true;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if dialog.danger {
                        if super::buttons::danger_button(ui, &dialog.confirm_label, true) {
                            confirmed = true;
                            closed = true;
                        }
                    } else if super::buttons::action_button(ui, &dialog.confirm_label, true) {
                        confirmed = true;
                        closed = true;
                    }
                });
            });
        });

    (confirmed, closed)
}

pub fn title_bar_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(colors::PANEL_BG)
        .inner_margin(egui::Margin::symmetric(
            spacing::LG as i8,
            spacing::MD as i8,
        ))
        .stroke(egui::Stroke::NONE)
}

pub fn toast_area(ctx: &egui::Context, toasts: &[crate::state::types::ToastMessage]) {
    if toasts.is_empty() {
        return;
    }

    egui::Area::new(egui::Id::new("toast_area"))
        .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -spacing::XL))
        .show(ctx, |ui| {
            ui.set_max_width(320.0);
            for toast in toasts {
                let color = match toast.level {
                    crate::state::types::ToastLevel::Success => super::tokens::SUCCESS,
                    crate::state::types::ToastLevel::Error => super::tokens::DANGER,
                    crate::state::types::ToastLevel::Warning => super::tokens::WARNING,
                    crate::state::types::ToastLevel::Info => super::tokens::INFO,
                };
                let frame = egui::Frame::new()
                    .fill(colors::SURFACE_DARK)
                    .inner_margin(egui::Margin::symmetric(spacing::LG as i8, spacing::MD as i8))
                    .corner_radius(0.0)
                    .stroke(egui::Stroke::new(1.0, color.linear_multiply(0.5)));
                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").color(color).size(font_size::SMALL));
                        ui.label(
                            RichText::new(&toast.text)
                                .color(super::tokens::TEXT_PRIMARY)
                                .size(font_size::BODY),
                        );
                    });
                });
                ui.add_space(spacing::SM);
            }
        });
}
