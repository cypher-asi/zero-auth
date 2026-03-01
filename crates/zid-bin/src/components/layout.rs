use egui::{RichText, Ui};

use super::tokens::{self, colors, font_size, spacing};

pub fn section(ui: &mut Ui, heading: &str, content: impl FnOnce(&mut Ui)) {
    let avail = ui.available_rect_before_wrap();

    let prev_clip = ui.clip_rect();
    ui.set_clip_rect(prev_clip.intersect(egui::Rect::from_x_y_ranges(
        avail.left()..=avail.right(),
        prev_clip.top()..=prev_clip.bottom(),
    )));

    let mut prepared = egui::Frame::new()
        .fill(colors::SURFACE)
        .corner_radius(0.0)
        .inner_margin(spacing::XL)
        .outer_margin(egui::Margin::symmetric(1, 0))
        .stroke(tokens::border_stroke())
        .begin(ui);

    {
        let ui = &mut prepared.content_ui;
        ui.set_width(ui.available_width());
        section_heading(ui, heading);
        ui.add_space(10.0);
        content(ui);
    }

    let resp = prepared.end(ui);

    let border_rect = egui::Rect::from_min_max(
        egui::pos2(avail.left() + 1.0, resp.rect.top()),
        egui::pos2(avail.right() - 1.0, resp.rect.bottom()),
    );
    ui.painter()
        .rect_stroke(border_rect, 0.0, tokens::border_stroke(), egui::StrokeKind::Inside);

    ui.set_clip_rect(prev_clip);
    ui.add_space(spacing::MD);
}

pub fn section_with_action(
    ui: &mut Ui,
    heading: &str,
    enabled: bool,
    content: impl FnOnce(&mut Ui),
) -> bool {
    let avail = ui.available_rect_before_wrap();

    let prev_clip = ui.clip_rect();
    ui.set_clip_rect(prev_clip.intersect(egui::Rect::from_x_y_ranges(
        avail.left()..=avail.right(),
        prev_clip.top()..=prev_clip.bottom(),
    )));

    let mut clicked = false;
    let mut prepared = egui::Frame::new()
        .fill(colors::SURFACE)
        .corner_radius(0.0)
        .inner_margin(spacing::XL)
        .outer_margin(egui::Margin::symmetric(1, 0))
        .stroke(tokens::border_stroke())
        .begin(ui);

    {
        let ui = &mut prepared.content_ui;
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            section_heading(ui, heading);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                clicked = super::buttons::section_add_button(ui, enabled);
            });
        });
        ui.add_space(10.0);
        content(ui);
    }

    let resp = prepared.end(ui);

    let border_rect = egui::Rect::from_min_max(
        egui::pos2(avail.left() + 1.0, resp.rect.top()),
        egui::pos2(avail.right() - 1.0, resp.rect.bottom()),
    );
    ui.painter()
        .rect_stroke(border_rect, 0.0, tokens::border_stroke(), egui::StrokeKind::Inside);

    ui.set_clip_rect(prev_clip);
    ui.add_space(spacing::MD);
    clicked
}

fn section_heading(ui: &mut Ui, title: &str) {
    ui.label(
        RichText::new(title.to_uppercase())
            .strong()
            .size(font_size::HEADING)
            .color(colors::TEXT_HEADING),
    );
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
