use egui::{Color32, RichText, Ui};

use super::tokens::{colors, font_size, spacing};

pub fn section_heading(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .color(colors::TEXT_HEADING)
            .size(font_size::HEADING),
    );
    ui.add_space(spacing::SM);
}

pub fn field_label(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .color(colors::TEXT_SECONDARY)
            .size(font_size::BODY),
    );
}

pub fn hint_label(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .color(colors::TEXT_MUTED)
            .size(font_size::SMALL),
    );
}

pub fn muted_label(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .color(colors::TEXT_MUTED)
            .size(font_size::BODY),
    );
}

pub fn error_label(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .color(super::tokens::DANGER)
            .size(font_size::SMALL),
    );
}

pub fn badge(ui: &mut Ui, label: &str, color: Color32) {
    let frame = egui::Frame::new()
        .fill(color.linear_multiply(0.15))
        .inner_margin(egui::Margin::symmetric(6i8, 2i8))
        .corner_radius(0.0)
        .stroke(egui::Stroke::new(1.0, color.linear_multiply(0.3)));
    frame.show(ui, |ui| {
        ui.label(
            RichText::new(label.to_uppercase())
                .color(color)
                .size(font_size::SMALL),
        );
    });
}
