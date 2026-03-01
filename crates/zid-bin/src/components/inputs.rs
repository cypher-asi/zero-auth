use egui::{RichText, Ui};

use super::tokens::{colors, font_size};

pub fn text_input(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    let te = egui::TextEdit::singleline(value)
        .hint_text(RichText::new(hint).color(colors::TEXT_MUTED).size(font_size::BODY))
        .desired_width(f32::INFINITY)
        .font(egui::FontId::proportional(font_size::BODY));
    ui.add(te)
}

pub fn text_input_password(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    let te = egui::TextEdit::singleline(value)
        .password(true)
        .hint_text(RichText::new(hint).color(colors::TEXT_MUTED).size(font_size::BODY))
        .desired_width(f32::INFINITY)
        .font(egui::FontId::proportional(font_size::BODY));
    ui.add(te)
}

pub fn hex_input(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    let te = egui::TextEdit::singleline(value)
        .hint_text(RichText::new(hint).color(colors::TEXT_MUTED).size(font_size::BODY))
        .desired_width(f32::INFINITY)
        .font(egui::FontId::monospace(font_size::BODY));
    ui.add(te)
}
