use egui::{RichText, Ui};

use super::tokens::{colors, font_size, spacing, TEXT_PRIMARY};

pub fn info_grid(ui: &mut Ui, id: &str, rows: impl FnOnce(&mut Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([spacing::XXL, spacing::SM])
        .show(ui, |ui| {
            rows(ui);
        });
}

pub fn kv_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(
        RichText::new(label.to_uppercase())
            .color(colors::TEXT_SECONDARY)
            .size(font_size::SMALL),
    );
    ui.label(RichText::new(value).color(TEXT_PRIMARY).size(font_size::BODY));
    ui.end_row();
}

pub fn kv_row_mono(ui: &mut Ui, label: &str, value: &str) {
    ui.label(
        RichText::new(label.to_uppercase())
            .color(colors::TEXT_SECONDARY)
            .size(font_size::SMALL),
    );
    ui.label(
        RichText::new(value)
            .color(TEXT_PRIMARY)
            .font(egui::FontId::monospace(font_size::BODY)),
    );
    ui.end_row();
}

pub fn kv_row_copyable(ui: &mut Ui, label: &str, value: &str) {
    ui.label(
        RichText::new(label.to_uppercase())
            .color(colors::TEXT_SECONDARY)
            .size(font_size::SMALL),
    );
    ui.horizontal(|ui| {
        ui.label(RichText::new(value).color(TEXT_PRIMARY).size(font_size::BODY));
        super::buttons::copy_button(ui, label, value);
    });
    ui.end_row();
}

pub fn editable_list(ui: &mut Ui, items: &[String], on_remove: &mut Option<usize>) {
    for (i, item) in items.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(item).color(TEXT_PRIMARY).size(font_size::BODY));
            if super::buttons::ghost_button(ui, "✕") {
                *on_remove = Some(i);
            }
        });
    }
}
