use egui::{Color32, RichText, Ui, Vec2};

use crate::ui::theme;

pub fn primary_button(ui: &mut Ui, label: &str, enabled: bool) -> bool {
    let btn = egui::Button::new(RichText::new(label).color(Color32::WHITE))
        .fill(theme::BRAND_PRIMARY)
        .rounding(egui::Rounding::same(6.0))
        .min_size(Vec2::new(0.0, 32.0));
    ui.add_enabled(enabled, btn).clicked()
}

pub fn danger_button(ui: &mut Ui, label: &str, enabled: bool) -> bool {
    let btn = egui::Button::new(RichText::new(label).color(Color32::WHITE))
        .fill(theme::DANGER)
        .rounding(egui::Rounding::same(6.0))
        .min_size(Vec2::new(0.0, 32.0));
    ui.add_enabled(enabled, btn).clicked()
}

pub fn secondary_button(ui: &mut Ui, label: &str) -> bool {
    let btn = egui::Button::new(RichText::new(label).color(theme::TEXT_SECONDARY))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .rounding(egui::Rounding::same(6.0))
        .min_size(Vec2::new(0.0, 32.0));
    ui.add(btn).clicked()
}

pub fn text_input(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    let te = egui::TextEdit::singleline(value)
        .hint_text(RichText::new(hint).color(theme::TEXT_MUTED))
        .desired_width(f32::INFINITY)
        .font(theme::body_font());
    ui.add(te)
}

pub fn password_input(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    let te = egui::TextEdit::singleline(value)
        .password(true)
        .hint_text(RichText::new(hint).color(theme::TEXT_MUTED))
        .desired_width(f32::INFINITY)
        .font(theme::body_font());
    ui.add(te)
}

pub fn hex_input(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    let te = egui::TextEdit::singleline(value)
        .hint_text(RichText::new(hint).color(theme::TEXT_MUTED))
        .desired_width(f32::INFINITY)
        .font(theme::mono_font());
    ui.add(te)
}

pub fn badge(ui: &mut Ui, label: &str, color: Color32) {
    let frame = egui::Frame::none()
        .fill(color.linear_multiply(0.2))
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .rounding(egui::Rounding::same(4.0));
    frame.show(ui, |ui| {
        ui.label(RichText::new(label).color(color).font(theme::small_font()));
    });
}

pub fn data_field(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{label}:")).color(theme::TEXT_MUTED).font(theme::small_font()));
        ui.label(RichText::new(value).color(theme::TEXT_PRIMARY).font(theme::body_font()));
    });
}

pub fn data_field_mono(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{label}:")).color(theme::TEXT_MUTED).font(theme::small_font()));
        ui.label(RichText::new(value).color(theme::TEXT_PRIMARY).font(theme::mono_font()));
    });
}

pub fn spinner(ui: &mut Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label(RichText::new(text).color(theme::TEXT_SECONDARY));
    });
}

pub fn strength_bar(ui: &mut Ui, passphrase: &str) {
    if passphrase.is_empty() {
        return;
    }
    let estimate = zxcvbn::zxcvbn(passphrase, &[]);
    let score = estimate.score();
    let (label, color, level) = match score {
        zxcvbn::Score::Zero | zxcvbn::Score::One => ("Weak", theme::DANGER, 1.0),
        zxcvbn::Score::Two => ("Fair", theme::WARNING, 2.0),
        zxcvbn::Score::Three => ("Good", theme::INFO, 3.0),
        zxcvbn::Score::Four => ("Strong", theme::SUCCESS, 4.0),
        _ => ("Unknown", theme::TEXT_MUTED, 0.0),
    };

    let fraction = (level + 1.0) / 5.0;
    let available = ui.available_width().min(300.0);

    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(available, 6.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 3.0, theme::BG_TERTIARY);
        let mut filled = rect;
        filled.set_width(rect.width() * fraction);
        painter.rect_filled(filled, 3.0, color);

        ui.add_space(8.0);
        ui.label(RichText::new(label).color(color).font(theme::small_font()));
    });
}

pub fn progress_stepper(ui: &mut Ui, steps: &[&str], current: usize) {
    ui.horizontal(|ui| {
        for (i, label) in steps.iter().enumerate() {
            let color = if i < current {
                theme::SUCCESS
            } else if i == current {
                theme::BRAND_PRIMARY
            } else {
                theme::TEXT_MUTED
            };

            let icon = if i < current { "✓" } else { &format!("{}", i + 1) };

            let frame = egui::Frame::none()
                .fill(color.linear_multiply(0.2))
                .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                .rounding(egui::Rounding::same(12.0));

            frame.show(ui, |ui| {
                ui.label(RichText::new(icon).color(color).font(theme::small_font()));
            });

            ui.label(RichText::new(*label).color(color).font(theme::small_font()));

            if i < steps.len() - 1 {
                ui.label(RichText::new("—").color(theme::TEXT_MUTED));
            }
        }
    });
}

pub fn acknowledge_checkbox(ui: &mut Ui, checked: &mut bool, label: &str) -> bool {
    ui.checkbox(checked, RichText::new(label).color(theme::TEXT_PRIMARY));
    *checked
}

pub fn card_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(theme::BG_CARD)
        .inner_margin(egui::Margin::same(16.0))
        .rounding(egui::Rounding::same(theme::ROUNDING))
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
}

pub fn section_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(theme::subheading_font()).color(theme::TEXT_PRIMARY));
    ui.add_space(4.0);
}
