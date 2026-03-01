use egui::{RichText, Ui, Vec2};

use super::tokens::{self, colors, font_size, spacing};

pub fn loading_state(ui: &mut Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label(RichText::new(text).color(colors::TEXT_SECONDARY).size(font_size::BODY));
    });
}

pub fn status_dot(ui: &mut Ui, connected: bool) {
    let color = if connected {
        colors::CONNECTED
    } else {
        colors::DISCONNECTED
    };
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), 3.0, color);
}

pub fn verified_icon(ui: &mut Ui) {
    ui.label(RichText::new("✓").color(tokens::SUCCESS).size(font_size::BODY));
}

pub fn failed_icon(ui: &mut Ui) {
    ui.label(RichText::new("✗").color(tokens::DANGER).size(font_size::BODY));
}

pub fn strength_bar(ui: &mut Ui, passphrase: &str) {
    if passphrase.is_empty() {
        return;
    }
    let estimate = zxcvbn::zxcvbn(passphrase, &[]);
    let score = estimate.score();
    let (label, color, level) = match score {
        zxcvbn::Score::Zero | zxcvbn::Score::One => ("WEAK", tokens::DANGER, 1.0),
        zxcvbn::Score::Two => ("FAIR", tokens::WARNING, 2.0),
        zxcvbn::Score::Three => ("GOOD", tokens::INFO, 3.0),
        zxcvbn::Score::Four => ("STRONG", tokens::SUCCESS, 4.0),
        _ => ("UNKNOWN", colors::TEXT_MUTED, 0.0),
    };

    let fraction = (level + 1.0) / 5.0;
    let available = ui.available_width().min(300.0);

    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(available, 4.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, colors::SURFACE_INTERACTIVE);
        let mut filled = rect;
        filled.set_width(rect.width() * fraction);
        painter.rect_filled(filled, 0.0, color);

        ui.add_space(spacing::MD);
        ui.label(RichText::new(label).color(color).size(font_size::SMALL));
    });
}

pub fn progress_stepper(ui: &mut Ui, steps: &[&str], current: usize) {
    ui.horizontal(|ui| {
        for (i, label) in steps.iter().enumerate() {
            let color = if i < current {
                tokens::SUCCESS
            } else if i == current {
                colors::ACCENT
            } else {
                colors::TEXT_MUTED
            };

            let icon = if i < current {
                "✓".to_string()
            } else {
                format!("{}", i + 1)
            };

            let frame = egui::Frame::new()
                .fill(color.linear_multiply(0.15))
                .inner_margin(egui::Margin::symmetric(4, 2))
                .corner_radius(0.0);

            frame.show(ui, |ui| {
                ui.label(RichText::new(&icon).color(color).size(font_size::SMALL));
            });

            ui.label(
                RichText::new(label.to_uppercase())
                    .color(color)
                    .size(font_size::SMALL),
            );

            if i < steps.len() - 1 {
                ui.label(RichText::new("—").color(colors::TEXT_MUTED));
            }
        }
    });
}
