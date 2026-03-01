use egui::{Color32, RichText, Ui, Vec2};

use super::tokens::{self, colors, font_size, ICON_SIZE, WIDGET_HEIGHT};

fn styled_button(ui: &mut Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label.to_uppercase())
            .color(Color32::WHITE)
            .size(font_size::BUTTON),
    )
    .fill(Color32::BLACK)
    .stroke(egui::Stroke::new(1.0, colors::BORDER))
    .corner_radius(0.0)
    .min_size(Vec2::new(0.0, WIDGET_HEIGHT));
    ui.add(btn)
}

pub fn action_button(ui: &mut Ui, label: &str, enabled: bool) -> bool {
    let btn = egui::Button::new(
        RichText::new(label.to_uppercase())
            .color(Color32::WHITE)
            .size(font_size::ACTION),
    )
    .fill(Color32::BLACK)
    .stroke(egui::Stroke::new(1.0, colors::BORDER_SUBTLE))
    .corner_radius(0.0)
    .min_size(Vec2::new(0.0, WIDGET_HEIGHT));
    ui.add_enabled(enabled, btn).clicked()
}

pub fn std_button(ui: &mut Ui, label: &str) -> bool {
    styled_button(ui, label).clicked()
}

pub fn danger_button(ui: &mut Ui, label: &str, enabled: bool) -> bool {
    let btn = egui::Button::new(
        RichText::new(label.to_uppercase())
            .color(tokens::DANGER)
            .size(font_size::BUTTON),
    )
    .fill(Color32::BLACK)
    .stroke(egui::Stroke::new(1.0, tokens::DANGER.linear_multiply(0.4)))
    .corner_radius(0.0)
    .min_size(Vec2::new(0.0, WIDGET_HEIGHT));
    ui.add_enabled(enabled, btn).clicked()
}

pub fn ghost_button(ui: &mut Ui, label: &str) -> bool {
    let btn = egui::Button::new(
        RichText::new(label.to_uppercase())
            .color(colors::TEXT_HEADING)
            .size(font_size::BUTTON),
    )
    .fill(Color32::TRANSPARENT)
    .stroke(egui::Stroke::NONE)
    .corner_radius(0.0)
    .min_size(Vec2::new(0.0, WIDGET_HEIGHT));
    ui.add(btn).clicked()
}

pub fn link_button(ui: &mut Ui, label: &str) -> bool {
    let btn = egui::Button::new(
        RichText::new(label)
            .color(colors::ACCENT)
            .size(font_size::BODY),
    )
    .fill(Color32::TRANSPARENT)
    .stroke(egui::Stroke::NONE)
    .corner_radius(0.0);
    ui.add(btn).clicked()
}

pub fn copy_button(ui: &mut Ui, id_salt: &str, text_to_copy: &str) -> bool {
    let id = ui.make_persistent_id(format!("copy_{}", id_salt));
    let copied = ui.data(|d| d.get_temp::<f64>(id)).unwrap_or(0.0);
    let now = ui.input(|i| i.time);
    let is_copied = (now - copied) < 2.0;

    let label = if is_copied { "COPIED" } else { "COPY" };
    let color = if is_copied {
        tokens::SUCCESS
    } else {
        colors::TEXT_HEADING
    };

    let btn = egui::Button::new(RichText::new(label).color(color).size(font_size::SMALL))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, colors::BORDER))
        .corner_radius(0.0)
        .min_size(Vec2::new(0.0, 18.0));

    let clicked = ui.add(btn).clicked();
    if clicked {
        ui.ctx().copy_text(text_to_copy.to_string());
        ui.data_mut(|d| d.insert_temp(id, now));
    }
    clicked
}

pub fn icon_button(ui: &mut Ui, icon: &str) -> bool {
    let btn = egui::Button::new(RichText::new(icon).color(colors::TEXT_HEADING).size(14.0))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::NONE)
        .corner_radius(0.0)
        .min_size(Vec2::new(WIDGET_HEIGHT, WIDGET_HEIGHT));
    ui.add(btn).clicked()
}

pub fn square_icon_button(ui: &mut Ui, icon: &str, size: f32) -> bool {
    let btn = egui::Button::new(RichText::new(icon).color(colors::TEXT_HEADING).size(size))
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::NONE)
        .corner_radius(0.0)
        .min_size(Vec2::new(size + 8.0, size + 8.0));
    ui.add(btn).clicked()
}

pub fn title_bar_icon(ui: &mut Ui, icon: &str, active: bool) -> egui::Response {
    let font_id = egui::FontId::proportional(ICON_SIZE);
    let galley =
        ui.fonts(|f| f.layout_no_wrap(icon.to_string(), font_id, Color32::PLACEHOLDER));
    let bp = ui.spacing().button_padding;
    let desired = Vec2::new(galley.size().x + bp.x * 2.0, ui.spacing().interact_size.y);
    let (rect, resp) = ui.allocate_exact_size(desired, egui::Sense::click());
    let vis = ui.style().interact_selectable(&resp, active);
    if !active && resp.hovered() {
        ui.painter()
            .rect_filled(rect, vis.corner_radius, vis.bg_fill);
    }
    let text_color = if active {
        Color32::WHITE
    } else {
        vis.text_color()
    };
    let galley = ui.fonts(|f| {
        f.layout_no_wrap(
            icon.to_string(),
            egui::FontId::proportional(ICON_SIZE),
            text_color,
        )
    });
    let text_pos = rect.center() - galley.size() / 2.0;
    ui.painter().galley(text_pos, galley, vis.text_color());
    resp
}
