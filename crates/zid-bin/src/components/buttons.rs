use egui::{Color32, RichText, Ui, Vec2};

use super::tokens::{self, colors, font_size, ICON_SIZE, WIDGET_HEIGHT};

fn styled_button(ui: &mut Ui, label: &str, padding: Vec2, font_size: f32) -> bool {
    let old_padding = ui.spacing().button_padding;
    ui.spacing_mut().button_padding = padding;

    let wv = &mut ui.visuals_mut().widgets;
    let saved = (
        wv.inactive.weak_bg_fill,
        wv.hovered.weak_bg_fill,
        wv.active.weak_bg_fill,
    );
    wv.inactive.weak_bg_fill = Color32::BLACK;
    wv.hovered.weak_bg_fill = colors::SURFACE_INTERACTIVE;
    wv.active.weak_bg_fill = colors::BORDER;

    let r = ui.add(
        egui::Button::new(
            RichText::new(label.to_uppercase())
                .color(Color32::WHITE)
                .size(font_size),
        )
        .stroke(tokens::default_stroke())
        .corner_radius(0.0)
        .min_size(Vec2::new(0.0, WIDGET_HEIGHT)),
    );

    let wv = &mut ui.visuals_mut().widgets;
    wv.inactive.weak_bg_fill = saved.0;
    wv.hovered.weak_bg_fill = saved.1;
    wv.active.weak_bg_fill = saved.2;
    ui.spacing_mut().button_padding = old_padding;
    r.clicked()
}

fn styled_button_enabled(
    ui: &mut Ui,
    label: &str,
    enabled: bool,
    padding: Vec2,
    font_size: f32,
) -> bool {
    let old_padding = ui.spacing().button_padding;
    ui.spacing_mut().button_padding = padding;

    let wv = &mut ui.visuals_mut().widgets;
    let saved = (
        wv.inactive.weak_bg_fill,
        wv.hovered.weak_bg_fill,
        wv.active.weak_bg_fill,
    );
    wv.inactive.weak_bg_fill = Color32::BLACK;
    wv.hovered.weak_bg_fill = colors::SURFACE_INTERACTIVE;
    wv.active.weak_bg_fill = colors::BORDER;

    let r = ui.add_enabled(
        enabled,
        egui::Button::new(
            RichText::new(label.to_uppercase())
                .color(Color32::WHITE)
                .size(font_size),
        )
        .stroke(tokens::default_stroke())
        .corner_radius(0.0)
        .min_size(Vec2::new(0.0, WIDGET_HEIGHT)),
    );

    let wv = &mut ui.visuals_mut().widgets;
    wv.inactive.weak_bg_fill = saved.0;
    wv.hovered.weak_bg_fill = saved.1;
    wv.active.weak_bg_fill = saved.2;
    ui.spacing_mut().button_padding = old_padding;
    r.clicked()
}

pub fn std_button(ui: &mut Ui, label: &str) -> bool {
    styled_button(ui, label, Vec2::new(10.0, 4.0), font_size::BUTTON)
}

pub fn action_button(ui: &mut Ui, label: &str, enabled: bool) -> bool {
    styled_button_enabled(ui, label, enabled, Vec2::new(12.0, 5.0), font_size::ACTION)
}

pub fn danger_button(ui: &mut Ui, label: &str, enabled: bool) -> bool {
    ui.add_enabled(
        enabled,
        egui::Button::new(
            RichText::new(label)
                .size(font_size::ACTION)
                .color(colors::ERROR),
        )
        .frame(false),
    )
    .clicked()
}

pub fn ghost_button(ui: &mut Ui, label: &str) -> bool {
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .size(font_size::ACTION)
                .color(colors::TEXT_HEADING),
        )
        .fill(Color32::TRANSPARENT)
        .stroke(egui::Stroke::NONE)
        .corner_radius(4.0),
    )
    .clicked()
}

pub fn link_button(ui: &mut Ui, label: &str) -> bool {
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .size(font_size::ACTION)
                .color(colors::TEXT_SECONDARY),
        )
        .frame(false),
    )
    .clicked()
}

pub fn icon_button(ui: &mut Ui, icon: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(icon).size(ICON_SIZE)).frame(false))
}

pub fn copy_button(ui: &mut Ui, id_salt: &str, text_to_copy: &str) {
    let id = ui.id().with("copy_feedback").with(id_salt);
    let copied_until: Option<f64> = ui.data(|d| d.get_temp(id));
    let now = ui.input(|i| i.time);
    let showing_check = copied_until.is_some_and(|t| now < t);

    let icon = if showing_check {
        egui_phosphor::regular::CHECK
    } else {
        egui_phosphor::regular::CLIPBOARD
    };

    if icon_button(ui, icon).clicked() {
        ui.ctx().copy_text(text_to_copy.to_owned());
        ui.data_mut(|d| d.insert_temp(id, now + 1.5));
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(1600));
    }
}

pub fn square_icon_button(ui: &mut Ui, icon: &str) -> bool {
    let size = Vec2::new(WIDGET_HEIGHT, WIDGET_HEIGHT);

    let wv = &mut ui.visuals_mut().widgets;
    let saved = (
        wv.inactive.weak_bg_fill,
        wv.hovered.weak_bg_fill,
        wv.active.weak_bg_fill,
    );
    wv.inactive.weak_bg_fill = Color32::BLACK;
    wv.hovered.weak_bg_fill = colors::SURFACE_INTERACTIVE;
    wv.active.weak_bg_fill = colors::BORDER;

    let r = ui.add(
        egui::Button::new(
            RichText::new(icon)
                .size(ICON_SIZE)
                .color(Color32::WHITE),
        )
        .stroke(tokens::default_stroke())
        .corner_radius(0.0)
        .min_size(size),
    );

    let wv = &mut ui.visuals_mut().widgets;
    wv.inactive.weak_bg_fill = saved.0;
    wv.hovered.weak_bg_fill = saved.1;
    wv.active.weak_bg_fill = saved.2;
    r.clicked()
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
