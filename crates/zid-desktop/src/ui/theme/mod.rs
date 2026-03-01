use egui::{Color32, FontId, Rounding, Stroke, Vec2, Visuals};

pub const BRAND_PRIMARY: Color32 = Color32::from_rgb(99, 102, 241);
pub const BRAND_PRIMARY_HOVER: Color32 = Color32::from_rgb(79, 70, 229);
pub const DANGER: Color32 = Color32::from_rgb(239, 68, 68);
pub const DANGER_HOVER: Color32 = Color32::from_rgb(220, 38, 38);
pub const WARNING: Color32 = Color32::from_rgb(245, 158, 11);
pub const SUCCESS: Color32 = Color32::from_rgb(34, 197, 94);
pub const INFO: Color32 = Color32::from_rgb(59, 130, 246);

pub const BG_PRIMARY: Color32 = Color32::from_rgb(17, 24, 39);
pub const BG_SECONDARY: Color32 = Color32::from_rgb(31, 41, 55);
pub const BG_TERTIARY: Color32 = Color32::from_rgb(55, 65, 81);
pub const BG_CARD: Color32 = Color32::from_rgb(31, 41, 55);
pub const BG_INPUT: Color32 = Color32::from_rgb(17, 24, 39);

pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(243, 244, 246);
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(156, 163, 175);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(107, 114, 128);

pub const BORDER: Color32 = Color32::from_rgb(75, 85, 99);
pub const BORDER_FOCUS: Color32 = BRAND_PRIMARY;

pub const SIDEBAR_WIDTH: f32 = 220.0;
pub const SPACING: f32 = 8.0;
pub const PADDING: f32 = 16.0;
pub const ROUNDING: f32 = 8.0;

pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    visuals.panel_fill = BG_PRIMARY;
    visuals.window_fill = BG_SECONDARY;
    visuals.extreme_bg_color = BG_INPUT;
    visuals.faint_bg_color = BG_TERTIARY;

    visuals.widgets.noninteractive.bg_fill = BG_CARD;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.noninteractive.rounding = Rounding::same(ROUNDING);

    visuals.widgets.inactive.bg_fill = BG_TERTIARY;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.inactive.rounding = Rounding::same(ROUNDING);

    visuals.widgets.hovered.bg_fill = BRAND_PRIMARY_HOVER;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.hovered.rounding = Rounding::same(ROUNDING);

    visuals.widgets.active.bg_fill = BRAND_PRIMARY;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.rounding = Rounding::same(ROUNDING);

    visuals.selection.bg_fill = BRAND_PRIMARY.linear_multiply(0.3);
    visuals.selection.stroke = Stroke::new(1.0, BRAND_PRIMARY);

    visuals.window_rounding = Rounding::same(12.0);
    visuals.window_stroke = Stroke::new(1.0, BORDER);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(SPACING, SPACING);
    style.spacing.window_margin = egui::Margin::same(PADDING);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    ctx.set_style(style);
}

pub fn heading_font() -> FontId {
    FontId::proportional(24.0)
}

pub fn subheading_font() -> FontId {
    FontId::proportional(18.0)
}

pub fn body_font() -> FontId {
    FontId::proportional(14.0)
}

pub fn mono_font() -> FontId {
    FontId::monospace(13.0)
}

pub fn small_font() -> FontId {
    FontId::proportional(12.0)
}
