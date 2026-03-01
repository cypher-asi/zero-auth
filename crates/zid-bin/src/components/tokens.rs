use eframe::egui::Color32;

pub mod colors {
    use eframe::egui::Color32;

    pub const SURFACE: Color32 = Color32::from_rgb(1, 1, 1);
    pub const SURFACE_DARK: Color32 = Color32::from_rgb(20, 20, 22);
    pub const SURFACE_RAISED: Color32 = Color32::from_rgb(28, 28, 30);
    pub const SURFACE_INTERACTIVE: Color32 = Color32::from_rgb(38, 38, 42);
    pub const PANEL_BG: Color32 = Color32::BLACK;

    pub const BORDER: Color32 = Color32::from_rgb(48, 48, 52);
    pub const BORDER_SUBTLE: Color32 = Color32::from_rgb(55, 55, 60);
    pub const BORDER_DIM: Color32 = Color32::from_rgb(50, 50, 55);

    pub const TEXT_HEADING: Color32 = Color32::from_rgb(140, 140, 145);
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(100, 100, 108);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(160, 160, 165);

    pub const ERROR: Color32 = Color32::from_rgb(255, 80, 80);
    pub const WARN: Color32 = Color32::from_rgb(255, 200, 100);
    pub const CONNECTED: Color32 = Color32::from_rgb(46, 230, 176);
    pub const DISCONNECTED: Color32 = Color32::from_rgb(255, 80, 80);

    pub const ACCENT: Color32 = Color32::from_rgb(0, 180, 255);
}

pub mod spacing {
    pub const XS: f32 = 2.0;
    pub const SM: f32 = 4.0;
    pub const MD: f32 = 8.0;
    pub const LG: f32 = 12.0;
    pub const XL: f32 = 16.0;
    pub const XXL: f32 = 24.0;
    pub const XXXL: f32 = 32.0;
}

pub mod font_size {
    pub const SMALL: f32 = 9.0;
    pub const BODY: f32 = 10.0;
    pub const BUTTON: f32 = 10.0;
    pub const ACTION: f32 = 11.0;
    pub const SUBTITLE: f32 = 12.0;
    pub const HEADING: f32 = 10.0;
}

pub const WIDGET_HEIGHT: f32 = 24.0;
pub const NAV_WIDTH: f32 = 168.0;
pub const TITLE_BAR_HEIGHT: f32 = 32.0;

pub const TEXT_PRIMARY: Color32 = Color32::WHITE;
pub const SUCCESS: Color32 = Color32::from_rgb(46, 230, 176);
pub const DANGER: Color32 = Color32::from_rgb(255, 80, 80);
pub const WARNING: Color32 = Color32::from_rgb(255, 200, 100);
pub const INFO: Color32 = Color32::from_rgb(0, 180, 255);
