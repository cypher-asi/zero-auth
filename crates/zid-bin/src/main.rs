mod app;
mod components;
mod error;
mod infra;
mod render;
mod service;
mod setup;
mod state;

use std::sync::Arc;

use eframe::egui;
use tokio::sync::mpsc;

use crate::components::tokens::{colors, font_size, spacing};
use crate::infra::local_storage::LocalStorage;
use crate::state::types::AppSettings;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zid_bin=info,zid_server=info".into()),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(ensure_server_running());

    let (tx, rx) = mpsc::unbounded_channel();

    let icon = load_icon();

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([820.0, 832.0])
        .with_min_inner_size([700.0, 500.0])
        .with_title("Zero-ID")
        .with_decorations(false)
        .with_resizable(true);

    if let Some(icon) = icon {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    let handle = rt.handle().clone();

    eframe::run_native(
        "Zero-ID",
        options,
        Box::new(move |cc| {
            configure_fonts(&cc.egui_ctx);
            Ok(Box::new(app::ZeroIdApp::new(cc, handle, tx, rx)))
        }),
    )
}

fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    let inter_data = include_bytes!("../assets/Inter-Regular.ttf");
    fonts.font_data.insert(
        "Inter".to_owned(),
        Arc::new(egui::FontData::from_static(inter_data)),
    );

    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "Inter".to_owned());

    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);

    ctx.set_fonts(fonts);
}

pub(crate) fn configure_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = colors::SURFACE;
    visuals.window_fill = colors::SURFACE_DARK;
    visuals.extreme_bg_color = colors::SURFACE_DARK;
    visuals.faint_bg_color = colors::SURFACE_RAISED;

    visuals.widgets.noninteractive.bg_fill = colors::SURFACE_DARK;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::ZERO;

    visuals.widgets.inactive.bg_fill = colors::SURFACE_INTERACTIVE;
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::ZERO;

    visuals.widgets.hovered.bg_fill = colors::SURFACE_INTERACTIVE;
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::ZERO;

    visuals.widgets.active.bg_fill = colors::SURFACE_RAISED;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.widgets.active.corner_radius = egui::CornerRadius::ZERO;

    visuals.selection.bg_fill = colors::ACCENT.linear_multiply(0.2);
    visuals.selection.stroke = egui::Stroke::new(1.0, colors::ACCENT);

    visuals.window_corner_radius = egui::CornerRadius::ZERO;
    visuals.window_stroke = egui::Stroke::new(1.0, colors::BORDER);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::Vec2::new(spacing::MD, spacing::SM);
    style.spacing.window_margin = egui::Margin::same(spacing::XL as i8);
    style.spacing.button_padding = egui::Vec2::new(spacing::MD, spacing::SM);
    style.spacing.interact_size.y = 20.0;

    use egui::{FontId, TextStyle};
    style.text_styles.insert(
        TextStyle::Body,
        FontId::proportional(font_size::BODY),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::proportional(font_size::BUTTON),
    );
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::proportional(font_size::HEADING),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::proportional(font_size::SMALL),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::monospace(font_size::BODY),
    );

    ctx.set_style(style);
}

fn load_icon() -> Option<egui::IconData> {
    let src = image::load_from_memory(include_bytes!("../assets/icon.png"))
        .ok()?
        .to_rgba8();
    let (sw, sh) = (src.width(), src.height());

    let pad = (sw.min(sh) as f64 * 0.10) as u32;
    let out_w = sw + pad * 2;
    let out_h = sh + pad * 2;
    let r = (out_w.min(out_h) as f64) * 0.18;

    let mut rgba = vec![0u8; (out_w * out_h * 4) as usize];

    for y in 0..out_h {
        for x in 0..out_w {
            let i = ((y * out_w + x) * 4) as usize;
            let a = corner_alpha(
                x as f64 + 0.5,
                y as f64 + 0.5,
                out_w as f64,
                out_h as f64,
                r,
            );
            if a <= 0.0 {
                continue;
            }

            let (r_val, g_val, b_val) = if x >= pad && x < pad + sw && y >= pad && y < pad + sh {
                let px = src.get_pixel(x - pad, y - pad);
                (px[0], px[1], px[2])
            } else {
                (0, 0, 0)
            };

            rgba[i] = r_val;
            rgba[i + 1] = g_val;
            rgba[i + 2] = b_val;
            rgba[i + 3] = (a * 255.0).round() as u8;
        }
    }

    Some(egui::IconData {
        width: out_w,
        height: out_h,
        rgba,
    })
}

fn corner_alpha(cx: f64, cy: f64, w: f64, h: f64, r: f64) -> f64 {
    let (kx, ky) = if cx < r && cy < r {
        (r, r)
    } else if cx > w - r && cy < r {
        (w - r, r)
    } else if cx < r && cy > h - r {
        (r, h - r)
    } else if cx > w - r && cy > h - r {
        (w - r, h - r)
    } else {
        return 1.0;
    };
    let dist = ((cx - kx).powi(2) + (cy - ky).powi(2)).sqrt();
    (r + 0.5 - dist).clamp(0.0, 1.0)
}

async fn ensure_server_running() {
    let storage = match LocalStorage::new() {
        Ok(s) => s,
        Err(_) => return,
    };
    let settings = storage
        .read_json::<AppSettings>(&storage.settings_path())
        .unwrap_or_default();

    let server_url = settings.server_url.trim_end_matches('/');

    if !is_local_url(server_url) {
        return;
    }

    let health_url = format!("{}/health", server_url);
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(1))
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();

    if client.get(&health_url).send().await.is_ok() {
        tracing::info!("Identity server already running at {}", server_url);
        return;
    }

    tracing::info!("Starting embedded identity server...");

    let bind_address = parse_bind_address(server_url);
    let data_dir = storage.server_data_dir();

    tokio::spawn(async move {
        if let Err(e) = zid_server::start_embedded(bind_address, data_dir).await {
            tracing::error!("Embedded identity server error: {}", e);
        }
    });

    for i in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if client.get(&health_url).send().await.is_ok() {
            tracing::info!("Embedded identity server ready");
            return;
        }
        if i == 20 {
            tracing::debug!("Still waiting for embedded server...");
        }
    }

    tracing::warn!("Embedded server did not become ready within 5 seconds, continuing anyway");
}

fn is_local_url(url: &str) -> bool {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    without_scheme.starts_with("127.0.0.1")
        || without_scheme.starts_with("localhost")
        || without_scheme.starts_with("[::1]")
}

fn parse_bind_address(server_url: &str) -> std::net::SocketAddr {
    let without_scheme = server_url
        .strip_prefix("http://")
        .or_else(|| server_url.strip_prefix("https://"))
        .unwrap_or(server_url);
    without_scheme
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:9999".parse().unwrap())
}
