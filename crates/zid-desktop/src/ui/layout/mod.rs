use egui::{Align, Color32, Layout, RichText, Ui, Vec2};

use crate::state::types::*;
use crate::state::AppState;
use crate::ui::theme;

pub fn render_sidebar(ui: &mut Ui, state: &mut AppState) {
    ui.vertical(|ui| {
        ui.add_space(12.0);

        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new("Zero-ID").font(theme::heading_font()).color(theme::BRAND_PRIMARY));
        });

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(8.0);

        let nav_items = [
            (Page::Dashboard, "Dashboard"),
            (Page::Machines, "Machines"),
            (Page::Credentials, "Linked Identities"),
            (Page::Mfa, "MFA"),
            (Page::Sessions, "Sessions"),
            (Page::Namespaces, "Namespaces"),
            (Page::Security, "Security"),
            (Page::Settings, "Settings"),
        ];

        for (page, label) in &nav_items {
            let is_active = std::mem::discriminant(&state.current_page) == std::mem::discriminant(page);
            let text_color = if is_active {
                theme::BRAND_PRIMARY
            } else {
                theme::TEXT_SECONDARY
            };
            let bg = if is_active {
                theme::BRAND_PRIMARY.linear_multiply(0.15)
            } else {
                Color32::TRANSPARENT
            };

            let btn = egui::Button::new(
                RichText::new(*label).color(text_color).font(theme::body_font()),
            )
            .fill(bg)
            .rounding(egui::Rounding::same(6.0))
            .min_size(Vec2::new(ui.available_width() - 24.0, 36.0));

            ui.horizontal(|ui| {
                ui.add_space(12.0);
                if ui.add(btn).clicked() {
                    state.navigate(page.clone());
                }
            });

            ui.add_space(2.0);
        }

        ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(12.0);
                if let Some(identity) = &state.identity {
                    ui.vertical(|ui| {
                        let did_short = if identity.did.len() > 20 {
                            format!("{}...{}", &identity.did[..10], &identity.did[identity.did.len()-6..])
                        } else if identity.did.is_empty() {
                            format!("{}", &identity.identity_id.to_string()[..8])
                        } else {
                            identity.did.clone()
                        };
                        ui.label(RichText::new(did_short).font(theme::small_font()).color(theme::TEXT_MUTED));
                        ui.label(RichText::new(&identity.tier).font(theme::small_font()).color(theme::TEXT_SECONDARY));
                    });
                }
            });
            ui.add_space(4.0);
            ui.separator();
        });
    });
}

pub fn render_frozen_banner(ui: &mut Ui, frozen: &FrozenInfo) {
    let frame = egui::Frame::none()
        .fill(theme::DANGER.linear_multiply(0.15))
        .inner_margin(egui::Margin::symmetric(16.0, 10.0))
        .stroke(egui::Stroke::new(1.0, theme::DANGER));

    frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("IDENTITY FROZEN").color(theme::DANGER).strong());
            ui.label(
                RichText::new(format!("Reason: {}", frozen.reason))
                    .color(theme::TEXT_SECONDARY),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new("Authentication blocked. Go to Security to unfreeze.")
                        .color(theme::TEXT_MUTED)
                        .font(theme::small_font()),
                );
            });
        });
    });
}

pub fn render_page_header(ui: &mut Ui, title: &str, action: Option<(&str, bool)>) -> bool {
    let mut clicked = false;
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).font(theme::heading_font()).color(theme::TEXT_PRIMARY));
        if let Some((label, enabled)) = action {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let btn = egui::Button::new(
                    RichText::new(label).color(Color32::WHITE),
                )
                .fill(theme::BRAND_PRIMARY)
                .rounding(egui::Rounding::same(6.0));
                let response = ui.add_enabled(enabled, btn);
                if response.clicked() {
                    clicked = true;
                }
            });
        }
    });
    ui.add_space(4.0);
    ui.separator();
    ui.add_space(8.0);
    clicked
}

pub fn render_toast_area(ui: &mut Ui, state: &mut AppState) {
    state.clear_expired_toasts();
    if state.toasts.is_empty() {
        return;
    }

    egui::Area::new(egui::Id::new("toast_area"))
        .fixed_pos(egui::pos2(
            ui.ctx().screen_rect().max.x - 360.0,
            ui.ctx().screen_rect().min.y + 12.0,
        ))
        .show(ui.ctx(), |ui| {
            ui.set_max_width(340.0);
            let toasts: Vec<_> = state.toasts.clone();
            for toast in &toasts {
                let color = match toast.level {
                    ToastLevel::Success => theme::SUCCESS,
                    ToastLevel::Error => theme::DANGER,
                    ToastLevel::Warning => theme::WARNING,
                    ToastLevel::Info => theme::INFO,
                };
                let frame = egui::Frame::none()
                    .fill(theme::BG_SECONDARY)
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                    .rounding(egui::Rounding::same(8.0))
                    .stroke(egui::Stroke::new(1.0, color));
                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").color(color));
                        ui.label(RichText::new(&toast.text).color(theme::TEXT_PRIMARY));
                    });
                });
                ui.add_space(4.0);
            }
        });
}

pub fn render_confirm_dialog(ui: &mut Ui, state: &mut AppState) -> Option<crate::state::ConfirmAction> {
    let dialog = match &state.confirm_dialog {
        Some(d) => d.clone(),
        None => return None,
    };

    let mut result = None;
    let mut close = false;

    egui::Window::new(&dialog.title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .fixed_size([400.0, 0.0])
        .show(ui.ctx(), |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new(&dialog.message).color(theme::TEXT_PRIMARY));
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if ui
                    .button(RichText::new("Cancel").color(theme::TEXT_SECONDARY))
                    .clicked()
                {
                    close = true;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let color = if dialog.danger {
                        theme::DANGER
                    } else {
                        theme::BRAND_PRIMARY
                    };
                    let btn = egui::Button::new(
                        RichText::new(&dialog.confirm_label).color(Color32::WHITE),
                    )
                    .fill(color);
                    if ui.add(btn).clicked() {
                        result = Some(dialog.action.clone());
                        close = true;
                    }
                });
            });
        });

    if close {
        state.confirm_dialog = None;
    }
    result
}
