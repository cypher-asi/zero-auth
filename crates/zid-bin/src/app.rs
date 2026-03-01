use eframe::egui;
use tokio::sync::mpsc;

use crate::components::buttons::title_bar_icon;
use crate::components::layout as comp_layout;
use crate::components::tokens::{colors, font_size, spacing};
use crate::infra::local_storage::LocalStorage;
use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::{AppState, NavSection};

pub struct ZeroIdApp {
    pub state: AppState,
    rx: mpsc::UnboundedReceiver<AppMessage>,
    rt: tokio::runtime::Handle,
    refresh_scheduled: bool,
}

impl ZeroIdApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        rt: tokio::runtime::Handle,
        tx: mpsc::UnboundedSender<AppMessage>,
        rx: mpsc::UnboundedReceiver<AppMessage>,
    ) -> Self {
        crate::configure_theme(&cc.egui_ctx);

        let storage = LocalStorage::new().expect("Failed to initialize local storage");

        let settings = storage
            .read_json::<AppSettings>(&storage.settings_path())
            .unwrap_or_default();

        let state = AppState::new(&settings.server_url, storage, tx);

        Self {
            state,
            rx,
            rt,
            refresh_scheduled: false,
        }
    }

    fn process_messages(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            if matches!(&msg, AppMessage::TokenRefreshed { .. }) {
                self.refresh_scheduled = false;
            }
            self.state.handle_message(msg);
            ctx.request_repaint();
        }
    }

    fn schedule_token_refresh(&mut self) {
        if self.refresh_scheduled || self.state.refresh_token.is_none() {
            return;
        }

        let (session_id, machine_id) = match &self.state.current_session {
            Some(s) => (s.session_id, s.machine_id.unwrap_or_default()),
            None => return,
        };

        self.refresh_scheduled = true;
        let tx = self.state.tx.clone();
        let client = self.state.http_client.clone();
        let refresh_token = self.state.refresh_token.clone().unwrap();

        self.rt.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(780)).await;

            match crate::service::session::refresh(&client, &refresh_token, session_id, machine_id)
                .await
            {
                Ok(resp) => {
                    let _ = tx.send(AppMessage::TokenRefreshed {
                        access_token: resp.access_token,
                        refresh_token: resp.refresh_token,
                        expires_at: resp.expires_at,
                    });
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e));
                }
            }
        });
    }
}

impl eframe::App for ZeroIdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_messages(ctx);

        if self.state.is_authenticated() {
            self.schedule_token_refresh();
        } else {
            self.refresh_scheduled = false;
        }

        let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
        let on_resize_edge = if !maximized {
            Self::handle_resize_edges(ctx)
        } else {
            false
        };

        let is_onboarding = matches!(self.state.current_page, Page::Onboarding(_));

        if is_onboarding {
            Self::render_title_bar_shell(ctx, "pre_auth_title", maximized, on_resize_edge, |ui| {
                ui.label(
                    egui::RichText::new("ZERO-ID")
                        .strong()
                        .size(font_size::ACTION)
                        .color(colors::TEXT_HEADING),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    Self::render_window_buttons(ui, maximized);
                });
            });
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::new()
                        .fill(colors::SURFACE)
                        .inner_margin(egui::Margin::same(spacing::XL as i8)),
                )
                .show(ctx, |ui| {
                    crate::setup::render(ui, &mut self.state, &self.rt);
                });
        } else {
            Self::render_title_bar_shell(ctx, "title_bar", maximized, on_resize_edge, |ui| {
                ui.label(
                    egui::RichText::new("ZERO-ID")
                        .strong()
                        .size(font_size::ACTION)
                        .color(colors::TEXT_HEADING),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    Self::render_window_buttons(ui, maximized);
                });
            });
            self.render_authenticated(ctx);
        }

        Self::render_window_border(ctx, maximized);

        self.state.clear_expired_toasts();
        comp_layout::toast_area(ctx, &self.state.toasts);
    }
}

impl ZeroIdApp {
    fn render_title_bar_shell(
        ctx: &egui::Context,
        panel_id: &'static str,
        maximized: bool,
        on_resize_edge: bool,
        content: impl FnOnce(&mut egui::Ui),
    ) {
        egui::TopBottomPanel::top(panel_id)
            .frame(comp_layout::title_bar_frame())
            .show(ctx, |ui| {
                let title_bar_rect = ui.max_rect();
                let title_resp = ui.interact(
                    title_bar_rect,
                    egui::Id::new(panel_id),
                    egui::Sense::click_and_drag(),
                );
                if !on_resize_edge && title_resp.drag_started_by(egui::PointerButton::Primary) {
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
                if title_resp.double_clicked() {
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                }

                ui.visuals_mut().widgets.active = ui.visuals().widgets.hovered;
                ui.visuals_mut().selection.bg_fill = egui::Color32::TRANSPARENT;
                ui.visuals_mut().selection.stroke =
                    egui::Stroke::new(1.0, egui::Color32::WHITE);
                ui.visuals_mut().widgets.active.fg_stroke =
                    egui::Stroke::new(1.0, egui::Color32::WHITE);

                ui.horizontal(content);

                Self::handle_title_bar_drag(ui, &title_resp, title_bar_rect, on_resize_edge);
            });
    }

    fn render_window_buttons(ui: &mut egui::Ui, maximized: bool) {
        if title_bar_icon(ui, egui_phosphor::regular::X, false).clicked() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let max_icon = if maximized {
            egui_phosphor::regular::CORNERS_IN
        } else {
            egui_phosphor::regular::CORNERS_OUT
        };
        if title_bar_icon(ui, max_icon, false).clicked() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        }
        if title_bar_icon(ui, egui_phosphor::regular::MINUS, false).clicked() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
    }

    fn handle_title_bar_drag(
        ui: &egui::Ui,
        title_resp: &egui::Response,
        title_bar_rect: egui::Rect,
        on_resize_edge: bool,
    ) {
        if on_resize_edge || title_resp.double_clicked() {
            return;
        }
        let drag = ui.input(
            |i| match (i.pointer.press_origin(), i.pointer.hover_pos()) {
                (Some(origin), Some(current)) => Some((origin, current)),
                _ => None,
            },
        );
        if let Some((press_origin, current)) = drag {
            if title_bar_rect.contains(press_origin) && press_origin.distance(current) > 4.0 {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
        }
    }

    fn handle_resize_edges(ctx: &egui::Context) -> bool {
        const BORDER: f32 = 6.0;
        let screen = ctx.screen_rect();
        let Some(pos) = ctx.input(|i| i.pointer.hover_pos()) else {
            return false;
        };

        let left = pos.x - screen.left() < BORDER;
        let right = screen.right() - pos.x < BORDER;
        let top = pos.y - screen.top() < BORDER;
        let bottom = screen.bottom() - pos.y < BORDER;

        use egui::viewport::ResizeDirection;
        let dir = match (left, right, top, bottom) {
            (true, _, true, _) => Some(ResizeDirection::NorthWest),
            (_, true, true, _) => Some(ResizeDirection::NorthEast),
            (true, _, _, true) => Some(ResizeDirection::SouthWest),
            (_, true, _, true) => Some(ResizeDirection::SouthEast),
            (true, _, _, _) => Some(ResizeDirection::West),
            (_, true, _, _) => Some(ResizeDirection::East),
            (_, _, true, _) => Some(ResizeDirection::North),
            (_, _, _, true) => Some(ResizeDirection::South),
            _ => None,
        };

        let Some(dir) = dir else { return false };

        let cursor = match dir {
            ResizeDirection::North | ResizeDirection::South => egui::CursorIcon::ResizeVertical,
            ResizeDirection::East | ResizeDirection::West => egui::CursorIcon::ResizeHorizontal,
            ResizeDirection::NorthWest | ResizeDirection::SouthEast => {
                egui::CursorIcon::ResizeNwSe
            }
            ResizeDirection::NorthEast | ResizeDirection::SouthWest => {
                egui::CursorIcon::ResizeNeSw
            }
        };
        ctx.set_cursor_icon(cursor);

        if ctx.input(|i| i.pointer.button_pressed(egui::PointerButton::Primary)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
        }

        true
    }

    fn render_window_border(ctx: &egui::Context, maximized: bool) {
        if !maximized {
            let fg = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("window_border"),
            ));
            fg.rect_stroke(
                ctx.screen_rect(),
                0.0,
                egui::Stroke::new(1.0, colors::BORDER),
                egui::StrokeKind::Outside,
            );
        }
    }

    fn render_authenticated(&mut self, ctx: &egui::Context) {
        render_nav_panel(ctx, &mut self.state);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(colors::SURFACE)
                    .inner_margin(egui::Margin::same(spacing::XL as i8)),
            )
            .show(ctx, |ui| {
                if let Some(frozen) = &self.state.frozen_state.clone() {
                    comp_layout::frozen_banner(ui, &frozen.reason);
                    ui.add_space(spacing::MD);
                }

                crate::render::render_page(ui, &mut self.state, &self.rt);

                if let Some(dialog) = &self.state.confirm_dialog.clone() {
                    let (confirmed, closed) = comp_layout::confirm_dialog(ui, dialog);
                    if confirmed {
                        self.dispatch_confirm_action(dialog.action.clone());
                    }
                    if closed {
                        self.state.confirm_dialog = None;
                    }
                }
            });
    }

    pub fn dispatch_confirm_action(&mut self, action: crate::state::ConfirmAction) {
        use crate::state::ConfirmAction;

        match action {
            ConfirmAction::RevokeMachine(id) => {
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                self.rt.spawn(async move {
                    match crate::service::machine::revoke(&client, &id).await {
                        Ok(()) => {
                            let _ = tx.send(AppMessage::MachineRevoked(id));
                        }
                        Err(e) => {
                            let _ = tx.send(AppMessage::Error(e));
                        }
                    }
                });
            }
            ConfirmAction::RevokeCredential(method_type, method_id) => {
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                let mt = method_type.clone();
                let mi = method_id.clone();
                self.rt.spawn(async move {
                    match crate::service::credentials::revoke(&client, &mt, &mi).await {
                        Ok(()) => {
                            let _ = tx.send(AppMessage::CredentialRevoked {
                                method_type: mt,
                                method_id: mi,
                            });
                        }
                        Err(e) => {
                            let _ = tx.send(AppMessage::Error(e));
                        }
                    }
                });
            }
            ConfirmAction::DisableMfa => {
                let code = self.state.mfa_disable_code.clone();
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                self.rt.spawn(async move {
                    match crate::service::mfa::disable(&client, &code).await {
                        Ok(()) => {
                            let _ = tx.send(AppMessage::MfaDisabled);
                        }
                        Err(e) => {
                            let _ = tx.send(AppMessage::Error(e));
                        }
                    }
                });
            }
            ConfirmAction::FreezeIdentity => {
                let reason = self.state.freeze_reason.clone();
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                self.rt.spawn(async move {
                    match crate::service::identity::freeze(&client, reason).await {
                        Ok(()) => {
                            let _ = tx.send(AppMessage::IdentityFrozen);
                        }
                        Err(e) => {
                            let _ = tx.send(AppMessage::Error(e));
                        }
                    }
                });
            }
            ConfirmAction::RevokeSession(session_id) => {
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                self.rt.spawn(async move {
                    match crate::service::session::revoke(&client, session_id).await {
                        Ok(()) => {
                            let _ = tx.send(AppMessage::SessionRevoked);
                        }
                        Err(e) => {
                            let _ = tx.send(AppMessage::Error(e));
                        }
                    }
                });
            }
            ConfirmAction::DeleteProfile(name) => {
                match self.state.storage.delete_profile(&name) {
                    Ok(()) => {
                        let _ = self.state.tx.send(AppMessage::ProfileDeleted(name));
                    }
                    Err(e) => {
                        let _ = self.state.tx.send(AppMessage::Error(e));
                    }
                }
            }
            ConfirmAction::Logout => {
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                let session_id = self.state.current_session.as_ref().map(|s| s.session_id);
                self.rt.spawn(async move {
                    if let Some(sid) = session_id {
                        let _ = crate::service::session::revoke(&client, sid).await;
                    }
                    let _ = tx.send(AppMessage::SessionRevoked);
                });
            }
        }
    }
}

fn render_nav_panel(ctx: &egui::Context, state: &mut AppState) {
    egui::SidePanel::left("nav")
        .exact_width(crate::components::tokens::NAV_WIDTH)
        .resizable(false)
        .show_separator_line(false)
        .frame(
            egui::Frame::new()
                .fill(colors::PANEL_BG)
                .inner_margin(egui::Margin::ZERO),
        )
        .show(ctx, |ui| {
            let panel_rect = ui.max_rect();

            ui.painter().rect_stroke(
                panel_rect,
                0.0,
                egui::Stroke::new(1.0, colors::BORDER),
                egui::StrokeKind::Outside,
            );

            ui.add_space(spacing::XL);

            let mut active_y = 0.0f32;
            let mut active_h = 0.0f32;

            for section in NavSection::ALL {
                let is_active = state.nav_section == section;
                let row_height = ui.spacing().interact_size.y;
                let (row_rect, response) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), row_height),
                    egui::Sense::click(),
                );

                let text_color = if is_active || response.hovered() {
                    egui::Color32::WHITE
                } else {
                    egui::Color32::from_gray(180)
                };

                let text_pos = egui::pos2(
                    row_rect.min.x + spacing::LG,
                    row_rect.center().y - font_size::BODY / 2.0,
                );

                ui.painter().text(
                    text_pos,
                    egui::Align2::LEFT_TOP,
                    section.label().to_uppercase(),
                    egui::FontId::proportional(font_size::BODY),
                    text_color,
                );

                if is_active {
                    active_y = row_rect.min.y;
                    active_h = row_rect.height();
                }

                if response.clicked() {
                    state.nav_section = section;
                    state.current_page = section.to_page();
                }
            }

            let target_y = active_y;
            let anim_y = ui.ctx().animate_value_with_time(
                egui::Id::new("nav_indicator_y"),
                target_y,
                0.15,
            );
            let anim_h = ui.ctx().animate_value_with_time(
                egui::Id::new("nav_indicator_h"),
                active_h,
                0.15,
            );

            let indicator_rect = egui::Rect::from_min_size(
                egui::pos2(panel_rect.min.x, anim_y),
                egui::vec2(2.0, anim_h),
            );
            ui.painter()
                .rect_filled(indicator_rect, 0.0, egui::Color32::WHITE);

            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.add_space(spacing::MD);

                if let Some(identity) = &state.identity {
                    let did_short = if identity.did.len() > 20 {
                        format!(
                            "{}...{}",
                            &identity.did[..10],
                            &identity.did[identity.did.len() - 6..]
                        )
                    } else if identity.did.is_empty() {
                        format!("{}", &identity.identity_id.to_string()[..8])
                    } else {
                        identity.did.clone()
                    };

                    ui.horizontal(|ui| {
                        ui.add_space(spacing::LG);
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(did_short)
                                    .size(font_size::SMALL)
                                    .color(colors::TEXT_MUTED),
                            );
                            ui.label(
                                egui::RichText::new(&identity.tier)
                                    .size(font_size::SMALL)
                                    .color(colors::TEXT_SECONDARY),
                            );
                        });
                    });
                }
            });
        });
}
