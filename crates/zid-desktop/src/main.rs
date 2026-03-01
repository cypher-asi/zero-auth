mod error;
mod infra;
mod service;
mod state;
mod ui;

use eframe::egui;
use tokio::sync::mpsc;

use crate::infra::local_storage::LocalStorage;
use crate::state::actions::AppMessage;
use crate::state::types::*;
use crate::state::AppState;
use crate::ui::theme;

struct ZeroIdApp {
    state: AppState,
    rx: mpsc::UnboundedReceiver<AppMessage>,
    rt: tokio::runtime::Handle,
    refresh_scheduled: bool,
}

impl ZeroIdApp {
    fn new(
        _cc: &eframe::CreationContext<'_>,
        rt: tokio::runtime::Handle,
        tx: mpsc::UnboundedSender<AppMessage>,
        rx: mpsc::UnboundedReceiver<AppMessage>,
    ) -> Self {
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
            self.state.handle_message(msg);
            ctx.request_repaint();
        }
    }

    fn schedule_token_refresh(&mut self) {
        if self.refresh_scheduled || self.state.refresh_token.is_none() {
            return;
        }

        self.refresh_scheduled = true;
        let tx = self.state.tx.clone();
        let client = self.state.http_client.clone();
        let refresh_token = self.state.refresh_token.clone().unwrap();

        self.rt.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(780)).await;

            match crate::service::session::refresh(&client, &refresh_token).await {
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
        theme::apply_theme(ctx);
        self.process_messages(ctx);

        if self.state.is_authenticated() {
            self.schedule_token_refresh();
        } else {
            self.refresh_scheduled = false;
        }

        let is_onboarding = matches!(self.state.current_page, Page::Onboarding(_));

        if is_onboarding {
            egui::CentralPanel::default().show(ctx, |ui| {
                crate::ui::pages::onboarding::render(ui, &mut self.state, &self.rt);
            });
        } else {
            egui::SidePanel::left("sidebar")
                .exact_width(theme::SIDEBAR_WIDTH)
                .resizable(false)
                .frame(
                    egui::Frame::none()
                        .fill(theme::BG_SECONDARY)
                        .inner_margin(egui::Margin::same(0.0)),
                )
                .show(ctx, |ui| {
                    crate::ui::layout::render_sidebar(ui, &mut self.state);
                });

            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(theme::BG_PRIMARY)
                        .inner_margin(egui::Margin::same(theme::PADDING)),
                )
                .show(ctx, |ui| {
                    if let Some(frozen) = &self.state.frozen_state.clone() {
                        crate::ui::layout::render_frozen_banner(ui, frozen);
                        ui.add_space(8.0);
                    }

                    match &self.state.current_page {
                        Page::Dashboard => {
                            crate::ui::pages::render_dashboard(ui, &mut self.state, &self.rt);
                        }
                        Page::Machines => {
                            crate::ui::pages::render_machines(ui, &mut self.state, &self.rt);
                        }
                        Page::Credentials => {
                            crate::ui::pages::render_credentials(ui, &mut self.state, &self.rt);
                        }
                        Page::Mfa => {
                            crate::ui::pages::render_mfa(ui, &mut self.state, &self.rt);
                        }
                        Page::Sessions => {
                            crate::ui::pages::render_sessions(ui, &mut self.state, &self.rt);
                        }
                        Page::Namespaces => {
                            crate::ui::pages::render_namespaces(ui, &mut self.state, &self.rt);
                        }
                        Page::Security => {
                            crate::ui::pages::render_security(ui, &mut self.state, &self.rt);
                        }
                        Page::Settings => {
                            crate::ui::pages::render_settings(ui, &mut self.state, &self.rt);
                        }
                        Page::Onboarding(_) => unreachable!(),
                    }

                    let action = crate::ui::layout::render_confirm_dialog(ui, &mut self.state);
                    if let Some(action) = action {
                        self.dispatch_confirm_action(action);
                    }
                });
        }

        // Toasts rendered via Area (doesn't need a parent Ui)
        self.state.clear_expired_toasts();
        if !self.state.toasts.is_empty() {
            egui::Area::new(egui::Id::new("toast_area"))
                .fixed_pos(egui::pos2(
                    ctx.screen_rect().max.x - 360.0,
                    ctx.screen_rect().min.y + 12.0,
                ))
                .show(ctx, |ui| {
                    ui.set_max_width(340.0);
                    let toasts: Vec<_> = self.state.toasts.clone();
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
                                ui.label(
                                    egui::RichText::new("●").color(color),
                                );
                                ui.label(
                                    egui::RichText::new(&toast.text)
                                        .color(theme::TEXT_PRIMARY),
                                );
                            });
                        });
                        ui.add_space(4.0);
                    }
                });
        }
    }
}

impl ZeroIdApp {
    fn dispatch_confirm_action(&mut self, action: crate::state::ConfirmAction) {
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
            ConfirmAction::RevokeSession(_id) => {
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                self.rt.spawn(async move {
                    match crate::service::session::revoke(&client).await {
                        Ok(()) => {
                            let _ = tx.send(AppMessage::SessionRevoked);
                        }
                        Err(e) => {
                            let _ = tx.send(AppMessage::Error(e));
                        }
                    }
                });
            }
            ConfirmAction::Logout => {
                let tx = self.state.tx.clone();
                let client = self.state.http_client.clone();
                self.rt.spawn(async move {
                    let _ = crate::service::session::revoke(&client).await;
                    let _ = tx.send(AppMessage::SessionRevoked);
                });
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zid_desktop=info".into()),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    let (tx, rx) = mpsc::unbounded_channel();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("Zero-ID"),
        ..Default::default()
    };

    let handle = rt.handle().clone();

    eframe::run_native(
        "Zero-ID",
        options,
        Box::new(move |cc| {
            Ok(Box::new(ZeroIdApp::new(cc, handle, tx, rx)))
        }),
    )
}
