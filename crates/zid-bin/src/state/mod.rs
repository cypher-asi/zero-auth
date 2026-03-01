pub mod actions;
pub mod types;

use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::error::AppError;
use crate::infra::http_client::HttpClient;
use crate::infra::local_storage::LocalStorage;
use actions::AppMessage;
use types::*;

static TOAST_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct AppState {
    // Navigation
    pub current_page: Page,
    pub navigation_stack: Vec<Page>,

    // Identity
    pub identity: Option<IdentityViewModel>,
    pub identity_status: LoadStatus,

    // Machines
    pub machines: Vec<MachineViewModel>,
    pub machines_status: LoadStatus,

    // Credentials
    pub credentials: Vec<CredentialViewModel>,
    pub credentials_status: LoadStatus,

    // MFA
    pub mfa_status: MfaState,

    // Sessions
    pub current_session: Option<SessionViewModel>,
    pub active_sessions: Vec<SessionViewModel>,

    // Namespaces
    pub namespaces: Vec<NamespaceViewModel>,
    pub active_namespace: Option<uuid::Uuid>,

    // Security
    pub frozen_state: Option<FrozenInfo>,

    // Notifications
    pub toasts: Vec<ToastMessage>,

    // Auth tokens
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    // Infra
    pub http_client: HttpClient,
    pub storage: LocalStorage,
    pub tx: mpsc::UnboundedSender<AppMessage>,

    // Onboarding transient state
    pub create_passphrase: String,
    pub create_passphrase_confirm: String,
    pub create_user_shards: Vec<String>,
    pub create_shards_acknowledged: bool,

    // Login transient state
    pub login_passphrase: String,
    pub login_user_shard_hex: String,

    // Recovery transient state
    pub recovery_shard_inputs: Vec<String>,
    pub recovery_passphrase: String,
    pub recovery_passphrase_confirm: String,
    pub recovery_new_shards: Vec<String>,
    pub recovery_shards_acknowledged: bool,

    // Machine enroll dialog
    pub show_enroll_dialog: bool,
    pub enroll_passphrase: String,

    // Revoke confirm dialog
    pub revoke_confirm_machine: Option<uuid::Uuid>,

    // Credential add dialog
    pub show_add_credential_dialog: bool,
    pub add_cred_tab: usize,
    pub add_email_address: String,
    pub add_email_password: String,
    pub add_wallet_address: String,
    pub add_wallet_signature: String,

    // MFA transient
    pub mfa_setup_code: String,
    pub mfa_disable_code: String,
    pub mfa_backup_acknowledged: bool,

    // Freeze dialog
    pub show_freeze_dialog: bool,
    pub freeze_reason: FreezeReason,

    // Settings
    pub settings: AppSettings,

    // Confirm dialog
    pub confirm_dialog: Option<ConfirmDialogState>,
}

#[derive(Debug, Clone)]
pub struct ConfirmDialogState {
    pub title: String,
    pub message: String,
    pub confirm_label: String,
    pub danger: bool,
    pub action: ConfirmAction,
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    RevokeMachine(uuid::Uuid),
    RevokeCredential(String, String),
    DisableMfa,
    FreezeIdentity,
    RevokeSession(uuid::Uuid),
    Logout,
}

impl AppState {
    pub fn new(
        server_url: &str,
        storage: LocalStorage,
        tx: mpsc::UnboundedSender<AppMessage>,
    ) -> Self {
        let http_client = HttpClient::new(server_url).expect("Failed to create HTTP client");
        let has_creds = storage.has_credentials();

        let initial_page = if has_creds {
            Page::Onboarding(OnboardingStep::Login(LoginStep::EnterPassphrase))
        } else {
            Page::Onboarding(OnboardingStep::Welcome)
        };

        let settings = storage
            .read_json::<AppSettings>(&storage.settings_path())
            .unwrap_or_default();

        Self {
            current_page: initial_page,
            navigation_stack: vec![],
            identity: None,
            identity_status: LoadStatus::Idle,
            machines: vec![],
            machines_status: LoadStatus::Idle,
            credentials: vec![],
            credentials_status: LoadStatus::Idle,
            mfa_status: MfaState::Disabled,
            current_session: None,
            active_sessions: vec![],
            namespaces: vec![],
            active_namespace: None,
            frozen_state: None,
            toasts: vec![],
            access_token: None,
            refresh_token: None,
            http_client,
            storage,
            tx,
            create_passphrase: String::new(),
            create_passphrase_confirm: String::new(),
            create_user_shards: vec![],
            create_shards_acknowledged: false,
            login_passphrase: String::new(),
            login_user_shard_hex: String::new(),
            recovery_shard_inputs: vec![String::new(); 3],
            recovery_passphrase: String::new(),
            recovery_passphrase_confirm: String::new(),
            recovery_new_shards: vec![],
            recovery_shards_acknowledged: false,
            show_enroll_dialog: false,
            enroll_passphrase: String::new(),
            revoke_confirm_machine: None,
            show_add_credential_dialog: false,
            add_cred_tab: 0,
            add_email_address: String::new(),
            add_email_password: String::new(),
            add_wallet_address: String::new(),
            add_wallet_signature: String::new(),
            mfa_setup_code: String::new(),
            mfa_disable_code: String::new(),
            mfa_backup_acknowledged: false,
            show_freeze_dialog: false,
            freeze_reason: FreezeReason::UserRequested,
            settings,
            confirm_dialog: None,
        }
    }

    pub fn navigate(&mut self, page: Page) {
        self.navigation_stack.push(self.current_page.clone());
        self.current_page = page;
    }

    pub fn go_back(&mut self) {
        if let Some(prev) = self.navigation_stack.pop() {
            self.current_page = prev;
        }
    }

    pub fn add_toast(&mut self, level: ToastLevel, text: String) {
        let id = TOAST_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.toasts.push(ToastMessage {
            id,
            level,
            text,
            created_at: std::time::Instant::now(),
        });
    }

    pub fn clear_expired_toasts(&mut self) {
        self.toasts.retain(|t| !t.is_expired());
    }

    pub fn handle_message(&mut self, msg: AppMessage) {
        match msg {
            AppMessage::IdentityCreated {
                identity,
                session,
                user_shard_hexes,
                stored_credentials,
                stored_session,
            } => {
                let cred_path = self.storage.credentials_path();
                let _ = self.storage.write_json(&cred_path, &stored_credentials);
                let sess_path = self.storage.session_path();
                let _ = self.storage.write_json(&sess_path, &stored_session);

                self.identity = Some(identity);
                self.identity_status = LoadStatus::Loaded;
                self.access_token = Some(session.access_token.clone());
                self.refresh_token = Some(session.refresh_token.clone());
                self.http_client
                    .set_access_token(Some(session.access_token.clone()));
                self.current_session =
                    Some(crate::service::session::tokens_to_view_model(&session));
                self.create_user_shards = user_shard_hexes;
                self.current_page =
                    Page::Onboarding(OnboardingStep::CreateIdentity(CreateStep::ShardBackup));
            }

            AppMessage::IdentityLoaded(identity) => {
                let frozen = identity.frozen;
                if frozen {
                    self.frozen_state = Some(FrozenInfo {
                        reason: identity
                            .freeze_reason
                            .clone()
                            .unwrap_or_else(|| "Unknown".into()),
                        frozen_at: identity.updated_at.clone(),
                    });
                }
                self.identity = Some(identity);
                self.identity_status = LoadStatus::Loaded;
            }

            AppMessage::LoginSuccess {
                session,
                identity,
                stored_session,
            } => {
                let sess_path = self.storage.session_path();
                let _ = self.storage.write_json(&sess_path, &stored_session);

                self.identity = Some(identity);
                self.identity_status = LoadStatus::Loaded;
                self.access_token = Some(session.access_token.clone());
                self.refresh_token = Some(session.refresh_token.clone());
                self.http_client
                    .set_access_token(Some(session.access_token.clone()));
                self.current_session =
                    Some(crate::service::session::tokens_to_view_model(&session));
                self.current_page = Page::Dashboard;
                self.login_passphrase.clear();
                self.login_user_shard_hex.clear();
                self.add_toast(ToastLevel::Success, "Logged in successfully".into());
            }

            AppMessage::TokenRefreshed {
                access_token,
                refresh_token,
                expires_at,
            } => {
                self.access_token = Some(access_token.clone());
                self.refresh_token = Some(refresh_token.clone());
                self.http_client.set_access_token(Some(access_token));
                if let Some(sess) = &mut self.current_session {
                    sess.expires_at = expires_at;
                }
                let sess_path = self.storage.session_path();
                if let (Some(at), Some(rt)) = (&self.access_token, &self.refresh_token) {
                    let stored = StoredSession {
                        access_token: at.clone(),
                        refresh_token: rt.clone(),
                        session_id: self
                            .current_session
                            .as_ref()
                            .map(|s| s.session_id)
                            .unwrap_or_default(),
                        expires_at: self
                            .current_session
                            .as_ref()
                            .map(|s| s.expires_at.clone())
                            .unwrap_or_default(),
                    };
                    let _ = self.storage.write_json(&sess_path, &stored);
                }
            }

            AppMessage::SessionRevoked => {
                self.access_token = None;
                self.refresh_token = None;
                self.http_client.set_access_token(None);
                self.current_session = None;
                let _ = self.storage.delete_file(&self.storage.session_path());
                self.current_page =
                    Page::Onboarding(OnboardingStep::Login(LoginStep::EnterPassphrase));
                self.add_toast(ToastLevel::Info, "Logged out".into());
            }

            AppMessage::MachinesLoaded(machines) => {
                self.machines = machines;
                self.machines_status = LoadStatus::Loaded;
            }

            AppMessage::MachineEnrolled(machine) => {
                self.machines.push(machine);
                self.show_enroll_dialog = false;
                self.enroll_passphrase.clear();
                self.add_toast(ToastLevel::Success, "Machine enrolled successfully".into());
            }

            AppMessage::MachineRevoked(id) => {
                self.machines.retain(|m| m.machine_id != id);
                self.revoke_confirm_machine = None;
                self.confirm_dialog = None;
                self.add_toast(ToastLevel::Success, "Machine revoked".into());
            }

            AppMessage::CredentialsLoaded(creds) => {
                self.credentials = creds;
                self.credentials_status = LoadStatus::Loaded;
            }

            AppMessage::CredentialLinked(cred) => {
                self.credentials.push(cred);
                self.show_add_credential_dialog = false;
                self.add_email_address.clear();
                self.add_email_password.clear();
                self.add_toast(ToastLevel::Success, "Credential linked".into());
            }

            AppMessage::CredentialRevoked {
                method_type,
                method_id,
            } => {
                self.credentials
                    .retain(|c| !(c.method_type == method_type && c.method_id == method_id));
                self.confirm_dialog = None;
                self.add_toast(ToastLevel::Success, "Credential revoked".into());
            }

            AppMessage::CredentialPrimarySet {
                method_type,
                method_id,
            } => {
                for c in &mut self.credentials {
                    c.primary = c.method_type == method_type && c.method_id == method_id;
                }
                self.add_toast(ToastLevel::Success, "Primary credential updated".into());
            }

            AppMessage::MfaSetupStarted(setup) => {
                self.mfa_status = MfaState::SetupInProgress(MfaSetupInfo {
                    secret: setup.secret,
                    qr_url: setup.qr_url,
                    backup_codes: setup.backup_codes,
                });
            }

            AppMessage::MfaEnabled => {
                self.mfa_status = MfaState::Enabled;
                self.mfa_setup_code.clear();
                self.add_toast(ToastLevel::Success, "MFA enabled".into());
            }

            AppMessage::MfaDisabled => {
                self.mfa_status = MfaState::Disabled;
                self.mfa_disable_code.clear();
                self.confirm_dialog = None;
                self.add_toast(ToastLevel::Info, "MFA disabled".into());
            }

            AppMessage::IdentityFrozen => {
                if let Some(id) = &mut self.identity {
                    id.frozen = true;
                    id.status = "Frozen".into();
                }
                self.frozen_state = Some(FrozenInfo {
                    reason: self.freeze_reason.as_str().to_string(),
                    frozen_at: chrono::Utc::now().to_rfc3339(),
                });
                self.show_freeze_dialog = false;
                self.add_toast(ToastLevel::Warning, "Identity frozen".into());
            }

            AppMessage::IdentityUnfrozen => {
                if let Some(id) = &mut self.identity {
                    id.frozen = false;
                    id.status = "Active".into();
                }
                self.frozen_state = None;
                self.add_toast(ToastLevel::Success, "Identity unfrozen".into());
            }

            AppMessage::IdentityDisabled => {
                if let Some(id) = &mut self.identity {
                    id.status = "Disabled".into();
                }
                self.add_toast(ToastLevel::Warning, "Identity disabled".into());
            }

            AppMessage::IdentityEnabled => {
                if let Some(id) = &mut self.identity {
                    id.status = "Active".into();
                }
                self.add_toast(ToastLevel::Success, "Identity enabled".into());
            }

            AppMessage::RecoveryComplete {
                identity,
                session,
                user_shard_hexes,
                stored_credentials,
                stored_session,
            } => {
                let cred_path = self.storage.credentials_path();
                let _ = self.storage.write_json(&cred_path, &stored_credentials);
                let sess_path = self.storage.session_path();
                let _ = self.storage.write_json(&sess_path, &stored_session);

                self.identity = Some(identity);
                self.identity_status = LoadStatus::Loaded;
                self.access_token = Some(session.access_token.clone());
                self.refresh_token = Some(session.refresh_token.clone());
                self.http_client
                    .set_access_token(Some(session.access_token.clone()));
                self.current_session =
                    Some(crate::service::session::tokens_to_view_model(&session));
                self.recovery_new_shards = user_shard_hexes;
                self.current_page = Page::Onboarding(OnboardingStep::RecoverIdentity(
                    RecoverStep::NewShardBackup,
                ));
            }

            AppMessage::OAuthUrlReady(url) => {
                let _ = crate::infra::os_integration::open_browser(&url);
                self.add_toast(
                    ToastLevel::Info,
                    "Redirecting to provider in your browser...".into(),
                );
            }

            AppMessage::Navigate(page) => {
                self.navigate(page);
            }

            AppMessage::Error(err) => {
                match &err {
                    AppError::TokenFamilyRevoked => {
                        self.access_token = None;
                        self.refresh_token = None;
                        self.http_client.set_access_token(None);
                        self.current_session = None;
                        self.current_page = Page::Onboarding(OnboardingStep::Login(
                            LoginStep::EnterPassphrase,
                        ));
                    }
                    AppError::SessionExpired => {
                        self.identity_status = LoadStatus::Error(err.to_string());
                    }
                    _ => {}
                }
                self.add_toast(ToastLevel::Error, err.to_string());
            }

            AppMessage::Toast(level, text) => {
                self.add_toast(level, text);
            }
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.access_token.is_some()
    }
}
