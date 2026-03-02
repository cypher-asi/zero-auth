use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::error::AppError;
use crate::infra::http_client::HttpClient;
use crate::infra::local_storage::LocalStorage;
use crate::service::session::SessionTokens;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum LoadStatus {
    Idle,
    Loading,
    Loaded,
    #[allow(dead_code)]
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Page {
    Onboarding(OnboardingStep),
    Dashboard,
    Machines,
    Credentials,
    Sessions,
    Namespaces,
    Security,
    Settings,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OnboardingStep {
    Welcome,
    CreateIdentity(CreateStep),
    RecoverIdentity(RecoverStep),
    Login(LoginStep),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateStep {
    Generating,
    Passphrase,
    ShardBackup,
    #[allow(dead_code)]
    Done,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecoverStep {
    EnterShards,
    Recovering,
    NewPassphrase,
    NewShardBackup,
    #[allow(dead_code)]
    Done,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LoginStep {
    EnterPassphrase,
    Authenticating,
}

#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub name: String,
    pub has_credentials: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct IdentityViewModel {
    pub identity_id: Uuid,
    pub did: String,
    pub tier: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub frozen: bool,
    pub freeze_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MachineViewModel {
    pub machine_id: Uuid,
    pub device_name: String,
    pub device_platform: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked: bool,
    pub key_scheme: String,
    #[allow(dead_code)]
    pub capabilities: Vec<String>,
    #[allow(dead_code)]
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct CredentialViewModel {
    pub method_type: String,
    pub method_id: String,
    pub primary: bool,
    pub verified: bool,
    #[allow(dead_code)]
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct SessionViewModel {
    pub session_id: Uuid,
    pub machine_id: Option<Uuid>,
    pub expires_at: String,
    pub is_current: bool,
}

#[derive(Debug, Clone)]
pub struct NamespaceViewModel {
    pub namespace_id: Uuid,
    pub name: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug, Clone)]
pub struct FrozenInfo {
    pub reason: String,
    #[allow(dead_code)]
    pub frozen_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToastLevel {
    Success,
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub struct ToastMessage {
    #[allow(dead_code)]
    pub id: u64,
    pub level: ToastLevel,
    pub text: String,
    pub created_at: std::time::Instant,
}

impl ToastMessage {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > std::time::Duration::from_secs(5)
    }
}

#[derive(Debug, Clone)]
pub enum FreezeReason {
    SecurityIncident,
    SuspiciousActivity,
    UserRequested,
}

impl FreezeReason {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SecurityIncident => "SecurityIncident",
            Self::SuspiciousActivity => "SuspiciousActivity",
            Self::UserRequested => "UserRequested",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredCredentials {
    #[serde(with = "hex_serde")]
    pub encrypted_shard_1: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub encrypted_shard_2: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub shards_nonce: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub kek_salt: Vec<u8>,
    #[serde(with = "hex_serde", default)]
    pub encrypted_machine_signing_seed: Vec<u8>,
    #[serde(with = "hex_serde", default)]
    pub machine_key_nonce: Vec<u8>,
    #[serde(with = "hex_serde", default)]
    pub neural_key_commitment: Vec<u8>,
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub identity_signing_public_key: String,
    pub machine_signing_public_key: String,
    pub machine_encryption_public_key: String,
    pub device_name: String,
    pub device_platform: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredSession {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppSettings {
    #[serde(default = "default_server_url")]
    pub server_url: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
        }
    }
}

fn default_server_url() -> String {
    "http://127.0.0.1:9999".to_string()
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Messages sent from background tasks to the UI thread via mpsc.
#[derive(Debug)]
pub enum AppMessage {
    // Identity
    IdentityCreated {
        identity: IdentityViewModel,
        session: SessionTokens,
        user_shard_hexes: Vec<String>,
        stored_credentials: StoredCredentials,
        stored_session: StoredSession,
    },
    IdentityLoaded(IdentityViewModel),
    IdentityFrozen,
    #[allow(dead_code)]
    IdentityUnfrozen,
    #[allow(dead_code)]
    IdentityDisabled,
    #[allow(dead_code)]
    IdentityEnabled,

    // Auth / Session
    LoginSuccess {
        session: SessionTokens,
        identity: IdentityViewModel,
        stored_session: StoredSession,
    },
    TokenRefreshed {
        access_token: String,
        refresh_token: String,
        expires_at: String,
    },
    SessionRevoked,

    // Machines
    MachinesLoaded(Vec<MachineViewModel>),
    MachineEnrolled(MachineViewModel),
    MachineRevoked(Uuid),

    // Credentials
    CredentialsLoaded(Vec<CredentialViewModel>),
    CredentialLinked(CredentialViewModel),
    CredentialRevoked {
        method_type: String,
        method_id: String,
    },
    CredentialPrimarySet {
        method_type: String,
        method_id: String,
    },

    // Recovery
    RecoveryComplete {
        identity: IdentityViewModel,
        session: SessionTokens,
        user_shard_hexes: Vec<String>,
        stored_credentials: StoredCredentials,
        stored_session: StoredSession,
    },

    // OAuth
    OAuthUrlReady(String),

    // Navigation
    Navigate(Page),

    // Error
    Error(AppError),

    // Profiles
    ProfileCreated(String),
    ProfileSwitched(String),
    ProfileDeleted(String),

    // Toast
    #[allow(dead_code)]
    Toast(ToastLevel, String),
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

static TOAST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Maps nav sidebar sections to pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavSection {
    Dashboard,
    Machines,
    Credentials,
    Sessions,
    Namespaces,
    Security,
    Settings,
}

impl NavSection {
    pub const ALL: [NavSection; 7] = [
        NavSection::Dashboard,
        NavSection::Machines,
        NavSection::Credentials,
        NavSection::Sessions,
        NavSection::Namespaces,
        NavSection::Security,
        NavSection::Settings,
    ];

    pub fn label(self) -> &'static str {
        match self {
            NavSection::Dashboard => "Dashboard",
            NavSection::Machines => "Machines",
            NavSection::Credentials => "Credentials",
            NavSection::Sessions => "Sessions",
            NavSection::Namespaces => "Namespaces",
            NavSection::Security => "Security",
            NavSection::Settings => "Settings",
        }
    }

    pub fn to_page(self) -> Page {
        match self {
            NavSection::Dashboard => Page::Dashboard,
            NavSection::Machines => Page::Machines,
            NavSection::Credentials => Page::Credentials,
            NavSection::Sessions => Page::Sessions,
            NavSection::Namespaces => Page::Namespaces,
            NavSection::Security => Page::Security,
            NavSection::Settings => Page::Settings,
        }
    }
}

// ---------------------------------------------------------------------------
// App State
// ---------------------------------------------------------------------------

pub struct AppState {
    // Navigation
    pub current_page: Page,
    pub navigation_stack: Vec<Page>,
    pub nav_section: NavSection,

    // Identity
    pub identity: Option<IdentityViewModel>,
    pub identity_status: LoadStatus,

    // Machines
    pub machines: Vec<MachineViewModel>,
    pub machines_status: LoadStatus,

    // Credentials
    pub credentials: Vec<CredentialViewModel>,
    pub credentials_status: LoadStatus,

    // Sessions
    pub current_session: Option<SessionViewModel>,
    #[allow(dead_code)]
    pub active_sessions: Vec<SessionViewModel>,

    // Namespaces
    pub namespaces: Vec<NamespaceViewModel>,
    #[allow(dead_code)]
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
    pub enroll_machine_name: String,
    pub enroll_passphrase: String,
    pub enroll_user_shard_hex: String,

    // Revoke confirm dialog
    pub revoke_confirm_machine: Option<uuid::Uuid>,

    // Credential add dialog
    pub show_add_credential_dialog: bool,
    pub add_cred_tab: usize,
    pub add_email_address: String,
    pub add_email_password: String,
    pub add_wallet_address: String,
    pub add_wallet_signature: String,

    // Freeze dialog
    pub show_freeze_dialog: bool,
    pub freeze_reason: FreezeReason,

    // Settings
    pub settings: AppSettings,

    // Profiles
    pub active_profile: String,
    pub profiles: Vec<ProfileInfo>,

    // Profile UI transient state
    pub new_profile_name: String,

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
    FreezeIdentity,
    #[allow(dead_code)]
    RevokeSession(uuid::Uuid),
    DeleteProfile(String),
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

        let active_profile = storage.active_profile_name().to_string();
        let profiles = load_profile_list(&storage);

        Self {
            current_page: initial_page,
            navigation_stack: vec![],
            nav_section: NavSection::Dashboard,
            identity: None,
            identity_status: LoadStatus::Idle,
            machines: vec![],
            machines_status: LoadStatus::Idle,
            credentials: vec![],
            credentials_status: LoadStatus::Idle,
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
            enroll_machine_name: String::new(),
            enroll_passphrase: String::new(),
            enroll_user_shard_hex: String::new(),
            revoke_confirm_machine: None,
            show_add_credential_dialog: false,
            add_cred_tab: 0,
            add_email_address: String::new(),
            add_email_password: String::new(),
            add_wallet_address: String::new(),
            add_wallet_signature: String::new(),
            show_freeze_dialog: false,
            freeze_reason: FreezeReason::UserRequested,
            settings,
            active_profile,
            profiles,
            new_profile_name: String::new(),
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
                self.enroll_machine_name.clear();
                self.enroll_passphrase.clear();
                self.enroll_user_shard_hex.clear();
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

            AppMessage::ProfileCreated(name) => {
                self.profiles = load_profile_list(&self.storage);
                self.new_profile_name.clear();
                self.add_toast(
                    ToastLevel::Success,
                    format!("Profile '{}' created", name),
                );
            }

            AppMessage::ProfileSwitched(name) => {
                if let Err(e) = self.storage.switch_profile(&name) {
                    self.add_toast(ToastLevel::Error, e.to_string());
                    return;
                }
                self.active_profile = name.clone();
                self.access_token = None;
                self.refresh_token = None;
                self.http_client.set_access_token(None);
                self.current_session = None;
                self.identity = None;
                self.identity_status = LoadStatus::Idle;
                self.machines.clear();
                self.credentials.clear();
                self.frozen_state = None;
                self.profiles = load_profile_list(&self.storage);

                let settings = self
                    .storage
                    .read_json::<AppSettings>(&self.storage.settings_path())
                    .unwrap_or_default();
                self.settings = settings;

                if self.storage.has_credentials() {
                    self.current_page =
                        Page::Onboarding(OnboardingStep::Login(LoginStep::EnterPassphrase));
                } else {
                    self.current_page = Page::Onboarding(OnboardingStep::Welcome);
                }
                self.navigation_stack.clear();
                self.add_toast(
                    ToastLevel::Success,
                    format!("Switched to profile: {}", name),
                );
            }

            AppMessage::ProfileDeleted(name) => {
                self.profiles = load_profile_list(&self.storage);
                self.add_toast(
                    ToastLevel::Success,
                    format!("Profile '{}' deleted", name),
                );
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
                        self.access_token = None;
                        self.refresh_token = None;
                        self.http_client.set_access_token(None);
                        self.current_session = None;
                        self.current_page = Page::Onboarding(OnboardingStep::Login(
                            LoginStep::EnterPassphrase,
                        ));
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

fn load_profile_list(storage: &LocalStorage) -> Vec<ProfileInfo> {
    let active = storage.active_profile_name().to_string();
    storage
        .list_profiles()
        .unwrap_or_else(|_| vec![active.clone()])
        .into_iter()
        .map(|name| {
            let is_active = name == active;
            let has_credentials = if is_active {
                storage.has_credentials()
            } else {
                LocalStorage::with_profile(&name)
                    .map(|s| s.has_credentials())
                    .unwrap_or(false)
            };
            ProfileInfo {
                name,
                has_credentials,
                is_active,
            }
        })
        .collect()
}
