use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum LoadStatus {
    Idle,
    Loading,
    Loaded,
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Page {
    Onboarding(OnboardingStep),
    Dashboard,
    Machines,
    Credentials,
    Mfa,
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
    Done,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecoverStep {
    EnterShards,
    Recovering,
    NewPassphrase,
    NewShardBackup,
    Done,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LoginStep {
    EnterPassphrase,
    Authenticating,
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
    pub capabilities: Vec<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct CredentialViewModel {
    pub method_type: String,
    pub method_id: String,
    pub primary: bool,
    pub verified: bool,
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
    pub frozen_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MfaState {
    Disabled,
    SetupInProgress(MfaSetupInfo),
    Enabled,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MfaSetupInfo {
    pub secret: String,
    pub qr_url: String,
    pub backup_codes: Vec<String>,
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

    pub fn display(&self) -> &str {
        match self {
            Self::SecurityIncident => "Security Incident",
            Self::SuspiciousActivity => "Suspicious Activity",
            Self::UserRequested => "User Requested",
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AppSettings {
    #[serde(default = "default_server_url")]
    pub server_url: String,
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
