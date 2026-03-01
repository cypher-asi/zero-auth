use uuid::Uuid;

use crate::error::AppError;
use crate::service::mfa::MfaSetupResponse;
use crate::service::session::SessionTokens;
use crate::state::types::*;

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
    IdentityUnfrozen,
    IdentityDisabled,
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

    // MFA
    MfaSetupStarted(MfaSetupResponse),
    MfaEnabled,
    MfaDisabled,

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
    Toast(ToastLevel, String),
}
