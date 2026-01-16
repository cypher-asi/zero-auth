//! OAuth types for token responses and user information.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-export OAuthProvider from parent types module
pub use crate::types::OAuthProvider;

/// OAuth token response from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    /// Access token from OAuth provider
    pub access_token: String,
    /// Token type (typically "Bearer")
    pub token_type: String,
    /// Optional refresh token for obtaining new access tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Token expiry time in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Optional OIDC ID token (for OIDC providers like Google)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// OAuth user info from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    /// Provider's user ID
    pub id: String,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub name: Option<String>,
    /// Profile picture URL
    pub picture: Option<String>,
}

/// OAuth state for CSRF protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// State parameter (random, for CSRF protection)
    pub state: String,
    /// Nonce parameter (random, for OIDC replay protection)
    pub nonce: String,
    /// Identity ID (if linking to existing identity)
    pub identity_id: Option<Uuid>,
    /// OAuth provider
    pub provider: OAuthProvider,
    /// Created timestamp
    pub created_at: u64,
    /// Expiry timestamp (10 minutes)
    pub expires_at: u64,
    /// Whether state has been used
    pub used: bool,
}

/// OAuth/OIDC link (stored credential)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthLink {
    /// Link ID
    pub link_id: Uuid,
    /// Identity ID
    pub identity_id: Uuid,
    /// OAuth provider
    pub provider: OAuthProvider,
    /// Provider's user ID (sub claim in OIDC)
    pub provider_user_id: String,
    /// Provider's email (if available)
    pub provider_email: Option<String>,
    /// Whether email is verified (OIDC only)
    pub email_verified: Option<bool>,
    /// Display name from provider
    pub display_name: Option<String>,
    /// When link was created
    pub linked_at: u64,
    /// Last authentication with this link
    pub last_auth_at: u64,
    /// Whether link is revoked
    pub revoked: bool,
    /// When link was revoked
    pub revoked_at: Option<u64>,
}
