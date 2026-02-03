//! Request/Response types for identity creation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to create identity via email
#[derive(Debug, Deserialize)]
pub struct CreateEmailIdentityRequest {
    /// Email address
    pub email: String,
    /// Password
    pub password: String,
    /// Optional namespace name
    pub namespace_name: Option<String>,
}

/// Response from identity creation (includes auth tokens for auto-login)
#[derive(Debug, Serialize)]
pub struct IdentityCreationResponse {
    /// Created identity ID
    pub identity_id: Uuid,
    /// Machine ID for authentication
    pub machine_id: Uuid,
    /// Namespace ID
    pub namespace_id: Uuid,
    /// Identity tier
    pub tier: String,
    /// Authentication method used (e.g., "email", "oauth:google", "wallet:ethereum")
    pub auth_method: String,
    /// Primary identifier for display (e.g., email address, wallet address, OAuth name)
    pub primary_identifier: String,
    /// JWT access token for API authentication
    pub access_token: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
    /// Session ID
    pub session_id: Uuid,
    /// Token expiration time (RFC3339 format)
    pub expires_at: String,
    /// Warning message about upgrading
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Request to initiate wallet identity creation
#[derive(Debug, Deserialize)]
pub struct InitiateWalletIdentityRequest {
    /// Wallet type (ethereum, polygon, arbitrum, base, solana)
    pub wallet_type: String,
    /// Wallet address
    pub address: String,
}

/// Response from wallet initiation
#[derive(Debug, Serialize)]
pub struct InitiateWalletResponse {
    /// Challenge ID
    pub challenge_id: Uuid,
    /// Message to sign
    pub message_to_sign: String,
}

/// Request to complete wallet identity creation
#[derive(Debug, Deserialize)]
pub struct CompleteWalletIdentityRequest {
    /// Challenge ID from initiation
    pub challenge_id: Uuid,
    /// Wallet type
    pub wallet_type: String,
    /// Wallet address
    pub address: String,
    /// Signature (hex encoded)
    pub signature: String,
    /// Optional namespace name
    pub namespace_name: Option<String>,
}

/// OAuth initiate response
#[derive(Debug, Serialize)]
pub struct OAuthIdentityInitiateResponse {
    /// Authorization URL
    pub auth_url: String,
    /// State parameter
    pub state: String,
}

/// OAuth callback request
#[derive(Debug, Deserialize)]
pub struct OAuthIdentityCallbackRequest {
    /// Authorization code
    pub code: String,
    /// State parameter
    pub state: String,
}

/// Request to get tier status
#[derive(Debug, Serialize)]
pub struct TierStatusResponse {
    /// Current tier
    pub tier: String,
    /// Number of linked auth methods
    pub auth_methods_count: usize,
    /// Whether identity can be upgraded
    pub can_upgrade: bool,
    /// Requirements for upgrade
    pub upgrade_requirements: Vec<String>,
}

/// Request to upgrade identity
#[derive(Debug, Deserialize)]
pub struct UpgradeIdentityRequest {
    /// New identity signing public key (hex)
    pub new_isk_public: String,
    /// Neural key commitment (hex)
    pub commitment: String,
    /// Upgrade signature from current ISK (hex)
    pub upgrade_signature: String,
}

/// Response from upgrade ceremony
#[derive(Debug, Serialize)]
pub struct UpgradeIdentityResponse {
    /// Whether upgrade was successful
    pub success: bool,
    /// New tier
    pub tier: String,
    /// Message about shard backup
    pub message: String,
}
