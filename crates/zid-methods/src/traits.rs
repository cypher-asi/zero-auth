//! Auth Methods trait definitions.

use crate::{errors::Result, types::*};
use async_trait::async_trait;
use uuid::Uuid;

/// Auth Methods subsystem trait
#[async_trait]
pub trait AuthMethods: Send + Sync {
    /// Create an authentication challenge
    ///
    /// Returns a structured challenge that the client must sign with their machine key.
    async fn create_challenge(&self, request: ChallengeRequest) -> Result<Challenge>;

    /// Authenticate with Machine Key challenge-response
    ///
    /// Verifies the signature on the challenge and returns an auth result.
    async fn authenticate_machine(
        &self,
        response: ChallengeResponse,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult>;

    /// OPAQUE email login – step 1.
    ///
    /// Returns a `CredentialResponse` and an ephemeral login state ID.
    async fn email_login_init(
        &self,
        request: EmailLoginInitRequest,
    ) -> Result<EmailLoginInitResponse>;

    /// OPAQUE email login – step 2.
    ///
    /// Verifies the `CredentialFinalization` and issues a session.
    async fn email_login_finish(
        &self,
        request: EmailLoginFinishRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult>;

    /// OPAQUE email credential attachment – step 1 (authenticated).
    async fn email_credential_register_init(
        &self,
        identity_id: Uuid,
        request: EmailRegisterInitRequest,
    ) -> Result<EmailRegisterInitResponse>;

    /// OPAQUE email credential attachment – step 2 (authenticated).
    async fn email_credential_register_finish(
        &self,
        identity_id: Uuid,
        request: EmailRegisterFinishRequest,
    ) -> Result<()>;

    /// Initiate OAuth link flow
    ///
    /// Generates OAuth state and returns authorization URL.
    async fn oauth_initiate(
        &self,
        identity_id: Uuid,
        provider: OAuthProvider,
    ) -> Result<OAuthInitiateResponse>;

    /// Initiate OAuth login flow
    ///
    /// Generates OAuth state for login and returns authorization URL.
    async fn oauth_initiate_login(&self, provider: OAuthProvider) -> Result<OAuthInitiateResponse>;

    /// Complete OAuth link flow
    ///
    /// Exchanges code for tokens, gets user info, and links to identity.
    async fn oauth_complete(
        &self,
        identity_id: Uuid,
        request: OAuthCompleteRequest,
    ) -> Result<Uuid>;

    /// Authenticate with OAuth
    ///
    /// Performs OAuth flow and returns auth result if account is linked.
    async fn authenticate_oauth(
        &self,
        request: OAuthCompleteRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult>;

    /// Revoke OAuth link
    ///
    /// Removes OAuth credential from identity.
    async fn revoke_oauth_link(&self, identity_id: Uuid, provider: OAuthProvider) -> Result<()>;

    /// Authenticate with EVM wallet signature
    ///
    /// Verifies SECP256k1 signature and returns auth result.
    async fn authenticate_wallet(
        &self,
        signature: WalletSignature,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult>;

    /// Authenticate with pre-verified wallet address
    ///
    /// Used for message-based authentication where signature is already verified.
    async fn authenticate_wallet_by_address(
        &self,
        wallet_address: String,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult>;

    /// Attach wallet credential to existing identity
    ///
    /// Links a wallet address to an identity.
    async fn attach_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
        chain: String,
    ) -> Result<()>;

    /// Revoke wallet credential
    ///
    /// Removes wallet credential from identity.
    async fn revoke_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
    ) -> Result<()>;

    /// List credentials for identity
    ///
    /// Returns all authentication credentials attached to an identity.
    async fn list_credentials(&self, identity_id: Uuid) -> Result<Vec<CredentialInfo>>;
}

/// Credential information for listing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialInfo {
    /// Credential type
    pub credential_type: CredentialType,
    /// Identifier (email, wallet address, or OAuth provider)
    pub identifier: String,
    /// Created timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used_at: u64,
    /// Whether credential is revoked
    pub revoked: bool,
}

/// Credential type
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Email + password
    Email,
    /// OAuth provider
    OAuth,
    /// EVM wallet
    Wallet,
}
