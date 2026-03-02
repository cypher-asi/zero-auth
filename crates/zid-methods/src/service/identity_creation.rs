//! Identity creation service for managed identities.
//!
//! Email identity creation uses OPAQUE (2 round-trips).
//! OAuth and wallet creation are unchanged.

use crate::{
    errors::*,
    oauth::types::OAuthUserInfo,
    types::*,
    wallet::{canonicalize_wallet_challenge, normalize_wallet_address, verify_wallet_signature_typed},
};
use tracing::info;
use uuid::Uuid;
use zid_crypto::current_timestamp;
use zid_identity_core::{
    CreateManagedIdentityParams, CreateManagedIdentityResult, IdentityCore, IdentityTier,
};
use zid_policy::PolicyEngine;
use zid_storage::Storage;

use super::{
    AuthMethodsService, CF_AUTH_CREDENTIALS, CF_CHALLENGES, CF_OAUTH_LINKS,
    CF_OAUTH_LINKS_BY_IDENTITY, CF_WALLET_CREDENTIALS, CF_WALLET_CREDENTIALS_BY_IDENTITY,
};

const CF_AUTH_LINKS: &str = "auth_links";
const CF_AUTH_LINKS_BY_METHOD: &str = "auth_links_by_method";
const CF_PRIMARY_AUTH_METHOD: &str = "primary_auth_method";

/// Response from identity creation
#[derive(Debug, Clone)]
pub struct IdentityCreationResponse {
    /// Created identity ID
    pub identity_id: Uuid,
    /// Machine ID for authentication
    pub machine_id: Uuid,
    /// Namespace ID (same as identity_id)
    pub namespace_id: Uuid,
    /// Identity tier (always Managed for these creation methods)
    pub tier: IdentityTier,
    /// Warning message about upgrading
    pub warning: Option<String>,
}

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore + 'static,
    P: PolicyEngine + 'static,
    S: Storage + 'static,
{
    // ========================================================================
    // Email Identity Creation (OPAQUE, 2 steps)
    // ========================================================================

    /// Step 1 — server evaluates the blinded registration request.
    pub async fn create_identity_via_email_init(
        &self,
        request: EmailRegisterInitRequest,
    ) -> Result<EmailRegisterInitResponse> {
        let email_lower = request.email.to_lowercase().trim().to_string();
        info!("OPAQUE registration init for email");

        let method_key = format!("email:{}", email_lower);
        if self
            .storage
            .exists(CF_AUTH_LINKS_BY_METHOD, &method_key)
            .await?
        {
            return Err(AuthMethodsError::Other(
                "Email already linked to an identity".to_string(),
            ));
        }

        self.opaque_register_init(&email_lower, &request.registration_request)
    }

    /// Step 2 — client sends the `RegistrationUpload`; server creates
    /// the identity, stores the OPAQUE record, and auto-logs in.
    pub async fn create_identity_via_email_finish(
        &self,
        request: EmailRegisterFinishRequest,
    ) -> Result<IdentityCreationResponse> {
        let email_lower = request.email.to_lowercase().trim().to_string();
        info!("OPAQUE registration finish for email");

        let method_key = format!("email:{}", email_lower);
        if self
            .storage
            .exists(CF_AUTH_LINKS_BY_METHOD, &method_key)
            .await?
        {
            return Err(AuthMethodsError::Other(
                "Email already linked to an identity".to_string(),
            ));
        }

        let opaque_record = self.opaque_register_finish(&request.registration_upload)?;

        let response = self
            .create_managed_identity_internal(
                *self.service_master_key,
                "email".to_string(),
                email_lower.clone(),
                request.namespace_name,
            )
            .await?;

        let credential = EmailCredential {
            identity_id: response.identity.identity_id,
            email: email_lower.clone(),
            opaque_record,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            email_verified: false,
            verification_token: Some(Uuid::new_v4().to_string()),
        };

        self.storage
            .put(CF_AUTH_CREDENTIALS, &email_lower, &credential)
            .await?;

        self.store_auth_link(
            response.identity.identity_id,
            AuthMethodType::Email,
            &email_lower,
            true,
            false,
        )
        .await?;

        info!(
            "Email identity created: {} for {}",
            response.identity.identity_id, email_lower
        );

        Ok(IdentityCreationResponse {
            identity_id: response.identity.identity_id,
            machine_id: response.machine_id,
            namespace_id: response.namespace_id,
            tier: response.identity.tier,
            warning: Some(
                "Consider upgrading to self-sovereign identity for enhanced security".to_string(),
            ),
        })
    }

    // ========================================================================
    // OAuth Identity Creation (unchanged)
    // ========================================================================

    /// Create a new identity via OAuth provider
    pub async fn create_identity_via_oauth(
        &self,
        provider: OAuthProvider,
        user_info: &OAuthUserInfo,
        namespace_name: Option<String>,
    ) -> Result<IdentityCreationResponse> {
        info!(
            "Creating identity via OAuth: {:?} for {}",
            provider, user_info.id
        );

        let method_id = user_info.id.clone();
        let auth_method_type = match provider {
            OAuthProvider::Google => AuthMethodType::OAuthGoogle,
            OAuthProvider::X => AuthMethodType::OAuthX,
            OAuthProvider::EpicGames => AuthMethodType::OAuthEpic,
        };
        let method_key = format!("{}:{}", auth_method_type.as_str(), method_id);
        if self
            .storage
            .exists(CF_AUTH_LINKS_BY_METHOD, &method_key)
            .await?
        {
            return Err(AuthMethodsError::Other(
                "OAuth account already linked to an identity".to_string(),
            ));
        }

        let method_type = format!("oauth:{}", provider.as_str());
        let response = self
            .create_managed_identity_internal(
                *self.service_master_key,
                method_type,
                method_id.clone(),
                namespace_name,
            )
            .await?;
        let identity_id = response.identity.identity_id;

        let link = crate::oauth::types::OAuthLink {
            link_id: Uuid::new_v4(),
            identity_id,
            provider,
            provider_user_id: user_info.id.clone(),
            provider_email: user_info.email.clone(),
            email_verified: None,
            display_name: user_info.name.clone(),
            linked_at: current_timestamp(),
            last_auth_at: current_timestamp(),
            revoked: false,
            revoked_at: None,
        };

        let link_key = format!("{}:{}", provider.as_str(), user_info.id);
        self.storage.put(CF_OAUTH_LINKS, &link_key, &link).await?;

        let identity_index_key = format!("{}:{}", identity_id, provider.as_str());
        self.storage
            .put(CF_OAUTH_LINKS_BY_IDENTITY, &identity_index_key, &user_info.id)
            .await?;

        self.store_auth_link(identity_id, auth_method_type, &method_id, true, true)
            .await?;

        info!("OAuth identity created: {} via {:?}", identity_id, provider);

        Ok(IdentityCreationResponse {
            identity_id,
            machine_id: response.machine_id,
            namespace_id: response.namespace_id,
            tier: response.identity.tier,
            warning: Some(
                "Consider upgrading to self-sovereign identity for enhanced security".to_string(),
            ),
        })
    }

    // ========================================================================
    // Wallet Identity Creation (unchanged)
    // ========================================================================

    /// Initiate wallet identity creation – returns challenge to sign
    pub async fn initiate_wallet_identity_creation(
        &self,
        wallet_type: WalletType,
        address: String,
    ) -> Result<(Uuid, String)> {
        let normalized = normalize_wallet_address(wallet_type, &address)?;
        info!("Initiating wallet identity creation: {:?} {}", wallet_type, normalized);

        let auth_method_type = wallet_type.to_auth_method_type();
        let method_key = format!("{}:{}", auth_method_type.as_str(), normalized);
        if self
            .storage
            .exists(CF_AUTH_LINKS_BY_METHOD, &method_key)
            .await?
        {
            return Err(AuthMethodsError::Other(
                "Wallet already linked to an identity".to_string(),
            ));
        }

        let challenge = zid_crypto::Challenge::new_for_wallet(&normalized);
        let challenge_id = challenge.id();
        self.storage
            .put(CF_CHALLENGES, &challenge_id, &challenge)
            .await?;

        let message = canonicalize_wallet_challenge(&challenge);
        Ok((challenge_id, message))
    }

    /// Complete wallet identity creation – verify signature and create identity
    pub async fn complete_wallet_identity_creation(
        &self,
        wallet_type: WalletType,
        address: String,
        challenge_id: Uuid,
        signature: Vec<u8>,
        namespace_name: Option<String>,
    ) -> Result<IdentityCreationResponse> {
        let normalized = normalize_wallet_address(wallet_type, &address)?;
        info!("Completing wallet identity creation: {:?} {}", wallet_type, normalized);

        let challenge: zid_crypto::Challenge = self
            .storage
            .get(CF_CHALLENGES, &challenge_id)
            .await?
            .ok_or(AuthMethodsError::ChallengeNotFound(challenge_id))?;

        self.storage.delete(CF_CHALLENGES, &challenge_id).await?;

        let canonical_message = canonicalize_wallet_challenge(&challenge);
        verify_wallet_signature_typed(
            wallet_type,
            &normalized,
            canonical_message.as_bytes(),
            &signature,
        )?;

        let method_type = format!("wallet:{}", wallet_type.as_str());
        let response = self
            .create_managed_identity_internal(
                *self.service_master_key,
                method_type,
                normalized.clone(),
                namespace_name,
            )
            .await?;
        let identity_id = response.identity.identity_id;

        let credential = WalletCredential {
            identity_id,
            wallet_type,
            wallet_address: normalized.clone(),
            public_key: if wallet_type == WalletType::Solana {
                bs58::decode(&normalized)
                    .into_vec()
                    .ok()
                    .and_then(|v| {
                        if v.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            Some(arr)
                        } else {
                            None
                        }
                    })
            } else {
                None
            },
            chain: wallet_type.as_str().to_string(),
            created_at: current_timestamp(),
            last_used_at: current_timestamp(),
            revoked: false,
            revoked_at: None,
        };

        self.storage
            .put(CF_WALLET_CREDENTIALS, &normalized, &credential)
            .await?;

        let identity_index_key = format!("{}:{}", identity_id, normalized);
        self.storage
            .put(CF_WALLET_CREDENTIALS_BY_IDENTITY, &identity_index_key, &())
            .await?;

        let auth_method_type = wallet_type.to_auth_method_type();
        self.store_auth_link(identity_id, auth_method_type, &normalized, true, true)
            .await?;

        info!("Wallet identity created: {} via {:?} {}", identity_id, wallet_type, normalized);

        Ok(IdentityCreationResponse {
            identity_id,
            machine_id: response.machine_id,
            namespace_id: response.namespace_id,
            tier: response.identity.tier,
            warning: Some(
                "Consider upgrading to self-sovereign identity for enhanced security".to_string(),
            ),
        })
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    async fn create_managed_identity_internal(
        &self,
        service_master_key: [u8; 32],
        method_type: String,
        method_id: String,
        namespace_name: Option<String>,
    ) -> Result<CreateManagedIdentityResult> {
        let params = CreateManagedIdentityParams {
            service_master_key,
            method_type,
            method_id,
            namespace_name,
        };
        self.identity_core
            .create_managed_identity(params)
            .await
            .map_err(|e| AuthMethodsError::Other(e.to_string()))
    }

    async fn store_auth_link(
        &self,
        identity_id: Uuid,
        method_type: AuthMethodType,
        method_id: &str,
        is_primary: bool,
        verified: bool,
    ) -> Result<()> {
        let link = AuthLinkRecord {
            identity_id,
            method_type,
            method_id: method_id.to_string(),
            linked_at: current_timestamp(),
            is_primary,
            verified,
            last_used_at: Some(current_timestamp()),
        };

        let link_key = format!("{}:{:?}", identity_id, method_type);
        self.storage.put(CF_AUTH_LINKS, &link_key, &link).await?;

        let method_key = format!("{}:{}", method_type.as_str(), method_id);
        self.storage
            .put(CF_AUTH_LINKS_BY_METHOD, &method_key, &identity_id)
            .await?;

        if is_primary {
            self.storage
                .put(CF_PRIMARY_AUTH_METHOD, &identity_id, &method_type)
                .await?;
        }

        Ok(())
    }

    /// Get auth method count for an identity
    pub async fn get_auth_method_count(&self, identity_id: Uuid) -> Result<usize> {
        let mut count = 0;

        let email_key = format!("{}:{:?}", identity_id, AuthMethodType::Email);
        if self.storage.exists(CF_AUTH_LINKS, &email_key).await? {
            count += 1;
        }

        for method_type in [
            AuthMethodType::OAuthGoogle,
            AuthMethodType::OAuthX,
            AuthMethodType::OAuthEpic,
        ] {
            let key = format!("{}:{:?}", identity_id, method_type);
            if self.storage.exists(CF_AUTH_LINKS, &key).await? {
                count += 1;
            }
        }

        for method_type in [AuthMethodType::WalletEvm, AuthMethodType::WalletSolana] {
            let key = format!("{}:{:?}", identity_id, method_type);
            if self.storage.exists(CF_AUTH_LINKS, &key).await? {
                count += 1;
            }
        }

        Ok(count)
    }
}
