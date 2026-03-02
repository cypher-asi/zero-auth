//! OPAQUE-based email authentication and credential attachment.

use crate::{errors::*, types::*};
use tracing::info;
use uuid::Uuid;
use zid_crypto::{
    blake3_hash, current_timestamp, OpaqueLoginState, ZeroAuthOpaque, OPAQUE_LOGIN_STATE_TTL_SECS,
};
use zid_identity_core::{IdentityCore, IdentityStatus};
use zid_policy::{Operation, PolicyContext, PolicyEngine, Verdict};
use zid_storage::Storage;

use super::{AuthMethodsService, CF_AUTH_CREDENTIALS, CF_OPAQUE_LOGIN_STATE};

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// OPAQUE login step 1: evaluate the blinded credential request.
    ///
    /// Returns a `CredentialResponse` (and persists ephemeral server state)
    /// regardless of whether the email exists, to prevent user enumeration.
    pub(super) async fn email_login_init(
        &self,
        request: EmailLoginInitRequest,
    ) -> Result<EmailLoginInitResponse> {
        info!(
            "OPAQUE login init for email hash: {}",
            email_hash_for_log(&request.email)
        );

        let email_lower = request.email.to_lowercase();
        let credential: Option<EmailCredential> =
            self.storage.get(CF_AUTH_CREDENTIALS, &email_lower).await?;

        let password_file = credential
            .as_ref()
            .map(|c| {
                opaque_ke::ServerRegistration::<ZeroAuthOpaque>::deserialize(&c.opaque_record)
            })
            .transpose()
            .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        let credential_request =
            opaque_ke::CredentialRequest::<ZeroAuthOpaque>::deserialize(&request.credential_request)
                .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        let mut rng = rand::rngs::OsRng;
        let server_login_result = opaque_ke::ServerLogin::start(
            &mut rng,
            &self.opaque_server_setup,
            password_file,
            credential_request,
            email_lower.as_bytes(),
            opaque_ke::ServerLoginParameters::default(),
        )
        .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        let login_state_id = Uuid::new_v4();
        let state = OpaqueLoginState {
            server_login_bytes: serde_json::to_vec(&server_login_result.state)
                .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?,
            email: email_lower,
            created_at: current_timestamp(),
        };

        self.storage
            .put(CF_OPAQUE_LOGIN_STATE, &login_state_id, &state)
            .await?;

        let response_bytes = serde_json::to_vec(&server_login_result.message)
            .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        Ok(EmailLoginInitResponse {
            credential_response: response_bytes,
            login_state_id,
        })
    }

    /// OPAQUE login step 2: verify the credential finalisation.
    pub(super) async fn email_login_finish(
        &self,
        request: EmailLoginFinishRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        let state: OpaqueLoginState = self
            .storage
            .get(CF_OPAQUE_LOGIN_STATE, &request.login_state_id)
            .await?
            .ok_or(AuthMethodsError::OpaqueLoginStateNotFound(
                request.login_state_id,
            ))?;

        self.storage
            .delete(CF_OPAQUE_LOGIN_STATE, &request.login_state_id)
            .await?;

        if current_timestamp() > state.created_at + OPAQUE_LOGIN_STATE_TTL_SECS {
            return Err(AuthMethodsError::OpaqueLoginStateNotFound(
                request.login_state_id,
            ));
        }

        let server_login: opaque_ke::ServerLogin<ZeroAuthOpaque> =
            serde_json::from_slice(&state.server_login_bytes)
                .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        let finalization =
            opaque_ke::CredentialFinalization::<ZeroAuthOpaque>::deserialize(
                &request.credential_finalization,
            )
            .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        server_login
            .finish(finalization, opaque_ke::ServerLoginParameters::default())
            .map_err(|_| AuthMethodsError::InvalidCredentials)?;

        let credential: EmailCredential = self
            .storage
            .get(CF_AUTH_CREDENTIALS, &state.email)
            .await?
            .ok_or(AuthMethodsError::InvalidCredentials)?;

        let identity = self.check_identity_status_opaque(&credential).await?;

        let (final_machine_id, warning) = self
            .resolve_machine_id(credential.identity_id, request.machine_id)
            .await?;

        let auth_result = self
            .evaluate_email_auth_policy(
                credential.identity_id,
                identity.identity_id,
                final_machine_id,
                ip_address,
                user_agent,
                warning,
            )
            .await?;

        info!(
            "OPAQUE email login succeeded for identity {}",
            credential.identity_id
        );

        Ok(auth_result)
    }

    /// Attach an email credential via OPAQUE registration – step 1.
    pub(super) async fn email_credential_register_init(
        &self,
        identity_id: Uuid,
        request: EmailRegisterInitRequest,
    ) -> Result<EmailRegisterInitResponse> {
        let _identity = self.identity_core.get_identity(identity_id).await?;
        let email_lower = request.email.to_lowercase();

        if self
            .storage
            .exists(CF_AUTH_CREDENTIALS, &email_lower)
            .await?
        {
            return Err(AuthMethodsError::Other(
                "Email already registered".to_string(),
            ));
        }

        self.opaque_register_init(&email_lower, &request.registration_request)
    }

    /// Attach an email credential via OPAQUE registration – step 2.
    pub(super) async fn email_credential_register_finish(
        &self,
        identity_id: Uuid,
        request: EmailRegisterFinishRequest,
    ) -> Result<()> {
        let _identity = self.identity_core.get_identity(identity_id).await?;
        let email_lower = request.email.to_lowercase();

        if self
            .storage
            .exists(CF_AUTH_CREDENTIALS, &email_lower)
            .await?
        {
            return Err(AuthMethodsError::Other(
                "Email already registered".to_string(),
            ));
        }

        let opaque_record = self.opaque_register_finish(&request.registration_upload)?;

        let credential = EmailCredential {
            identity_id,
            email: email_lower.clone(),
            opaque_record,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            email_verified: false,
            verification_token: None,
        };

        self.storage
            .put(CF_AUTH_CREDENTIALS, &email_lower, &credential)
            .await?;

        info!("Email credential attached for identity {}", identity_id);
        Ok(())
    }

    // ========================================================================
    // OPAQUE helpers
    // ========================================================================

    /// Run the server side of OPAQUE registration step 1.
    pub(crate) fn opaque_register_init(
        &self,
        email: &str,
        registration_request_bytes: &[u8],
    ) -> Result<EmailRegisterInitResponse> {
        let reg_request =
            opaque_ke::RegistrationRequest::<ZeroAuthOpaque>::deserialize(registration_request_bytes)
                .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        let result = opaque_ke::ServerRegistration::<ZeroAuthOpaque>::start(
            &self.opaque_server_setup,
            reg_request,
            email.as_bytes(),
        )
        .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        let response_bytes = serde_json::to_vec(&result.message)
            .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        Ok(EmailRegisterInitResponse {
            registration_response: response_bytes,
        })
    }

    /// Run the server side of OPAQUE registration finish — returns serialised password file.
    pub(crate) fn opaque_register_finish(
        &self,
        registration_upload_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let upload =
            opaque_ke::RegistrationUpload::<ZeroAuthOpaque>::deserialize(registration_upload_bytes)
                .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))?;

        let record = opaque_ke::ServerRegistration::<ZeroAuthOpaque>::finish(upload);

        serde_json::to_vec(&record)
            .map_err(|e| AuthMethodsError::OpaqueProtocol(format!("{e}")))
    }

    // ========================================================================
    // Auth-flow helpers
    // ========================================================================

    async fn check_identity_status_opaque(
        &self,
        credential: &EmailCredential,
    ) -> Result<zid_identity_core::Identity> {
        let identity = self
            .identity_core
            .get_identity(credential.identity_id)
            .await?;

        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id: identity.identity_id,
                reason: identity.frozen_reason,
            });
        }

        Ok(identity)
    }

    /// Resolve machine ID – verify provided or create virtual.
    pub(crate) async fn resolve_machine_id(
        &self,
        identity_id: Uuid,
        machine_id: Option<Uuid>,
    ) -> Result<(Uuid, Option<String>)> {
        if let Some(mid) = machine_id {
            let machine = self
                .identity_core
                .get_machine_key(mid)
                .await
                .map_err(|_| AuthMethodsError::MachineNotFound(mid))?;

            if machine.identity_id != identity_id {
                return Err(AuthMethodsError::MachineNotOwned {
                    machine_id: mid,
                    identity_id,
                });
            }
            if machine.revoked {
                return Err(AuthMethodsError::MachineRevoked(mid));
            }
            Ok((mid, None))
        } else {
            let virtual_machine_id = self.create_virtual_machine(identity_id).await?;
            info!(
                "Using virtual machine {} for email auth (identity {})",
                virtual_machine_id, identity_id
            );
            Ok((
                virtual_machine_id,
                Some("Consider enrolling a real device for enhanced security".to_string()),
            ))
        }
    }

    /// Evaluate policy for email authentication.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn evaluate_email_auth_policy(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
        machine_id: Uuid,
        ip_address: String,
        user_agent: String,
        warning: Option<String>,
    ) -> Result<AuthResult> {
        let reputation_score = self.policy.get_reputation(identity_id).await.unwrap_or(50);

        let decision = self
            .policy
            .evaluate(PolicyContext {
                identity_id,
                machine_id: Some(machine_id),
                namespace_id,
                auth_method: zid_policy::AuthMethod::EmailPassword,
                operation: Operation::Login,
                resource: None,
                ip_address,
                user_agent,
                timestamp: current_timestamp(),
                reputation_score,
                recent_failed_attempts: 0,
                identity_status: None,
                machine_revoked: None,
                machine_capabilities: None,
                namespace_active: None,
            })
            .await?;

        if decision.verdict != Verdict::Allow {
            return Err(AuthMethodsError::PolicyDenied(decision.reason));
        }

        self.policy
            .record_attempt(identity_id, Operation::Login, true)
            .await?;

        Ok(AuthResult {
            identity_id,
            machine_id,
            namespace_id,
            auth_method: AuthMethod::EmailPassword,
            warning,
        })
    }
}

fn email_hash_for_log(email: &str) -> String {
    let hash = blake3_hash(email.as_bytes());
    hex::encode(&hash[..8])
}
