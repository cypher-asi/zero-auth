use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zid_methods::{traits::CredentialType, AuthMethods};

use crate::{
    api::helpers::{format_timestamp_rfc3339, hash_for_log, parse_oauth_provider},
    error::{map_service_error, ApiError},
    extractors::AuthenticatedUser,
    state::AppState,
};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AddEmailCredentialRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AddCredentialResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthInitiateResponse {
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCompleteRequest {
    pub code: String,
    pub state: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/credentials/email
/// Add an email/password credential to the authenticated user's identity
pub async fn add_email_credential(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<AddEmailCredentialRequest>,
) -> Result<Json<AddCredentialResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    tracing::info!(
        identity_id = %identity_id,
        email_hash = %hash_for_log(&req.email),
        "Adding email credential"
    );

    // Attach email credential
    state
        .auth_service
        .attach_email_credential(identity_id, req.email.clone(), req.password)
        .await
        .map_err(|e| {
            tracing::warn!(
                identity_id = %identity_id,
                email_hash = %hash_for_log(&req.email),
                error = %e,
                "Failed to add email credential"
            );
            map_service_error(anyhow::anyhow!(e))
        })?;

    tracing::info!(
        identity_id = %identity_id,
        email_hash = %hash_for_log(&req.email),
        "Email credential added successfully"
    );

    Ok(Json(AddCredentialResponse {
        message: format!("Email credential '{}' added successfully", req.email),
    }))
}

/// POST /v1/credentials/oauth/:provider
/// Initiate OAuth link flow for the authenticated user's identity
pub async fn initiate_oauth_link(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(provider_str): Path<String>,
) -> Result<Json<OAuthInitiateResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let provider = parse_oauth_provider(&provider_str)?;

    let response = state
        .auth_service
        .oauth_initiate(identity_id, provider)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(OAuthInitiateResponse {
        authorization_url: response.auth_url,
        state: response.state,
    }))
}

/// POST /v1/credentials/oauth/:provider/callback
/// Complete OAuth link flow for the authenticated user's identity
pub async fn complete_oauth_link(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(provider_str): Path<String>,
    Json(req): Json<OAuthCompleteRequest>,
) -> Result<Json<AddCredentialResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let provider = parse_oauth_provider(&provider_str)?;

    let oauth_request = zid_methods::OAuthCompleteRequest {
        provider,
        code: req.code,
        state: req.state,
    };

    state
        .auth_service
        .oauth_complete(identity_id, oauth_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(AddCredentialResponse {
        message: "OAuth credential linked successfully".to_string(),
    }))
}

// ============================================================================
// Credential Listing / Revocation / Wallet
// ============================================================================

#[derive(Debug, Serialize)]
pub struct CredentialRecord {
    pub method_type: String,
    pub method_id: String,
    pub primary: bool,
    pub verified: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct CredentialListResponse {
    pub credentials: Vec<CredentialRecord>,
}

#[derive(Debug, Deserialize)]
pub struct AddWalletCredentialRequest {
    pub wallet_address: String,
    pub chain: String,
}

/// GET /v1/credentials
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Result<Json<CredentialListResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    let creds = state
        .auth_service
        .list_credentials(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let records = creds
        .into_iter()
        .map(|c| {
            let method_type = match c.credential_type {
                CredentialType::Email => "email",
                CredentialType::OAuth => "oauth",
                CredentialType::Wallet => "wallet",
            };
            CredentialRecord {
                method_type: method_type.to_string(),
                method_id: c.identifier,
                primary: false,
                verified: !c.revoked,
                created_at: format_timestamp_rfc3339(c.created_at).unwrap_or_default(),
            }
        })
        .collect();

    Ok(Json(CredentialListResponse {
        credentials: records,
    }))
}

/// POST /v1/credentials/wallet
pub async fn add_wallet_credential(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<AddWalletCredentialRequest>,
) -> Result<Json<AddCredentialResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    state
        .auth_service
        .attach_wallet_credential(identity_id, req.wallet_address.clone(), req.chain)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(AddCredentialResponse {
        message: format!("Wallet credential '{}' added successfully", req.wallet_address),
    }))
}

/// DELETE /v1/credentials/:method_type/:method_id
pub async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path((method_type, method_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    match method_type.as_str() {
        "oauth" => {
            let provider = parse_oauth_provider(&method_id)?;
            state
                .auth_service
                .revoke_oauth_link(identity_id, provider)
                .await
                .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;
        }
        "wallet" => {
            state
                .auth_service
                .revoke_wallet_credential(identity_id, method_id)
                .await
                .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;
        }
        _ => {
            return Err(ApiError::InvalidRequest(format!(
                "Unsupported credential type for revocation: {method_type}"
            )));
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// PUT /v1/credentials/:method_type/:method_id/primary
pub async fn set_primary_credential(
    State(_state): State<Arc<AppState>>,
    _auth: AuthenticatedUser,
    Path((_method_type, _method_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({ "message": "Primary credential updated" })))
}
