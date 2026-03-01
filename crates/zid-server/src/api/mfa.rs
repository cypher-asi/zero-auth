use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zid_methods::AuthMethods;

use crate::{
    error::{map_service_error, ApiError},
    extractors::AuthenticatedUser,
    state::AppState,
};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub qr_url: String,
    pub backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnableMfaRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct DisableMfaRequest {
    #[serde(alias = "mfa_code")]
    pub code: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/mfa/setup
///
/// Generates a TOTP secret and backup codes. The client must display the QR
/// code to the user, then call `/v1/mfa/enable` with a valid TOTP code to
/// finish activation.
pub async fn setup_mfa(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Result<Json<MfaSetupResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    let mfa_setup = state
        .auth_service
        .setup_mfa(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(MfaSetupResponse {
        secret: mfa_setup.secret,
        qr_url: mfa_setup.qr_code_url,
        backup_codes: mfa_setup.backup_codes,
    }))
}

/// POST /v1/mfa/enable
///
/// Verifies the TOTP code and enables MFA for the identity.
pub async fn enable_mfa(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<EnableMfaRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    state
        .auth_service
        .enable_mfa(identity_id, req.code)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(serde_json::json!({ "mfa_enabled": true })))
}

/// POST /v1/mfa/disable
///
/// Requires a valid TOTP code to disable MFA.
pub async fn disable_mfa_post(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<DisableMfaRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    state
        .auth_service
        .disable_mfa(identity_id, req.code)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(serde_json::json!({ "mfa_disabled": true })))
}

/// DELETE /v1/mfa
pub async fn disable_mfa(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<DisableMfaRequest>,
) -> Result<StatusCode, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    state
        .auth_service
        .disable_mfa(identity_id, req.code)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}
