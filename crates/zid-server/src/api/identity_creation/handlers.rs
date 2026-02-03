//! API endpoint handlers for identity creation.

use axum::{
    extract::{Path, State},
    response::Json,
};
use std::sync::Arc;
use zid_identity_core::IdentityCore;
use zid_methods::AuthMethods;
use zid_sessions::SessionManager;

use super::helpers::{
    format_expires_at, parse_hex_32, parse_hex_64, parse_oauth_provider, parse_wallet_type,
    provider_display_name, truncate_wallet_address,
};
use super::types::{
    CompleteWalletIdentityRequest, CreateEmailIdentityRequest, IdentityCreationResponse,
    InitiateWalletIdentityRequest, InitiateWalletResponse, OAuthIdentityCallbackRequest,
    OAuthIdentityInitiateResponse, TierStatusResponse, UpgradeIdentityRequest,
    UpgradeIdentityResponse,
};
use crate::{
    error::{map_service_error, ApiError},
    extractors::JsonWithErrors,
    request_context::RequestContext,
    state::AppState,
};

/// POST /v1/identity/email - Create identity via email (auto-login)
pub async fn create_email_identity(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    JsonWithErrors(req): JsonWithErrors<CreateEmailIdentityRequest>,
) -> Result<Json<IdentityCreationResponse>, ApiError> {
    tracing::info!(
        ip = %ctx.ip_address,
        user_agent = %ctx.user_agent,
        "Email identity creation attempt"
    );

    // Validate email format
    if !req.email.contains('@') || req.email.len() < 5 {
        return Err(ApiError::InvalidRequest("Invalid email format".to_string()));
    }

    // Validate password strength
    if req.password.len() < 8 {
        return Err(ApiError::InvalidRequest(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    // Store email for response before moving into service call
    let email = req.email.clone();

    // Create the identity
    let response = state
        .auth_service
        .create_identity_via_email(req.email, req.password, req.namespace_name)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(response.machine_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Create session for auto-login
    let session = state
        .session_service
        .create_session(
            response.identity_id,
            response.machine_id,
            response.namespace_id,
            false, // MFA not verified on signup
            machine.capabilities.to_string_vec(),
            vec!["default".to_string()],
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    tracing::info!(
        identity_id = %response.identity_id,
        tier = %response.tier.as_str(),
        "Email identity created successfully"
    );

    Ok(Json(IdentityCreationResponse {
        identity_id: response.identity_id,
        machine_id: response.machine_id,
        namespace_id: response.namespace_id,
        tier: response.tier.as_str().to_string(),
        auth_method: "email".to_string(),
        primary_identifier: email,
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        expires_at: format_expires_at(session.expires_in)?,
        warning: response.warning,
    }))
}

/// POST /v1/identity/oauth/:provider - Initiate OAuth identity creation
pub async fn initiate_oauth_identity(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
) -> Result<Json<OAuthIdentityInitiateResponse>, ApiError> {
    let provider = parse_oauth_provider(&provider)?;

    let response = state
        .auth_service
        .oauth_initiate_login(provider)
        .await
        .map_err(|e: zid_methods::errors::AuthMethodsError| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(OAuthIdentityInitiateResponse {
        auth_url: response.auth_url,
        state: response.state,
    }))
}

/// POST /v1/identity/oauth/:provider/callback - Complete OAuth identity creation (auto-login)
pub async fn complete_oauth_identity(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Path(provider_str): Path<String>,
    JsonWithErrors(req): JsonWithErrors<OAuthIdentityCallbackRequest>,
) -> Result<Json<IdentityCreationResponse>, ApiError> {
    let provider = parse_oauth_provider(&provider_str)?;

    tracing::info!(
        ip = %ctx.ip_address,
        provider = ?provider,
        "OAuth identity creation attempt"
    );

    // Store provider info for response
    let auth_method = format!("oauth:{}", provider_str.to_lowercase());
    let primary_identifier = format!("{} Account", provider_display_name(provider));

    // This would normally call create_identity_via_oauth after verifying the OAuth callback
    // For now, we'll use the existing authenticate_oauth which handles both login and signup
    let oauth_request = zid_methods::types::OAuthCompleteRequest {
        provider,
        code: req.code,
        state: req.state,
    };

    let result = state
        .auth_service
        .authenticate_oauth(oauth_request, ctx.ip_address.clone(), ctx.user_agent.clone())
        .await
        .map_err(|e: zid_methods::errors::AuthMethodsError| map_service_error(anyhow::anyhow!(e)))?;

    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(result.machine_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Create session for auto-login
    let session = state
        .session_service
        .create_session(
            result.identity_id,
            result.machine_id,
            result.namespace_id,
            false, // MFA not verified on signup
            machine.capabilities.to_string_vec(),
            vec!["default".to_string()],
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    tracing::info!(
        identity_id = %result.identity_id,
        provider = %auth_method,
        "OAuth identity created successfully"
    );

    Ok(Json(IdentityCreationResponse {
        identity_id: result.identity_id,
        machine_id: result.machine_id,
        namespace_id: result.namespace_id,
        tier: "managed".to_string(), // OAuth always creates managed identities
        auth_method,
        primary_identifier,
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        expires_at: format_expires_at(session.expires_in)?,
        warning: result.warning,
    }))
}

/// POST /v1/identity/wallet/challenge - Initiate wallet identity creation
pub async fn initiate_wallet_identity(
    State(state): State<Arc<AppState>>,
    JsonWithErrors(req): JsonWithErrors<InitiateWalletIdentityRequest>,
) -> Result<Json<InitiateWalletResponse>, ApiError> {
    let wallet_type = parse_wallet_type(&req.wallet_type)?;

    let (challenge_id, message) = state
        .auth_service
        .initiate_wallet_identity_creation(wallet_type, req.address)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(InitiateWalletResponse {
        challenge_id,
        message_to_sign: message,
    }))
}

/// POST /v1/identity/wallet/verify - Complete wallet identity creation (auto-login)
pub async fn complete_wallet_identity(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    JsonWithErrors(req): JsonWithErrors<CompleteWalletIdentityRequest>,
) -> Result<Json<IdentityCreationResponse>, ApiError> {
    let wallet_type = parse_wallet_type(&req.wallet_type)?;

    tracing::info!(
        ip = %ctx.ip_address,
        wallet_type = ?wallet_type,
        "Wallet identity creation attempt"
    );

    // Store wallet info for response
    let auth_method = format!("wallet:{}", req.wallet_type.to_lowercase());
    let wallet_address = req.address.clone();

    let signature = hex::decode(&req.signature)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding for signature".to_string()))?;

    let response = state
        .auth_service
        .complete_wallet_identity_creation(
            wallet_type,
            req.address,
            req.challenge_id,
            signature,
            req.namespace_name,
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(response.machine_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Create session for auto-login
    let session = state
        .session_service
        .create_session(
            response.identity_id,
            response.machine_id,
            response.namespace_id,
            false, // MFA not verified on signup
            machine.capabilities.to_string_vec(),
            vec!["default".to_string()],
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    tracing::info!(
        identity_id = %response.identity_id,
        wallet_type = ?wallet_type,
        "Wallet identity created successfully"
    );

    // Format wallet address for display (truncate middle for long addresses)
    let primary_identifier = truncate_wallet_address(&wallet_address);

    Ok(Json(IdentityCreationResponse {
        identity_id: response.identity_id,
        machine_id: response.machine_id,
        namespace_id: response.namespace_id,
        tier: response.tier.as_str().to_string(),
        auth_method,
        primary_identifier,
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        expires_at: format_expires_at(session.expires_in)?,
        warning: response.warning,
    }))
}

/// GET /v1/identity/tier - Get tier status
pub async fn get_tier_status(
    State(state): State<Arc<AppState>>,
    auth: crate::extractors::AuthenticatedUser,
) -> Result<Json<TierStatusResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Get auth method count
    let auth_methods_count = state
        .auth_service
        .get_auth_method_count(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let status = state
        .identity_service
        .get_tier_status(identity_id, auth_methods_count)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(TierStatusResponse {
        tier: status.tier.as_str().to_string(),
        auth_methods_count: status.auth_methods_count,
        can_upgrade: status.can_upgrade,
        upgrade_requirements: status.upgrade_requirements,
    }))
}

/// POST /v1/identity/upgrade - Upgrade to self-sovereign
pub async fn upgrade_identity(
    State(state): State<Arc<AppState>>,
    auth: crate::extractors::AuthenticatedUser,
    JsonWithErrors(req): JsonWithErrors<UpgradeIdentityRequest>,
) -> Result<Json<UpgradeIdentityResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    let new_isk = parse_hex_32(&req.new_isk_public)?;
    let commitment = parse_hex_32(&req.commitment)?;
    let signature = parse_hex_64(&req.upgrade_signature)?;

    let upgrade_request = zid_identity_core::UpgradeIdentityRequest {
        identity_id,
        new_identity_signing_public_key: new_isk,
        neural_key_commitment: commitment,
        upgrade_signature: signature,
    };

    let result = state
        .identity_service
        .upgrade_identity(upgrade_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(UpgradeIdentityResponse {
        success: result.success,
        tier: result.tier.as_str().to_string(),
        message: result.message,
    }))
}
