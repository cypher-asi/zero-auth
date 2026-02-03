//! Wallet-based authentication handler.

use axum::{extract::State, response::Json};
use std::sync::Arc;

use crate::error::{ApiError, MapServiceErr};
use crate::state::AppState;

use super::auth::{LoginResponse, WalletLoginRequest};
use super::helpers::create_login_session;

/// POST /v1/auth/login/wallet
pub async fn login_wallet(
    State(state): State<Arc<AppState>>,
    ctx: crate::request_context::RequestContext,
    Json(req): Json<WalletLoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Parse and validate signature
    let signature_bytes = parse_wallet_signature(&req.signature)?;

    // Validate message format
    validate_wallet_message(&req.message, &req.wallet_address)?;

    // Validate timestamp in message
    validate_message_timestamp(&req.message)?;

    // Verify EVM signature
    verify_evm_signature(&req.message, &signature_bytes, &req.wallet_address)?;

    // Authenticate with wallet service (signature already verified above)
    let auth_result = authenticate_wallet(&state, &req, &ctx).await?;

    // Create session
    create_wallet_session(&state, &auth_result).await
}

/// Parse wallet signature from hex string
fn parse_wallet_signature(signature_hex: &str) -> Result<Vec<u8>, ApiError> {
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| ApiError::InvalidRequest("Invalid signature".to_string()))?;

    // Ensure signature is exactly 65 bytes (r,s,v)
    if signature_bytes.len() != 65 {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid signature length: expected 65 bytes, got {}",
            signature_bytes.len()
        )));
    }

    Ok(signature_bytes)
}

/// Validate the wallet authentication message format
fn validate_wallet_message(message: &str, wallet_address: &str) -> Result<(), ApiError> {
    // Standard format: "Sign in to zid\nTimestamp: <unix_timestamp>\nWallet: <address>"
    if !message.contains("Sign in to zid")
        || !message.contains("Timestamp:")
        || !message.contains(wallet_address)
    {
        return Err(ApiError::InvalidRequest(
            "Invalid message format. Expected standard auth message.".to_string(),
        ));
    }
    Ok(())
}

/// Validate timestamp in message is within acceptable range
fn validate_message_timestamp(message: &str) -> Result<(), ApiError> {
    let timestamp_str = message
        .lines()
        .find(|line| line.starts_with("Timestamp:"))
        .and_then(|line| line.strip_prefix("Timestamp:"))
        .map(|s| s.trim())
        .ok_or_else(|| ApiError::InvalidRequest("Missing timestamp in message".to_string()))?;

    let message_timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::InvalidRequest("Invalid timestamp format".to_string()))?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("System time error")))?
        .as_secs();

    // Allow 60 seconds clock skew tolerance for future timestamps
    const TIME_TOLERANCE: u64 = 60;

    if message_timestamp > current_time + TIME_TOLERANCE {
        return Err(ApiError::InvalidRequest(
            "Message timestamp is in the future".to_string(),
        ));
    }

    if current_time > message_timestamp + 300 {
        return Err(ApiError::InvalidRequest(
            "Message timestamp expired (>5 minutes old)".to_string(),
        ));
    }

    Ok(())
}

/// Verify EVM signature and recovered address matches
fn verify_evm_signature(
    message: &str,
    signature_bytes: &[u8],
    expected_address: &str,
) -> Result<(), ApiError> {
    use zid_methods::wallet::{build_eip191_message, keccak256, recover_address};

    let mut signature_array = [0u8; 65];
    signature_array.copy_from_slice(signature_bytes);

    // Build EIP-191 message and hash it
    let eip191_message = build_eip191_message(message);
    let message_hash = keccak256(eip191_message.as_bytes());

    // Recover address from signature
    let recovered_address = recover_address(&message_hash, &signature_array)
        .map_err(|e| ApiError::InvalidRequest(format!("Signature recovery failed: {}", e)))?;

    // Verify recovered address matches provided wallet address
    if recovered_address.to_lowercase() != expected_address.to_lowercase() {
        return Err(ApiError::InvalidRequest(format!(
            "Signature verification failed: expected {}, recovered {}",
            expected_address, recovered_address
        )));
    }

    Ok(())
}

/// Authenticate with wallet service
async fn authenticate_wallet(
    state: &Arc<AppState>,
    req: &WalletLoginRequest,
    ctx: &crate::request_context::RequestContext,
) -> Result<zid_methods::AuthResult, ApiError> {
    // Use message-based authentication - signature already verified by caller
    state
        .auth_service
        .authenticate_wallet_by_address(
            req.wallet_address.clone(),
            None, // MFA code not yet supported in wallet login
            ctx.ip_address.clone(),
            ctx.user_agent.clone(),
        )
        .await
        .map_svc_err()
}

/// Create session for authenticated wallet user
async fn create_wallet_session(
    state: &Arc<AppState>,
    auth_result: &zid_methods::AuthResult,
) -> Result<Json<LoginResponse>, ApiError> {
    Ok(Json(create_login_session(state, auth_result).await?))
}
