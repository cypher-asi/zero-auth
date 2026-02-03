//! Shared API helper functions.

use std::sync::Arc;

use crate::error::{map_service_error, ApiError, MapServiceErr};
use crate::state::AppState;
use super::auth::LoginResponse;
use uuid::Uuid;
use zid_crypto::{blake3_hash, KeyScheme, MachineKeyCapabilities, ML_DSA_65_PUBLIC_KEY_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE};
use zid_identity_core::{Approval, Identity, IdentityCore, IdentityTier};
use zid_methods::{AuthResult, OAuthProvider};
use zid_sessions::SessionManager;

/// Parse a hex string into a 32-byte array
pub fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest("Expected 32 bytes".to_string()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Parse a hex string into a 64-byte array
pub fn parse_hex_64(hex_str: &str) -> Result<[u8; 64], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
    if bytes.len() != 64 {
        return Err(ApiError::InvalidRequest("Expected 64 bytes".to_string()));
    }
    let mut array = [0u8; 64];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Parse capability strings into MachineKeyCapabilities bitflags
pub fn parse_capabilities(caps: &[String]) -> Result<MachineKeyCapabilities, ApiError> {
    let mut result = MachineKeyCapabilities::empty();
    for s in caps {
        match s.as_str() {
            "FULL_DEVICE" => result |= MachineKeyCapabilities::FULL_DEVICE,
            "AUTHENTICATE" => result |= MachineKeyCapabilities::AUTHENTICATE,
            "SIGN" => result |= MachineKeyCapabilities::SIGN,
            "ENCRYPT" => result |= MachineKeyCapabilities::ENCRYPT,
            "SVK_UNWRAP" => result |= MachineKeyCapabilities::SVK_UNWRAP,
            "MLS_MESSAGING" => result |= MachineKeyCapabilities::MLS_MESSAGING,
            "VAULT_OPERATIONS" => result |= MachineKeyCapabilities::VAULT_OPERATIONS,
            "SERVICE_MACHINE" => result |= MachineKeyCapabilities::SERVICE_MACHINE,
            _ => {
                return Err(ApiError::InvalidRequest(format!(
                    "Invalid capability: {}",
                    s
                )))
            }
        }
    }
    Ok(result)
}

/// Format a unix timestamp (seconds) as RFC3339.
pub fn format_timestamp_rfc3339(timestamp: u64) -> Result<String, ApiError> {
    Ok(chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Invalid timestamp")))?
        .to_rfc3339())
}

pub fn parse_oauth_provider(provider_str: &str) -> Result<OAuthProvider, ApiError> {
    match provider_str.to_lowercase().as_str() {
        "google" => Ok(OAuthProvider::Google),
        "x" | "twitter" => Ok(OAuthProvider::X),
        "epic" => Ok(OAuthProvider::EpicGames),
        _ => Err(ApiError::InvalidRequest(format!(
            "Unknown OAuth provider: {}",
            provider_str
        ))),
    }
}

pub fn hash_for_log(value: &str) -> String {
    let hash = blake3_hash(value.as_bytes());
    hex::encode(&hash[..8])
}

/// Parse key scheme string into KeyScheme enum
pub fn parse_key_scheme(scheme: Option<&str>) -> Result<KeyScheme, ApiError> {
    match scheme {
        None | Some("classical") => Ok(KeyScheme::Classical),
        Some("pq_hybrid") => Ok(KeyScheme::PqHybrid),
        Some(other) => Err(ApiError::InvalidRequest(format!(
            "Invalid key_scheme: {}. Expected 'classical' or 'pq_hybrid'",
            other
        ))),
    }
}

/// Parse ML-DSA-65 public key from hex string (1952 bytes)
pub fn parse_pq_signing_key(hex_str: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding for PQ signing key".to_string()))?;
    if bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid PQ signing key size: expected {} bytes, got {}",
            ML_DSA_65_PUBLIC_KEY_SIZE, bytes.len()
        )));
    }
    Ok(bytes)
}

/// Parse ML-KEM-768 public key from hex string (1184 bytes)
pub fn parse_pq_encryption_key(hex_str: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding for PQ encryption key".to_string()))?;
    if bytes.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid PQ encryption key size: expected {} bytes, got {}",
            ML_KEM_768_PUBLIC_KEY_SIZE, bytes.len()
        )));
    }
    Ok(bytes)
}

/// Parse approval signatures into Approval structs.
///
/// Validates that the number of machine IDs matches the number of signatures.
pub fn parse_approvals(
    machine_ids: &[Uuid],
    signatures: &[String],
) -> Result<Vec<Approval>, ApiError> {
    if machine_ids.len() != signatures.len() {
        return Err(ApiError::InvalidRequest(
            "Number of approvers must match number of signatures".to_string(),
        ));
    }

    signatures
        .iter()
        .enumerate()
        .map(|(i, sig_hex)| {
            let signature_bytes = hex::decode(sig_hex)
                .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;

            Ok(Approval {
                machine_id: machine_ids[i],
                signature: signature_bytes,
                timestamp: chrono::Utc::now().timestamp() as u64,
            })
        })
        .collect()
}

/// Require that the identity is self-sovereign for the given operation.
///
/// Returns an error if the identity is managed.
pub fn require_self_sovereign(identity: &Identity, operation: &str) -> Result<(), ApiError> {
    if identity.tier == IdentityTier::Managed {
        return Err(ApiError::InvalidRequest(format!(
            "{} requires self-sovereign identity. Please upgrade your identity first.",
            operation
        )));
    }
    Ok(())
}

/// Parse PQ keys based on key scheme.
///
/// For Classical scheme, returns (None, None).
/// For PqHybrid scheme, parses and validates both PQ keys.
pub fn parse_pq_keys(
    key_scheme: KeyScheme,
    signing_key: Option<&String>,
    encryption_key: Option<&String>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), ApiError> {
    match key_scheme {
        KeyScheme::Classical => Ok((None, None)),
        KeyScheme::PqHybrid => {
            let pq_sign = signing_key
                .ok_or_else(|| ApiError::InvalidRequest(
                    "pq_signing_public_key required for pq_hybrid scheme".to_string()
                ))
                .and_then(|s| parse_pq_signing_key(s))?;
            let pq_enc = encryption_key
                .ok_or_else(|| ApiError::InvalidRequest(
                    "pq_encryption_public_key required for pq_hybrid scheme".to_string()
                ))
                .and_then(|s| parse_pq_encryption_key(s))?;
            Ok((Some(pq_sign), Some(pq_enc)))
        }
    }
}

/// Create a login session from an authentication result.
///
/// This helper consolidates the common pattern across auth handlers:
/// 1. Get machine key to extract capabilities
/// 2. Create session with machine capabilities
/// 3. Format the login response
pub async fn create_login_session(
    state: &Arc<AppState>,
    auth_result: &AuthResult,
) -> Result<LoginResponse, ApiError> {
    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(auth_result.machine_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get machine key");
            map_service_error(anyhow::anyhow!(e))
        })?;

    // Create session with machine capabilities
    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            auth_result.machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            machine.capabilities.to_string_vec(),
            vec!["default".to_string()],
        )
        .await
        .map_svc_err()?;

    // Format expires_at timestamp
    let now = chrono::Utc::now().timestamp();
    let expires_in = session.expires_in as i64;
    let expires_at = now
        .checked_add(expires_in)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Timestamp overflow")))?;

    Ok(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id: auth_result.machine_id,
        expires_at: format_timestamp_rfc3339(expires_at as u64)?,
        warning: auth_result.warning.clone(),
    })
}
