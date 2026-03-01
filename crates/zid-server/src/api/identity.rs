use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zid_crypto::MachineKeyCapabilities;
use zid_identity_core::{
    CreateIdentityRequest as CoreCreateIdentityRequest, FreezeReason, IdentityCore,
    IdentityStatus, MachineKey, RotationRequest,
};

use crate::{
    error::{ApiError, MapServiceErr},
    extractors::{AuthenticatedUser, JsonWithErrors},
    state::AppState,
};

use super::helpers::{
    format_timestamp_rfc3339, parse_approvals, parse_capabilities, parse_hex_32, parse_hex_64,
    parse_pq_keys, require_self_sovereign,
};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    pub identity_id: Uuid,
    pub identity_signing_public_key: String, // hex
    pub authorization_signature: String,     // hex
    pub machine_key: MachineKeyRequest,
    pub namespace_name: String,
    pub created_at: u64, // Unix timestamp - must match the timestamp used to create the signature
}

#[derive(Debug, Deserialize)]
pub struct MachineKeyRequest {
    pub machine_id: Uuid,
    pub signing_public_key: String,    // hex
    pub encryption_public_key: String, // hex
    pub capabilities: Vec<String>,
    pub device_name: String,
    pub device_platform: String,
    /// ML-DSA-65 public key (hex, 3904 chars)
    pub pq_signing_public_key: String,
    /// ML-KEM-768 public key (hex, 2368 chars)
    pub pq_encryption_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct CreateIdentityResponse {
    pub identity_id: Uuid,
    pub did: String,
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct GetIdentityResponse {
    pub identity_id: Uuid,
    pub did: String,
    pub identity_signing_public_key: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct FreezeCeremonyRequest {
    #[serde(default)]
    pub approver_machine_ids: Vec<Uuid>,
    #[serde(default)]
    pub approval_signatures: Vec<String>, // hex
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct UnfreezeCeremonyRequest {
    #[serde(default)]
    pub approver_machine_ids: Vec<Uuid>,
    #[serde(default)]
    pub approval_signatures: Vec<String>, // hex
}

#[derive(Debug, Deserialize)]
pub struct RecoveryCeremonyRequest {
    pub new_identity_signing_public_key: String, // hex
    #[serde(default)]
    pub approver_machine_ids: Vec<Uuid>,
    #[serde(default)]
    pub approval_signatures: Vec<String>, // hex
}

#[derive(Debug, Deserialize)]
pub struct RotationCeremonyRequest {
    pub new_identity_signing_public_key: String, // hex
    /// Signature from current identity signing key proving authorization
    pub rotation_signature: String, // hex from current identity signing key
    #[serde(default)]
    pub approver_machine_ids: Vec<Uuid>,
    #[serde(default)]
    pub approval_signatures: Vec<String>, // hex
}

#[derive(Debug, Serialize)]
pub struct CeremonyResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/identity
pub async fn create_identity(
    State(state): State<Arc<AppState>>,
    JsonWithErrors(req): JsonWithErrors<CreateIdentityRequest>,
) -> Result<Json<CreateIdentityResponse>, ApiError> {
    // Parse hex strings
    let identity_signing_public_key = parse_hex_32(&req.identity_signing_public_key)?;
    let authorization_signature = parse_hex_64(&req.authorization_signature)?;
    let signing_public_key = parse_hex_32(&req.machine_key.signing_public_key)?;
    let encryption_public_key = parse_hex_32(&req.machine_key.encryption_public_key)?;

    // Parse capabilities
    let capabilities = parse_capabilities(&req.machine_key.capabilities)?;

    // Parse PQ keys (always required)
    let (pq_signing_public_key, pq_encryption_public_key) = parse_pq_keys(
        &req.machine_key.pq_signing_public_key,
        &req.machine_key.pq_encryption_public_key,
    )?;

    // Create machine key
    let machine_key = MachineKey {
        machine_id: req.machine_key.machine_id,
        identity_id: req.identity_id,
        namespace_id: req.identity_id, // Personal namespace
        signing_public_key,
        encryption_public_key,
        capabilities,
        epoch: 0,
        created_at: req.created_at, // Use client-provided timestamp
        expires_at: None,
        last_used_at: None,
        device_name: req.machine_key.device_name.clone(),
        device_platform: req.machine_key.device_platform.clone(),
        revoked: false,
        revoked_at: None,
        pq_signing_public_key,
        pq_encryption_public_key,
    };

    // Create identity request
    let create_request = CoreCreateIdentityRequest {
        identity_id: req.identity_id,
        identity_signing_public_key,
        machine_key,
        authorization_signature: authorization_signature.to_vec(),
        namespace_name: Some(req.namespace_name),
        created_at: req.created_at, // Use client-provided timestamp for signature verification
    };

    // Create identity
    let identity = state
        .identity_service
        .create_identity(create_request)
        .await
        .map_svc_err()?;

    // Personal namespace has same ID as identity
    let namespace_id = req.identity_id;

    Ok(Json(CreateIdentityResponse {
        identity_id: identity.identity_id,
        did: identity.did,
        machine_id: req.machine_key.machine_id,
        namespace_id,
        created_at: format_timestamp_rfc3339(identity.created_at)?,
    }))
}

/// GET /v1/identity — returns the authenticated caller's identity
pub async fn get_current_identity(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Result<Json<GetIdentityResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    get_identity_inner(&state, identity_id).await
}

/// GET /v1/identity/:identity_id
pub async fn get_identity(
    State(state): State<Arc<AppState>>,
    Path(identity_id): Path<Uuid>,
    _auth: AuthenticatedUser,
) -> Result<Json<GetIdentityResponse>, ApiError> {
    get_identity_inner(&state, identity_id).await
}

async fn get_identity_inner(
    state: &AppState,
    identity_id: Uuid,
) -> Result<Json<GetIdentityResponse>, ApiError> {
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_svc_err()?;

    let status_str = match identity.status {
        IdentityStatus::Active => "active",
        IdentityStatus::Disabled => "disabled",
        IdentityStatus::Frozen => "frozen",
        IdentityStatus::Deleted => "deleted",
    };

    Ok(Json(GetIdentityResponse {
        identity_id: identity.identity_id,
        did: identity.did,
        identity_signing_public_key: hex::encode(identity.identity_signing_public_key),
        status: status_str.to_string(),
        created_at: format_timestamp_rfc3339(identity.created_at)?,
    }))
}

/// GET /v1/identity/did/:did
///
/// Retrieve an identity by its DID (Decentralized Identifier).
/// The DID must be URL-encoded when passed in the path.
pub async fn get_identity_by_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<GetIdentityResponse>, ApiError> {
    // URL decode the DID (colons are often encoded)
    let did = urlencoding::decode(&did)
        .map_err(|_| ApiError::InvalidRequest("Invalid DID encoding".to_string()))?
        .into_owned();

    // Validate DID format
    if !did.starts_with("did:key:") {
        return Err(ApiError::InvalidRequest(
            "Invalid DID format: must start with 'did:key:'".to_string(),
        ));
    }

    let identity = state
        .identity_service
        .get_identity_by_did(&did)
        .await
        .map_svc_err()?;

    let status_str = match identity.status {
        IdentityStatus::Active => "active",
        IdentityStatus::Disabled => "disabled",
        IdentityStatus::Frozen => "frozen",
        IdentityStatus::Deleted => "deleted",
    };

    Ok(Json(GetIdentityResponse {
        identity_id: identity.identity_id,
        did: identity.did,
        identity_signing_public_key: hex::encode(identity.identity_signing_public_key),
        status: status_str.to_string(),
        created_at: format_timestamp_rfc3339(identity.created_at)?,
    }))
}

/// POST /v1/identity/freeze
pub async fn freeze_identity(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<FreezeCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Check tier - freeze requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_svc_err()?;
    
    require_self_sovereign(&identity, "Freeze ceremony")?;

    // Parse freeze reason
    let freeze_reason = match req.reason.as_str() {
        "security_incident" => FreezeReason::SecurityIncident,
        "suspicious_activity" => FreezeReason::SuspiciousActivity,
        "user_requested" => FreezeReason::UserRequested,
        "administrative" => FreezeReason::Administrative,
        _ => FreezeReason::Administrative,
    };

    // Parse approvals for freeze ceremony (only for high-risk freezes)
    let approvals = if matches!(
        freeze_reason,
        FreezeReason::SecurityIncident | FreezeReason::SuspiciousActivity
    ) {
        // For high-risk freezes, require at least one approval
        if req.approver_machine_ids.is_empty() || req.approval_signatures.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Multi-party approval required for security-related freeze".to_string(),
            ));
        }
        parse_approvals(&req.approver_machine_ids, &req.approval_signatures)?
    } else {
        Vec::new()
    };

    // Execute freeze ceremony with cryptographic verification of approvals
    state
        .identity_service
        .freeze_identity(identity_id, freeze_reason, approvals)
        .await
        .map_svc_err()?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Identity frozen successfully".to_string(),
    }))
}

/// POST /v1/identity/unfreeze
pub async fn unfreeze_identity(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<UnfreezeCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Check tier - unfreeze requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_svc_err()?;
    
    require_self_sovereign(&identity, "Unfreeze ceremony")?;

    // Parse approvals
    let approvals = parse_approvals(&req.approver_machine_ids, &req.approval_signatures)?;

    // Execute unfreeze ceremony
    state
        .identity_service
        .unfreeze_identity(identity_id, approvals)
        .await
        .map_svc_err()?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Identity unfrozen successfully".to_string(),
    }))
}

/// POST /v1/identity/recovery
pub async fn recovery_ceremony(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<RecoveryCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Check tier - recovery ceremony requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_svc_err()?;
    
    if identity.tier.is_managed() {
        return Err(ApiError::InvalidRequest(
            "Recovery ceremony requires self-sovereign identity. Managed identities use multi-method recovery via /v1/identity/recover endpoint.".to_string()
        ));
    }

    let new_identity_signing_public_key = parse_hex_32(&req.new_identity_signing_public_key)?;

    // Parse approvals
    let approvals = parse_approvals(&req.approver_machine_ids, &req.approval_signatures)?;

    // Create a recovery machine key (placeholder - should come from request)
    let recovery_machine_key = MachineKey {
        machine_id: Uuid::new_v4(),
        identity_id,
        namespace_id: identity_id,
        signing_public_key: new_identity_signing_public_key,
        encryption_public_key: new_identity_signing_public_key,
        capabilities: MachineKeyCapabilities::FULL_DEVICE,
        epoch: 1,
        created_at: chrono::Utc::now().timestamp() as u64,
        expires_at: None,
        last_used_at: None,
        device_name: "Recovery Device".to_string(),
        device_platform: "unknown".to_string(),
        pq_signing_public_key: vec![],
        pq_encryption_public_key: vec![],
        revoked: false,
        revoked_at: None,
    };

    // Execute recovery ceremony
    state
        .identity_service
        .initiate_recovery(identity_id, recovery_machine_key, approvals)
        .await
        .map_svc_err()?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Identity recovered successfully".to_string(),
    }))
}

/// POST /v1/identity/rotation
pub async fn rotation_ceremony(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<RotationCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    // Rotation is a high-risk operation - require MFA
    auth.claims.require_mfa()?;

    let identity_id = auth.claims.identity_id()?;

    // Check tier - rotation ceremony requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_svc_err()?;
    
    require_self_sovereign(&identity, "Rotation ceremony")?;

    let new_identity_signing_public_key = parse_hex_32(&req.new_identity_signing_public_key)?;

    // Parse rotation signature (signature from current identity signing key)
    let rotation_signature_bytes = hex::decode(&req.rotation_signature)
        .map_err(|_| ApiError::InvalidRequest("Invalid rotation signature encoding".to_string()))?;

    verify_rotation_signature(
        identity_id,
        &identity.identity_signing_public_key,
        &new_identity_signing_public_key,
        &rotation_signature_bytes,
    )?;
    
    // Parse approvals
    let approvals = parse_approvals(&req.approver_machine_ids, &req.approval_signatures)?;

    // Create rotation request
    let rotation_request = RotationRequest {
        identity_id,
        new_identity_signing_public_key,
        approvals,
        new_machines: Vec::new(), // TODO: Should come from request
    };

    // Execute rotation ceremony
    state
        .identity_service
        .rotate_neural_key(rotation_request)
        .await
        .map_svc_err()?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Identity signing key rotated successfully".to_string(),
    }))
}

fn verify_rotation_signature(
    identity_id: Uuid,
    identity_signing_public_key: &[u8; 32],
    new_identity_signing_public_key: &[u8; 32],
    rotation_signature: &[u8],
) -> Result<(), ApiError> {
    if rotation_signature.len() != 64 {
        return Err(ApiError::InvalidRequest(
            "Rotation signature must be 64 bytes".to_string(),
        ));
    }

    let mut message = Vec::with_capacity(6 + 16 + 32);
    message.extend_from_slice(b"rotate");
    message.extend_from_slice(identity_id.as_bytes());
    message.extend_from_slice(new_identity_signing_public_key);

    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(rotation_signature);

    zid_crypto::verify_signature(identity_signing_public_key, &message, &signature_array)
        .map_err(|_| ApiError::InvalidSignature)
}
