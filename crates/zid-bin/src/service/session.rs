use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::infra::{crypto_adapter, http_client::HttpClient};
use crate::state::SessionViewModel;

#[derive(Deserialize, Debug, Clone)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    #[serde(default)]
    pub machine_id: Option<Uuid>,
    pub expires_at: String,
}

#[derive(Deserialize, Debug)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
}

#[derive(Serialize)]
struct MachineLoginBody {
    machine_id: Uuid,
    challenge_id: Uuid,
    signature: String,
}

#[derive(Serialize)]
struct RefreshBody {
    refresh_token: String,
    session_id: Uuid,
    machine_id: Uuid,
}

#[derive(Deserialize, Debug)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
}

pub async fn login_machine(
    client: &HttpClient,
    machine_id: &Uuid,
    keypair: &zid_crypto::IdentitySigningKey,
) -> Result<SessionTokens, AppError> {
    let challenge_resp: ChallengeResponse = client
        .get(&format!("/v1/auth/challenge?machine_id={}", machine_id))
        .await?;

    use base64::Engine;
    let challenge_json = base64::engine::general_purpose::STANDARD
        .decode(&challenge_resp.challenge)
        .map_err(|e| AppError::CryptoError(format!("Challenge decode failed: {e}")))?;

    let challenge: zid_crypto::Challenge = serde_json::from_slice(&challenge_json)
        .map_err(|e| AppError::CryptoError(format!("Challenge parse failed: {e}")))?;

    let canonical = zid_crypto::canonicalize_challenge(&challenge);
    let sig = crypto_adapter::sign_bytes(keypair, &canonical);

    let body = MachineLoginBody {
        machine_id: *machine_id,
        challenge_id: challenge_resp.challenge_id,
        signature: hex::encode(sig),
    };

    client.post("/v1/auth/login/machine", &body).await
}

pub async fn refresh(
    client: &HttpClient,
    refresh_token: &str,
    session_id: Uuid,
    machine_id: Uuid,
) -> Result<RefreshResponse, AppError> {
    let body = RefreshBody {
        refresh_token: refresh_token.to_string(),
        session_id,
        machine_id,
    };
    client.post("/v1/auth/refresh", &body).await
}

pub async fn revoke(client: &HttpClient, session_id: Uuid) -> Result<(), AppError> {
    client
        .post_no_response("/v1/session/revoke", &serde_json::json!({ "session_id": session_id }))
        .await
}

pub async fn login_machine_after_create(
    client: &HttpClient,
    machine_id: &Uuid,
    passphrase: &str,
    creds: &crate::state::StoredCredentials,
) -> Result<SessionTokens, AppError> {
    let kek = crypto_adapter::derive_kek(passphrase, &creds.kek_salt)?;
    let nonce: [u8; 24] = creds
        .machine_key_nonce
        .as_slice()
        .try_into()
        .map_err(|_| AppError::StorageError("Invalid nonce length".into()))?;
    let seed_bytes = crypto_adapter::decrypt_machine_seed(
        &kek,
        &creds.encrypted_machine_signing_seed,
        &nonce,
        &creds.identity_id,
    )?;
    let signing_key = if seed_bytes.len() == 64 {
        let ed_seed: [u8; 32] = seed_bytes[..32].try_into()
            .map_err(|_| AppError::CryptoError("Invalid seed length".into()))?;
        let pq_seed: [u8; 32] = seed_bytes[32..].try_into()
            .map_err(|_| AppError::CryptoError("Invalid seed length".into()))?;
        zid_crypto::IdentitySigningKey::from_seeds(ed_seed, pq_seed)
    } else if seed_bytes.len() == 32 {
        let ed_seed: [u8; 32] = seed_bytes.try_into()
            .map_err(|_| AppError::CryptoError("Invalid seed length".into()))?;
        zid_crypto::IdentitySigningKey::from_seeds(ed_seed, [0u8; 32])
    } else {
        return Err(AppError::CryptoError("Invalid seed length".into()));
    };

    login_machine(client, machine_id, &signing_key).await
}

pub fn tokens_to_view_model(tokens: &SessionTokens) -> SessionViewModel {
    SessionViewModel {
        session_id: tokens.session_id,
        machine_id: tokens.machine_id,
        expires_at: tokens.expires_at.clone(),
        is_current: true,
    }
}
