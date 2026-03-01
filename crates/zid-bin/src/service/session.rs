use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::infra::{crypto_adapter, http_client::HttpClient};
use crate::state::types::SessionViewModel;

#[derive(Deserialize, Debug, Clone)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    #[serde(default)]
    pub machine_id: Option<Uuid>,
    pub expires_at: String,
    #[serde(default)]
    pub warning: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
    pub expires_at: String,
}

#[derive(Serialize)]
struct MachineLoginBody {
    machine_id: Uuid,
    challenge_id: Uuid,
    signature: String,
}

#[derive(Serialize)]
struct EmailLoginBody {
    email: String,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<Uuid>,
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

#[derive(Serialize)]
struct IntrospectBody {
    token: String,
}

#[derive(Deserialize, Debug)]
pub struct TokenIntrospection {
    pub active: bool,
    pub identity_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub mfa_verified: Option<bool>,
    pub capabilities: Option<Vec<String>>,
    pub exp: Option<i64>,
}

pub async fn request_challenge(client: &HttpClient) -> Result<ChallengeResponse, AppError> {
    client.get("/v1/auth/challenge").await
}

pub async fn login_machine(
    client: &HttpClient,
    machine_id: &Uuid,
    keypair: &zid_crypto::Ed25519KeyPair,
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

pub async fn login_email(
    client: &HttpClient,
    email: &str,
    password: &str,
    machine_id: Option<Uuid>,
) -> Result<SessionTokens, AppError> {
    let body = EmailLoginBody {
        email: email.to_string(),
        password: password.to_string(),
        machine_id,
    };
    client.post("/v1/auth/login/email", &body).await
}

pub async fn login_oauth_initiate(
    client: &HttpClient,
    provider: &str,
) -> Result<String, AppError> {
    #[derive(Deserialize)]
    struct InitiateResp {
        authorization_url: String,
    }
    let resp: InitiateResp = client
        .get(&format!("/v1/auth/oauth/{provider}"))
        .await?;
    Ok(resp.authorization_url)
}

pub async fn login_oauth_callback(
    client: &HttpClient,
    provider: &str,
    code: &str,
    oauth_state: &str,
) -> Result<SessionTokens, AppError> {
    let body = serde_json::json!({ "code": code, "state": oauth_state });
    client
        .post(&format!("/v1/auth/oauth/{provider}/callback"), &body)
        .await
}

pub async fn login_wallet(
    client: &HttpClient,
    wallet_address: &str,
    signature: &str,
    challenge_id: &Uuid,
) -> Result<SessionTokens, AppError> {
    let body = serde_json::json!({
        "wallet_address": wallet_address,
        "signature": signature,
        "challenge_id": challenge_id,
    });
    client.post("/v1/auth/login/wallet", &body).await
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

pub async fn introspect(
    client: &HttpClient,
    token: &str,
) -> Result<TokenIntrospection, AppError> {
    let body = IntrospectBody {
        token: token.to_string(),
    };
    client.post("/v1/auth/introspect", &body).await
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
    creds: &crate::state::types::StoredCredentials,
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
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| AppError::CryptoError("Invalid seed length".into()))?;
    let keypair = zid_crypto::Ed25519KeyPair::from_seed(&seed)
        .map_err(|e| AppError::CryptoError(e.to_string()))?;

    login_machine(client, machine_id, &keypair).await
}

pub fn tokens_to_view_model(tokens: &SessionTokens) -> SessionViewModel {
    SessionViewModel {
        session_id: tokens.session_id,
        machine_id: tokens.machine_id,
        expires_at: tokens.expires_at.clone(),
        is_current: true,
    }
}
