use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::infra::http_client::HttpClient;
use crate::state::types::CredentialViewModel;

#[derive(Deserialize, Debug)]
pub struct CredentialRecord {
    pub method_type: String,
    pub method_id: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Deserialize, Debug)]
struct CredentialListResponse {
    pub credentials: Vec<CredentialRecord>,
}

#[derive(Serialize)]
struct LinkEmailBody {
    email: String,
    password: String,
}

pub async fn link_email(
    client: &HttpClient,
    email: &str,
    password: &str,
) -> Result<CredentialViewModel, AppError> {
    let body = LinkEmailBody {
        email: email.to_string(),
        password: password.to_string(),
    };
    let resp: CredentialRecord = client.post("/v1/credentials/email", &body).await?;
    Ok(record_to_view_model(resp))
}

pub async fn link_wallet(
    client: &HttpClient,
    wallet_address: &str,
    signature: &str,
    challenge_id: &Uuid,
) -> Result<CredentialViewModel, AppError> {
    let body = serde_json::json!({
        "wallet_address": wallet_address,
        "signature": signature,
        "challenge_id": challenge_id,
    });
    let resp: CredentialRecord = client.post("/v1/credentials/wallet", &body).await?;
    Ok(record_to_view_model(resp))
}

pub async fn initiate_oauth(
    client: &HttpClient,
    provider: &str,
) -> Result<String, AppError> {
    #[derive(Deserialize)]
    struct Resp {
        auth_url: String,
    }
    let resp: Resp = client
        .get(&format!("/v1/oauth/{provider}/initiate"))
        .await?;
    Ok(resp.auth_url)
}

pub async fn complete_oauth(
    client: &HttpClient,
    code: &str,
    state: &str,
) -> Result<CredentialViewModel, AppError> {
    let body = serde_json::json!({ "code": code, "state": state });
    let resp: CredentialRecord = client.post("/v1/oauth/callback", &body).await?;
    Ok(record_to_view_model(resp))
}

pub async fn list(client: &HttpClient) -> Result<Vec<CredentialViewModel>, AppError> {
    let resp: CredentialListResponse = client.get("/v1/credentials").await?;
    Ok(resp.credentials.into_iter().map(record_to_view_model).collect())
}

pub async fn revoke(
    client: &HttpClient,
    method_type: &str,
    method_id: &str,
) -> Result<(), AppError> {
    client
        .delete_no_body(&format!("/v1/credentials/{method_type}/{method_id}"))
        .await
}

pub async fn set_primary(
    client: &HttpClient,
    method_type: &str,
    method_id: &str,
) -> Result<(), AppError> {
    let _: serde_json::Value = client
        .put(
            &format!("/v1/credentials/{method_type}/{method_id}/primary"),
            &serde_json::json!({}),
        )
        .await?;
    Ok(())
}

fn record_to_view_model(r: CredentialRecord) -> CredentialViewModel {
    CredentialViewModel {
        method_type: r.method_type,
        method_id: r.method_id,
        primary: r.primary,
        verified: r.verified,
        created_at: r.created_at.unwrap_or_default(),
    }
}
