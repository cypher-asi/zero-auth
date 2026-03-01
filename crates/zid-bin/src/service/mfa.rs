use serde::Deserialize;

use crate::error::AppError;
use crate::infra::http_client::HttpClient;

#[derive(Deserialize, Debug, Clone)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub qr_url: String,
    pub backup_codes: Vec<String>,
}

pub async fn setup(client: &HttpClient) -> Result<MfaSetupResponse, AppError> {
    let resp: MfaSetupResponse = client
        .post("/v1/mfa/setup", &serde_json::json!({}))
        .await?;
    Ok(resp)
}

pub async fn enable(client: &HttpClient, code: &str) -> Result<(), AppError> {
    let body = serde_json::json!({ "code": code });
    let _: serde_json::Value = client.post("/v1/mfa/enable", &body).await?;
    Ok(())
}

pub async fn disable(client: &HttpClient, code: &str) -> Result<(), AppError> {
    let body = serde_json::json!({ "code": code });
    let _: serde_json::Value = client.post("/v1/mfa/disable", &body).await?;
    Ok(())
}

pub async fn verify(client: &HttpClient, code: &str) -> Result<(), AppError> {
    let body = serde_json::json!({ "code": code });
    let _: serde_json::Value = client.post("/v1/mfa/verify", &body).await?;
    Ok(())
}
