use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zid_crypto::NeuralKey;

use crate::error::AppError;
use crate::infra::{crypto_adapter, http_client::HttpClient};
use crate::service::key_shard;
use crate::state::types::MachineViewModel;

#[derive(Serialize)]
struct EnrollBody {
    machine_id: Uuid,
    machine_signing_public_key: String,
    machine_encryption_public_key: String,
    authorization_signature: String,
    device_name: String,
    device_platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_signing_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_encryption_public_key: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct EnrollResponse {
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub enrolled_at: String,
}

#[derive(Deserialize, Debug)]
pub struct MachinesListResponse {
    pub machines: Vec<MachineInfo>,
}

#[derive(Deserialize, Debug)]
pub struct MachineInfo {
    pub machine_id: Uuid,
    pub device_name: String,
    pub device_platform: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked: bool,
    #[serde(default)]
    pub key_scheme: Option<String>,
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    #[serde(default)]
    pub epoch: Option<u64>,
}

pub async fn enroll(
    client: &HttpClient,
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    device_name: &str,
    device_platform: &str,
) -> Result<(EnrollResponse, zid_crypto::MachineKeyPair), AppError> {
    let machine_id = Uuid::new_v4();
    let keys = key_shard::derive_keys(neural_key, identity_id, &machine_id, 0)?;
    let pk = crypto_adapter::extract_machine_public_keys(&keys.machine_keypair);

    let (sig, _) = crypto_adapter::sign_enrollment_message(
        &keys.isk_keypair,
        identity_id,
        &machine_id,
        &pk.signing,
        &pk.encryption,
    );

    let body = EnrollBody {
        machine_id,
        machine_signing_public_key: hex::encode(pk.signing),
        machine_encryption_public_key: hex::encode(pk.encryption),
        authorization_signature: hex::encode(sig),
        device_name: device_name.to_string(),
        device_platform: device_platform.to_string(),
        pq_signing_public_key: Some(hex::encode(&pk.pq_signing)),
        pq_encryption_public_key: Some(hex::encode(&pk.pq_encryption)),
    };

    let response: EnrollResponse = client.post("/v1/machines/enroll", &body).await?;
    Ok((response, keys.machine_keypair))
}

pub async fn list(client: &HttpClient) -> Result<Vec<MachineViewModel>, AppError> {
    let resp: MachinesListResponse = client.get("/v1/machines").await?;
    Ok(resp
        .machines
        .into_iter()
        .map(|m| MachineViewModel {
            machine_id: m.machine_id,
            device_name: m.device_name,
            device_platform: m.device_platform,
            created_at: m.created_at,
            last_used_at: m.last_used_at,
            revoked: m.revoked,
            key_scheme: m.key_scheme.unwrap_or_else(|| "Classical".into()),
            capabilities: m.capabilities.unwrap_or_default(),
            epoch: m.epoch.unwrap_or(0),
        })
        .collect())
}

pub async fn revoke(client: &HttpClient, machine_id: &Uuid) -> Result<(), AppError> {
    client
        .delete_no_body(&format!("/v1/machines/{machine_id}"))
        .await
}
