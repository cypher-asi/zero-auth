use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::infra::{crypto_adapter, http_client::HttpClient};

#[derive(Serialize)]
struct Approval {
    machine_id: Uuid,
    signature: String,
    timestamp: String,
}

#[derive(Serialize)]
struct UnfreezeBody {
    approvals: Vec<Approval>,
}

#[derive(Serialize)]
struct RecoveryBody {
    identity_id: Uuid,
    machine_id: Uuid,
    machine_signing_public_key: String,
    machine_encryption_public_key: String,
    authorization_signature: String,
    neural_key_commitment: String,
    device_name: String,
    device_platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_signing_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_encryption_public_key: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct RecoveryResponse {
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub created_at: String,
}

pub async fn unfreeze(
    client: &HttpClient,
    approvals: Vec<(Uuid, String, String)>,
) -> Result<(), AppError> {
    let body = UnfreezeBody {
        approvals: approvals
            .into_iter()
            .map(|(mid, sig, ts)| Approval {
                machine_id: mid,
                signature: sig,
                timestamp: ts,
            })
            .collect(),
    };
    let _: serde_json::Value = client.post("/v1/identity/unfreeze", &body).await?;
    Ok(())
}

pub async fn recover(
    client: &HttpClient,
    neural_key: &zid_crypto::NeuralKey,
    identity_id: &Uuid,
    device_name: &str,
    device_platform: &str,
) -> Result<RecoveryResponse, AppError> {
    let machine_id = Uuid::new_v4();

    let keys = crate::service::key_shard::derive_keys(neural_key, identity_id, &machine_id, 0)?;
    let pk = crypto_adapter::extract_machine_public_keys(&keys.machine_keypair);

    let (sig, _) = crypto_adapter::sign_enrollment_message(
        &keys.isk_keypair,
        identity_id,
        &machine_id,
        &pk.signing,
        &pk.encryption,
    );

    let commitment = crypto_adapter::neural_key_commitment(neural_key);

    let body = RecoveryBody {
        identity_id: *identity_id,
        machine_id,
        machine_signing_public_key: hex::encode(pk.signing),
        machine_encryption_public_key: hex::encode(pk.encryption),
        authorization_signature: hex::encode(sig),
        neural_key_commitment: hex::encode(commitment),
        device_name: device_name.to_string(),
        device_platform: device_platform.to_string(),
        pq_signing_public_key: Some(hex::encode(&pk.pq_signing)),
        pq_encryption_public_key: Some(hex::encode(&pk.pq_encryption)),
    };

    client.post("/v1/identity/recovery", &body).await
}

pub async fn rotate_key(client: &HttpClient) -> Result<(), AppError> {
    let _: serde_json::Value = client
        .post("/v1/identity/rotate", &serde_json::json!({}))
        .await?;
    Ok(())
}
