use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::infra::crypto_adapter;
use crate::infra::http_client::HttpClient;
use crate::service::key_shard::{self, ShardSet};
use crate::state::types::{FreezeReason, IdentityViewModel};

#[derive(Serialize)]
struct CreateIdentityBody {
    identity_id: Uuid,
    machine_id: Uuid,
    identity_signing_public_key: String,
    machine_signing_public_key: String,
    machine_encryption_public_key: String,
    authorization_signature: String,
    device_name: String,
    device_platform: String,
    neural_key_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_signing_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_encryption_public_key: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CreateIdentityResponse {
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub created_at: String,
}

#[derive(Deserialize, Debug)]
pub struct IdentityResponse {
    pub identity_id: Uuid,
    #[serde(default)]
    pub did: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub frozen: Option<bool>,
    #[serde(default)]
    pub freeze_reason: Option<String>,
}

#[derive(Serialize)]
struct FreezeBody {
    reason: String,
}

pub struct IdentityCreationResult {
    pub response: CreateIdentityResponse,
    pub shard_set: ShardSet,
    pub encrypted_machine_seed: Vec<u8>,
    pub machine_key_nonce: [u8; 24],
    pub isk_public: [u8; 32],
    pub machine_signing_pub: String,
    pub machine_encryption_pub: String,
}

pub async fn create_self_sovereign(
    client: &HttpClient,
    passphrase: &str,
    device_name: &str,
    device_platform: &str,
) -> Result<IdentityCreationResult, AppError> {
    let neural_key = key_shard::generate_neural_key();
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();

    let keys = key_shard::derive_keys(&neural_key, &identity_id, &machine_id, 0)?;
    let pk = crypto_adapter::extract_machine_public_keys(&keys.machine_keypair);

    let (sig, _msg) = crypto_adapter::sign_creation_message(
        &keys.isk_keypair,
        &identity_id,
        &machine_id,
        &keys.isk_public,
        &pk.signing,
        &pk.encryption,
    );

    let commitment = crypto_adapter::neural_key_commitment(&neural_key);

    let body = CreateIdentityBody {
        identity_id,
        machine_id,
        identity_signing_public_key: hex::encode(keys.isk_public),
        machine_signing_public_key: hex::encode(pk.signing),
        machine_encryption_public_key: hex::encode(pk.encryption),
        authorization_signature: hex::encode(sig),
        device_name: device_name.to_string(),
        device_platform: device_platform.to_string(),
        neural_key_commitment: hex::encode(commitment),
        pq_signing_public_key: Some(hex::encode(&pk.pq_signing)),
        pq_encryption_public_key: Some(hex::encode(&pk.pq_encryption)),
    };

    let response: CreateIdentityResponse = client.post("/v1/identity", &body).await?;

    let shard_set = key_shard::split_and_encrypt(&neural_key, &response.identity_id, passphrase)?;

    let (encrypted_machine_seed, machine_key_nonce) =
        key_shard::encrypt_machine_seed_for_storage(
            &keys.machine_keypair,
            passphrase,
            &shard_set.salt,
            &response.identity_id,
        )?;

    Ok(IdentityCreationResult {
        response,
        shard_set,
        encrypted_machine_seed,
        machine_key_nonce,
        isk_public: keys.isk_public,
        machine_signing_pub: hex::encode(pk.signing),
        machine_encryption_pub: hex::encode(pk.encryption),
    })
}

pub async fn get_current(client: &HttpClient) -> Result<IdentityViewModel, AppError> {
    let resp: IdentityResponse = client.get("/v1/identity").await?;
    Ok(IdentityViewModel {
        identity_id: resp.identity_id,
        did: resp.did.unwrap_or_default(),
        tier: resp.tier.unwrap_or_else(|| "SelfSovereign".into()),
        status: resp.status.unwrap_or_else(|| "Active".into()),
        created_at: resp.created_at.unwrap_or_default(),
        updated_at: resp.updated_at.unwrap_or_default(),
        frozen: resp.frozen.unwrap_or(false),
        freeze_reason: resp.freeze_reason,
    })
}

pub async fn freeze(client: &HttpClient, reason: FreezeReason) -> Result<(), AppError> {
    let body = FreezeBody {
        reason: reason.as_str().to_string(),
    };
    let _: serde_json::Value = client.post("/v1/identity/freeze", &body).await?;
    Ok(())
}

pub async fn disable(client: &HttpClient) -> Result<(), AppError> {
    let _: serde_json::Value = client
        .post("/v1/identity/disable", &serde_json::json!({}))
        .await?;
    Ok(())
}

pub async fn enable(client: &HttpClient) -> Result<(), AppError> {
    let _: serde_json::Value = client
        .post("/v1/identity/enable", &serde_json::json!({}))
        .await?;
    Ok(())
}
