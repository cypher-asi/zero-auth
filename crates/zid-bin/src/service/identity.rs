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
    identity_signing_public_key: String,
    authorization_signature: String,
    machine_key: MachineKeyBody,
    namespace_name: String,
    created_at: u64,
}

#[derive(Serialize)]
struct MachineKeyBody {
    machine_id: Uuid,
    signing_public_key: String,
    encryption_public_key: String,
    capabilities: Vec<String>,
    device_name: String,
    device_platform: String,
    pq_signing_public_key: String,
    pq_encryption_public_key: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateIdentityResponse {
    pub identity_id: Uuid,
    pub did: String,
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

    let (sig, created_at) = crypto_adapter::sign_creation_message(
        &keys.isk_keypair,
        &identity_id,
        &machine_id,
        &keys.isk_public,
        &pk.signing,
        &pk.encryption,
    );

    let body = CreateIdentityBody {
        identity_id,
        identity_signing_public_key: hex::encode(keys.isk_public),
        authorization_signature: hex::encode(sig),
        machine_key: MachineKeyBody {
            machine_id,
            signing_public_key: hex::encode(pk.signing),
            encryption_public_key: hex::encode(pk.encryption),
            capabilities: vec!["FULL_DEVICE".to_string()],
            device_name: device_name.to_string(),
            device_platform: device_platform.to_string(),
            pq_signing_public_key: hex::encode(&pk.pq_signing),
            pq_encryption_public_key: hex::encode(&pk.pq_encryption),
        },
        namespace_name: format!("personal-{}", identity_id),
        created_at,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that CreateIdentityBody serializes with field names matching
    /// the server's CreateIdentityRequest (POST /v1/identity).
    ///
    /// Server struct: zid-server/src/api/identity.rs :: CreateIdentityRequest
    #[test]
    fn create_identity_body_matches_server_contract() {
        let body = CreateIdentityBody {
            identity_id: Uuid::nil(),
            identity_signing_public_key: "ab".repeat(32),
            authorization_signature: "cd".repeat(64),
            machine_key: MachineKeyBody {
                machine_id: Uuid::nil(),
                signing_public_key: "ef".repeat(32),
                encryption_public_key: "01".repeat(32),
                capabilities: vec!["FULL_DEVICE".into()],
                device_name: "Test Device".into(),
                device_platform: "test-os".into(),
                pq_signing_public_key: "aa".repeat(1952),
                pq_encryption_public_key: "bb".repeat(1184),
            },
            namespace_name: "test-namespace".into(),
            created_at: 1700000000,
        };

        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = json.as_object().expect("CreateIdentityBody should serialize as a JSON object");

        let required_fields = [
            "identity_id",
            "identity_signing_public_key",
            "authorization_signature",
            "machine_key",
            "namespace_name",
            "created_at",
        ];

        for field in &required_fields {
            assert!(
                obj.contains_key(*field),
                "CreateIdentityBody is missing field '{field}' required by server's CreateIdentityRequest"
            );
        }

        let mk = obj["machine_key"]
            .as_object()
            .expect("machine_key should be a nested JSON object");

        let mk_required_fields = [
            "machine_id",
            "signing_public_key",
            "encryption_public_key",
            "capabilities",
            "device_name",
            "device_platform",
            "pq_signing_public_key",
            "pq_encryption_public_key",
        ];

        for field in &mk_required_fields {
            assert!(
                mk.contains_key(*field),
                "machine_key is missing field '{field}' required by server's MachineKeyRequest"
            );
        }
    }

    #[test]
    fn create_identity_body_has_no_extraneous_fields() {
        let body = CreateIdentityBody {
            identity_id: Uuid::nil(),
            identity_signing_public_key: String::new(),
            authorization_signature: String::new(),
            machine_key: MachineKeyBody {
                machine_id: Uuid::nil(),
                signing_public_key: String::new(),
                encryption_public_key: String::new(),
                capabilities: vec![],
                device_name: String::new(),
                device_platform: String::new(),
                pq_signing_public_key: String::new(),
                pq_encryption_public_key: String::new(),
            },
            namespace_name: String::new(),
            created_at: 0,
        };

        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = json.as_object().unwrap();

        let known_top_level: std::collections::HashSet<&str> = [
            "identity_id",
            "identity_signing_public_key",
            "authorization_signature",
            "machine_key",
            "namespace_name",
            "created_at",
        ]
        .into_iter()
        .collect();

        for key in obj.keys() {
            assert!(
                known_top_level.contains(key.as_str()),
                "CreateIdentityBody has unexpected field '{key}' — update server and this test."
            );
        }

        let mk = obj["machine_key"].as_object().unwrap();
        let known_mk: std::collections::HashSet<&str> = [
            "machine_id",
            "signing_public_key",
            "encryption_public_key",
            "capabilities",
            "device_name",
            "device_platform",
            "pq_signing_public_key",
            "pq_encryption_public_key",
        ]
        .into_iter()
        .collect();

        for key in mk.keys() {
            assert!(
                known_mk.contains(key.as_str()),
                "machine_key has unexpected field '{key}' — update server and this test."
            );
        }
    }
}
