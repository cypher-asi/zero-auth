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
    signing_public_key: String,
    encryption_public_key: String,
    capabilities: Vec<String>,
    authorization_signature: String,
    device_name: String,
    device_platform: String,
    pq_signing_public_key: String,
    pq_encryption_public_key: String,
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
        signing_public_key: hex::encode(pk.signing),
        encryption_public_key: hex::encode(pk.encryption),
        capabilities: vec!["FULL_DEVICE".to_string()],
        authorization_signature: hex::encode(sig),
        device_name: device_name.to_string(),
        device_platform: device_platform.to_string(),
        pq_signing_public_key: hex::encode(&pk.pq_signing),
        pq_encryption_public_key: hex::encode(&pk.pq_encryption),
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
    #[derive(Serialize)]
    struct RevokeBody {
        reason: String,
    }

    let body = RevokeBody {
        reason: "Revoked by user".to_string(),
    };

    client
        .delete_with_body(&format!("/v1/machines/{machine_id}"), &body)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that EnrollBody serializes with field names matching
    /// the server's EnrollMachineRequest (POST /v1/machines/enroll).
    ///
    /// Server struct: zid-server/src/api/machines.rs :: EnrollMachineRequest
    #[test]
    fn enroll_body_matches_server_contract() {
        let body = EnrollBody {
            machine_id: Uuid::nil(),
            signing_public_key: "ab".repeat(32),
            encryption_public_key: "cd".repeat(32),
            capabilities: vec!["FULL_DEVICE".into()],
            authorization_signature: "ef".repeat(64),
            device_name: "Test Device".into(),
            device_platform: "test-os".into(),
            pq_signing_public_key: "aa".repeat(1952),
            pq_encryption_public_key: "bb".repeat(1184),
        };

        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = json.as_object().expect("EnrollBody should serialize as a JSON object");

        let required_fields = [
            "machine_id",
            "signing_public_key",
            "encryption_public_key",
            "capabilities",
            "device_name",
            "device_platform",
            "authorization_signature",
            "pq_signing_public_key",
            "pq_encryption_public_key",
        ];

        for field in &required_fields {
            assert!(
                obj.contains_key(*field),
                "EnrollBody is missing field '{field}' required by server's EnrollMachineRequest"
            );
        }
    }

    /// Guard against accidental field renames by checking no unexpected
    /// fields are present that the server would silently ignore.
    #[test]
    fn enroll_body_has_no_extraneous_fields() {
        let body = EnrollBody {
            machine_id: Uuid::nil(),
            signing_public_key: String::new(),
            encryption_public_key: String::new(),
            capabilities: vec![],
            authorization_signature: String::new(),
            device_name: String::new(),
            device_platform: String::new(),
            pq_signing_public_key: String::new(),
            pq_encryption_public_key: String::new(),
        };

        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = json.as_object().unwrap();

        let known_fields: std::collections::HashSet<&str> = [
            "machine_id",
            "signing_public_key",
            "encryption_public_key",
            "capabilities",
            "device_name",
            "device_platform",
            "authorization_signature",
            "pq_signing_public_key",
            "pq_encryption_public_key",
        ]
        .into_iter()
        .collect();

        for key in obj.keys() {
            assert!(
                known_fields.contains(key.as_str()),
                "EnrollBody has unexpected field '{key}' — server will ignore it. \
                 If intentional, update both the server's EnrollMachineRequest and this test."
            );
        }
    }
}
