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
        .post("/v1/identity/rotation", &serde_json::json!({}))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that RecoveryBody serializes with field names matching the server's
    /// expected request schema at POST /v1/identity/recovery.
    ///
    /// NOTE: The server currently defines RecoveryCeremonyRequest with only
    /// `new_identity_signing_public_key` (+ optional approvals), and the handler
    /// builds a placeholder MachineKey. This test documents what the client sends
    /// so the server can be updated to accept it. Until then, this endpoint will
    /// reject the client's payload.
    ///
    /// Server struct: zid-server/src/api/identity.rs :: RecoveryCeremonyRequest
    #[test]
    #[ignore = "server's RecoveryCeremonyRequest is a stub — needs updating to accept machine key data"]
    fn recovery_body_matches_server_contract() {
        let body = RecoveryBody {
            identity_id: Uuid::nil(),
            machine_id: Uuid::nil(),
            machine_signing_public_key: "ab".repeat(32),
            machine_encryption_public_key: "cd".repeat(32),
            authorization_signature: "ef".repeat(64),
            neural_key_commitment: "01".repeat(32),
            device_name: "Test Device".into(),
            device_platform: "test-os".into(),
            pq_signing_public_key: Some("aa".repeat(1952)),
            pq_encryption_public_key: Some("bb".repeat(1184)),
        };

        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = json.as_object().expect("RecoveryBody should serialize as a JSON object");

        // Fields the server should accept once RecoveryCeremonyRequest is updated.
        // Currently the server only expects: new_identity_signing_public_key
        let expected_fields = [
            "identity_id",
            "machine_id",
            "machine_signing_public_key",
            "machine_encryption_public_key",
            "authorization_signature",
            "neural_key_commitment",
            "device_name",
            "device_platform",
        ];

        for field in &expected_fields {
            assert!(
                obj.contains_key(*field),
                "RecoveryBody is missing field '{field}'"
            );
        }
    }
}
