use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use zid_crypto::{OpaqueServerSetup, deserialize_server_setup, generate_server_setup, serialize_server_setup};
use zid_identity_core::IdentityCoreService;
use zid_integrations::IntegrationsService;
use zid_methods::AuthMethodsService;
use zid_policy::PolicyEngineImpl;
use zid_sessions::{NoOpEventPublisher, SessionService};
use zid_storage::{column_families::CF_OPAQUE_SERVER_SETUP, RocksDbStorage};

use crate::config::Config;

/// Key used to store the single ServerSetup record
const OPAQUE_SETUP_KEY: &str = "setup";

/// No-op event publisher for identity core (we'll use integrations for real events)
#[derive(Clone)]
pub struct IdentityNoOpPublisher;

#[async_trait]
impl zid_identity_core::EventPublisher for IdentityNoOpPublisher {
    async fn publish(
        &self,
        _event: zid_identity_core::RevocationEvent,
    ) -> zid_identity_core::Result<()> {
        Ok(())
    }
}

/// Type alias for the policy engine with RocksDB storage
pub type PolicyEngine = PolicyEngineImpl<RocksDbStorage>;

/// Type alias for identity service with standard dependencies
pub type IdentityService = IdentityCoreService<PolicyEngine, IdentityNoOpPublisher, RocksDbStorage>;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Server configuration for admin/ops endpoints and diagnostics.
    pub config: Config,
    /// Direct storage handle for health checks and admin queries.
    pub storage: Arc<RocksDbStorage>,
    pub identity_service: Arc<IdentityService>,
    pub auth_service: Arc<AuthMethodsService<IdentityService, PolicyEngine, RocksDbStorage>>,
    pub session_service:
        Arc<SessionService<RocksDbStorage, IdentityService, NoOpEventPublisher>>,
    pub integrations_service: Arc<IntegrationsService<RocksDbStorage>>,
    /// Policy engine handle for policy-aware endpoints.
    pub policy_engine: Arc<PolicyEngine>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize storage
        let storage = Arc::new(RocksDbStorage::open(&config.database_path)?);

        // Initialize policy engine with storage for persistent reputation and rate limits
        let policy_engine = Arc::new(PolicyEngineImpl::new(Arc::clone(&storage)));

        // Load rate limit state from storage (prevents bypass via restart)
        if let Err(e) = policy_engine.initialize().await {
            tracing::warn!(error = %e, "Failed to initialize policy engine, continuing with fresh state");
        }

        // Initialize services
        let identity_service = Arc::new(IdentityCoreService::new(
            policy_engine.clone(),
            Arc::new(IdentityNoOpPublisher),
            storage.clone(),
        ));

        // Build OAuth configs from environment
        let oauth_configs = zid_methods::OAuthConfigs {
            google: config
                .oauth_google
                .as_ref()
                .map(|c| zid_methods::OAuthProviderConfig {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    redirect_uri: c.redirect_uri.clone(),
                }),
            x: config
                .oauth_x
                .as_ref()
                .map(|c| zid_methods::OAuthProviderConfig {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    redirect_uri: c.redirect_uri.clone(),
                }),
            epic_games: config.oauth_epic.as_ref().map(|c| {
                zid_methods::OAuthProviderConfig {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    redirect_uri: c.redirect_uri.clone(),
                }
            }),
        };

        // Load or generate the node-local OPAQUE ServerSetup
        let opaque_server_setup = load_or_generate_opaque_setup(&storage, &config.service_master_key)?;
        let opaque_server_setup = Arc::new(opaque_server_setup);

        let auth_service = Arc::new(AuthMethodsService::with_oauth_configs(
            identity_service.clone(),
            policy_engine.clone(),
            storage.clone(),
            config.service_master_key,
            oauth_configs,
            opaque_server_setup,
        ));

        let session_service = Arc::new(SessionService::with_event_publisher(
            storage.clone(),
            identity_service.clone(),
            Arc::new(NoOpEventPublisher),
            config.service_master_key,
            config.jwt_issuer.clone(),
            vec![config.jwt_audience.clone()],
            config.access_token_expiry,
            config.refresh_token_expiry,
        ));

        let integrations_service = Arc::new(IntegrationsService::new(storage.clone()));

        // Initialize session service signing keys
        session_service.initialize().await?;

        // Start background cleanup task for expired nonces, challenges, and OAuth states
        // This prevents unbounded growth of replay-prevention data
        let cleanup_service = auth_service.clone();
        let _cleanup_handle = zid_methods::start_cleanup_task(
            cleanup_service,
            zid_methods::DEFAULT_CLEANUP_INTERVAL_SECS,
        );

        tracing::info!(
            interval_secs = zid_methods::DEFAULT_CLEANUP_INTERVAL_SECS,
            "Started background cleanup task"
        );

        Ok(AppState {
            config,
            storage,
            identity_service,
            auth_service,
            session_service,
            integrations_service,
            policy_engine,
        })
    }
}

/// Load the OPAQUE `ServerSetup` from storage, or generate a new one on first boot.
///
/// The serialised blob is stored encrypted with XChaCha20-Poly1305 using a
/// key derived from the service master key.
fn load_or_generate_opaque_setup(
    storage: &RocksDbStorage,
    smk: &[u8; 32],
) -> Result<OpaqueServerSetup> {
    use zid_crypto::{decrypt, encrypt, hkdf_derive_32};

    let enc_key = hkdf_derive_32(smk, b"cypher:opaque:server-setup-kek:v1")?;

    let existing: Option<Vec<u8>> = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            zid_storage::Storage::get::<String, Vec<u8>>(storage, CF_OPAQUE_SERVER_SETUP, &OPAQUE_SETUP_KEY.to_string()).await
        })
    })?;

    if let Some(blob) = existing {
        if blob.len() > 24 {
            let (nonce_bytes, ciphertext) = blob.split_at(24);
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(nonce_bytes);
            let plaintext = decrypt(&enc_key, ciphertext, &nonce, b"")?;
            let setup = deserialize_server_setup(&plaintext)?;
            tracing::info!("Loaded existing OPAQUE ServerSetup");
            return Ok(setup);
        }
    }

    let setup = generate_server_setup();
    let serialised = serialize_server_setup(&setup)?;

    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let ciphertext = encrypt(&enc_key, &serialised, &nonce, b"")?;

    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            zid_storage::Storage::put(storage, CF_OPAQUE_SERVER_SETUP, &OPAQUE_SETUP_KEY.to_string(), &blob).await
        })
    })?;

    tracing::info!("Generated and stored new OPAQUE ServerSetup");
    Ok(setup)
}
