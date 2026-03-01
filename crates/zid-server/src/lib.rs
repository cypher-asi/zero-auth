pub mod config;
pub mod state;

mod api;
mod error;
mod extractors;
mod middleware;
mod request_context;
mod validation;

use axum::{
    http::{HeaderValue, Method},
    routing::{delete, get, patch, post},
    Router,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};

use config::Config;
use state::AppState;

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};

    let mut cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::PUT,
            Method::OPTIONS,
        ])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_credentials(true);

    for origin in allowed_origins {
        if let Ok(header_value) = origin.parse::<HeaderValue>() {
            cors = cors.allow_origin(header_value);
        } else {
            tracing::warn!("Invalid CORS origin: {}", origin);
        }
    }

    cors
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health checks
        .route("/health", get(api::health::health_check))
        .route("/ready", get(api::health::readiness_check))
        // Identity management (self-sovereign creation)
        .route("/v1/identity", get(api::identity::get_current_identity).post(api::identity::create_identity))
        // DID lookup (must come before :identity_id to avoid matching)
        .route(
            "/v1/identity/did/*did",
            get(api::identity::get_identity_by_did),
        )
        .route(
            "/v1/identity/:identity_id",
            get(api::identity::get_identity),
        )
        // Identity creation (managed tier)
        .route(
            "/v1/identity/email",
            post(api::identity_creation::create_email_identity),
        )
        .route(
            "/v1/identity/oauth/:provider",
            post(api::identity_creation::initiate_oauth_identity),
        )
        .route(
            "/v1/identity/oauth/:provider/callback",
            post(api::identity_creation::complete_oauth_identity),
        )
        .route(
            "/v1/identity/wallet/challenge",
            post(api::identity_creation::initiate_wallet_identity),
        )
        .route(
            "/v1/identity/wallet/verify",
            post(api::identity_creation::complete_wallet_identity),
        )
        // Identity tier and upgrade
        .route(
            "/v1/identity/tier",
            get(api::identity_creation::get_tier_status),
        )
        .route(
            "/v1/identity/upgrade",
            post(api::identity_creation::upgrade_identity),
        )
        // Ceremonies (self-sovereign only)
        .route("/v1/identity/freeze", post(api::identity::freeze_identity))
        .route(
            "/v1/identity/unfreeze",
            post(api::identity::unfreeze_identity),
        )
        .route(
            "/v1/identity/recovery",
            post(api::identity::recovery_ceremony),
        )
        .route(
            "/v1/identity/rotation",
            post(api::identity::rotation_ceremony),
        )
        // Machine key management
        .route("/v1/machines/enroll", post(api::machines::enroll_machine))
        .route("/v1/machines", get(api::machines::list_machines))
        .route(
            "/v1/machines/:machine_id",
            delete(api::machines::revoke_machine),
        )
        // Namespace management
        .route("/v1/namespaces", post(api::namespaces::create_namespace))
        .route("/v1/namespaces", get(api::namespaces::list_namespaces))
        .route(
            "/v1/namespaces/:namespace_id",
            get(api::namespaces::get_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id",
            patch(api::namespaces::update_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id/deactivate",
            post(api::namespaces::deactivate_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id/reactivate",
            post(api::namespaces::reactivate_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id",
            delete(api::namespaces::delete_namespace),
        )
        // Namespace members
        .route(
            "/v1/namespaces/:namespace_id/members",
            get(api::namespaces::list_members),
        )
        .route(
            "/v1/namespaces/:namespace_id/members",
            post(api::namespaces::add_member),
        )
        .route(
            "/v1/namespaces/:namespace_id/members/:identity_id",
            patch(api::namespaces::update_member),
        )
        .route(
            "/v1/namespaces/:namespace_id/members/:identity_id",
            delete(api::namespaces::remove_member),
        )
        // Authentication
        .route("/v1/auth/challenge", get(api::auth::get_challenge))
        .route("/v1/auth/login/machine", post(api::auth::login_machine))
        .route("/v1/auth/login/email", post(api::auth::login_email))
        .route(
            "/v1/auth/login/wallet",
            post(api::auth_wallet::login_wallet),
        )
        .route("/v1/auth/oauth/:provider", get(api::auth::oauth_initiate))
        .route(
            "/v1/auth/oauth/:provider/callback",
            post(api::auth::oauth_complete),
        )
        // MFA
        .route("/v1/mfa/setup", post(api::mfa::setup_mfa))
        .route("/v1/mfa/enable", post(api::mfa::enable_mfa))
        .route("/v1/mfa/disable", post(api::mfa::disable_mfa_post))
        .route("/v1/mfa", delete(api::mfa::disable_mfa))
        // Credentials
        .route(
            "/v1/credentials",
            get(api::credentials::list_credentials),
        )
        .route(
            "/v1/credentials/email",
            post(api::credentials::add_email_credential),
        )
        .route(
            "/v1/credentials/wallet",
            post(api::credentials::add_wallet_credential),
        )
        .route(
            "/v1/credentials/oauth/:provider",
            post(api::credentials::initiate_oauth_link),
        )
        .route(
            "/v1/credentials/oauth/:provider/callback",
            post(api::credentials::complete_oauth_link),
        )
        .route(
            "/v1/credentials/:method_type/:method_id",
            delete(api::credentials::revoke_credential),
        )
        .route(
            "/v1/credentials/:method_type/:method_id/primary",
            axum::routing::put(api::credentials::set_primary_credential),
        )
        // Sessions
        .route("/v1/auth/refresh", post(api::sessions::refresh_session))
        .route("/v1/session/revoke", post(api::sessions::revoke_session))
        .route(
            "/v1/session/revoke-all",
            post(api::sessions::revoke_all_sessions),
        )
        .route("/v1/auth/introspect", post(api::sessions::introspect_token))
        .route("/.well-known/jwks.json", get(api::sessions::jwks_endpoint))
        // Integrations
        .route(
            "/v1/integrations/register",
            post(api::integrations::register_service),
        )
        .route("/v1/events/stream", get(api::integrations::event_stream))
        // Middleware (order matters: last added = first executed)
        .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::default()))
        .layer(build_cors_layer(&state.config.cors_allowed_origins))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::request_id_middleware,
        ))
        .with_state(state)
}

/// Start the identity server as an embedded service within the current process.
///
/// Persists a service master key in `data_dir` so auth tokens survive app restarts.
/// Does NOT initialize tracing — the caller is expected to have done that already.
pub async fn start_embedded(bind_address: SocketAddr, data_dir: PathBuf) -> anyhow::Result<()> {
    std::fs::create_dir_all(&data_dir)?;

    let service_master_key = load_or_generate_key(&data_dir.join("server_master.key"))?;

    let config = Config {
        bind_address,
        database_path: data_dir.join("identity.db"),
        service_master_key,
        jwt_issuer: "https://zid.zero.tech".to_string(),
        jwt_audience: "zero-vault".to_string(),
        access_token_expiry: 900,
        refresh_token_expiry: 2_592_000,
        oauth_google: None,
        oauth_x: None,
        oauth_epic: None,
        cors_allowed_origins: vec![],
        trusted_proxies: vec![],
    };

    let state = Arc::new(AppState::new(config).await?);
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    tracing::info!("Embedded identity server listening on {}", bind_address);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn load_or_generate_key(key_path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    if key_path.exists() {
        let hex_str = std::fs::read_to_string(key_path)?;
        let hex_str = hex_str.trim();
        let bytes = hex::decode(hex_str)?;
        anyhow::ensure!(bytes.len() == 32, "Stored server key must be 32 bytes");
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    } else {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        std::fs::write(key_path, hex::encode(key))?;
        Ok(key)
    }
}
