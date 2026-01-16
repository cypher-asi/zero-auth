use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// OAuth provider configuration
#[derive(Clone)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

// Custom Debug implementation to prevent secret leakage
impl std::fmt::Debug for OAuthProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProviderConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the server to
    pub bind_address: SocketAddr,
    
    /// Path to RocksDB database
    pub database_path: PathBuf,
    
    /// Service master key (hex-encoded 32 bytes)
    pub service_master_key: [u8; 32],
    
    /// JWT issuer
    pub jwt_issuer: String,
    
    /// JWT audience
    pub jwt_audience: String,
    
    /// Access token expiry (seconds)
    pub access_token_expiry: u64,
    
    /// Refresh token expiry (seconds)
    pub refresh_token_expiry: u64,
    
    /// OAuth provider configurations
    pub oauth_google: Option<OAuthProviderConfig>,
    pub oauth_x: Option<OAuthProviderConfig>,
    pub oauth_epic: Option<OAuthProviderConfig>,
    
    /// CORS allowed origins (comma-separated list)
    pub cors_allowed_origins: Vec<String>,
    
    /// Trusted proxy IP addresses (for X-Forwarded-For validation)
    /// Only requests from these IPs will have their X-Forwarded-For header trusted
    #[allow(dead_code)] // TODO: Use this for rate limiting
    pub trusted_proxies: Vec<IpAddr>,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let bind_address = std::env::var("BIND_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()?;

        let database_path = std::env::var("DATABASE_PATH")
            .unwrap_or_else(|_| "./data/zero-auth.db".to_string())
            .into();

        let service_master_key = {
            let hex_key = std::env::var("SERVICE_MASTER_KEY")
                .expect("SERVICE_MASTER_KEY environment variable required");
            let bytes = hex::decode(&hex_key)?;
            if bytes.len() != 32 {
                anyhow::bail!("SERVICE_MASTER_KEY must be 32 bytes (64 hex chars)");
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        };

        let jwt_issuer = std::env::var("JWT_ISSUER")
            .unwrap_or_else(|_| "https://zero-auth.cypher.io".to_string());

        let jwt_audience = std::env::var("JWT_AUDIENCE")
            .unwrap_or_else(|_| "zero-vault".to_string());

        let access_token_expiry = std::env::var("ACCESS_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "900".to_string()) // 15 minutes
            .parse()?;

        let refresh_token_expiry = std::env::var("REFRESH_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "2592000".to_string()) // 30 days
            .parse()?;

        // OAuth configurations (optional)
        let oauth_google = if let (Ok(client_id), Ok(client_secret), Ok(redirect_uri)) = (
            std::env::var("OAUTH_GOOGLE_CLIENT_ID"),
            std::env::var("OAUTH_GOOGLE_CLIENT_SECRET"),
            std::env::var("OAUTH_GOOGLE_REDIRECT_URI"),
        ) {
            Some(OAuthProviderConfig {
                client_id,
                client_secret,
                redirect_uri,
            })
        } else {
            None
        };

        let oauth_x = if let (Ok(client_id), Ok(client_secret), Ok(redirect_uri)) = (
            std::env::var("OAUTH_X_CLIENT_ID"),
            std::env::var("OAUTH_X_CLIENT_SECRET"),
            std::env::var("OAUTH_X_REDIRECT_URI"),
        ) {
            Some(OAuthProviderConfig {
                client_id,
                client_secret,
                redirect_uri,
            })
        } else {
            None
        };

        let oauth_epic = if let (Ok(client_id), Ok(client_secret), Ok(redirect_uri)) = (
            std::env::var("OAUTH_EPIC_CLIENT_ID"),
            std::env::var("OAUTH_EPIC_CLIENT_SECRET"),
            std::env::var("OAUTH_EPIC_REDIRECT_URI"),
        ) {
            Some(OAuthProviderConfig {
                client_id,
                client_secret,
                redirect_uri,
            })
        } else {
            None
        };

        // CORS configuration
        let cors_allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Trusted proxies configuration (for X-Forwarded-For validation)
        // Format: comma-separated list of IP addresses
        // Example: "10.0.0.1,172.16.0.1,192.168.1.1"
        let trusted_proxies = std::env::var("TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                s.parse::<IpAddr>().ok().or_else(|| {
                    eprintln!("Warning: Invalid IP address in TRUSTED_PROXIES: {}", s);
                    None
                })
            })
            .collect();

        Ok(Config {
            bind_address,
            database_path,
            service_master_key,
            jwt_issuer,
            jwt_audience,
            access_token_expiry,
            refresh_token_expiry,
            oauth_google,
            oauth_x,
            oauth_epic,
            cors_allowed_origins,
            trusted_proxies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_provider_config_debug_redacts_secret() {
        let config = OAuthProviderConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "super_secret_key_67890".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
        };

        let debug_output = format!("{:?}", config);

        // Secret should be redacted
        assert!(!debug_output.contains("super_secret_key_67890"));
        assert!(debug_output.contains("[REDACTED]"));

        // Other fields should be visible
        assert!(debug_output.contains("test_client_id"));
        assert!(debug_output.contains("https://example.com/callback"));
    }
}
