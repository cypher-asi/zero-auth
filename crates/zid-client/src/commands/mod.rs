/*!
 * Command implementations
 */

use anyhow::{Context, Result};
use std::time::Duration;

pub mod auth;
pub mod credentials;
pub mod identity;
pub mod machines;
pub mod recovery;
pub mod show;
pub mod tokens;

/// Default timeout for HTTP requests (30 seconds)
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Default connection timeout (10 seconds)
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Create a new HTTP client with configured timeouts
pub(crate) fn create_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .build()
        .context("Failed to create HTTP client")
}
