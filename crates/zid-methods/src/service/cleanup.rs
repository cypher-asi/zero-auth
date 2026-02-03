//! Cleanup routines for expired data.
//!
//! This module provides background cleanup functionality for:
//! - Expired used nonces (replay attack prevention)
//! - Expired OAuth states
//! - Expired challenges

use crate::errors::*;
use tracing::{debug, info, warn};
use zid_crypto::current_timestamp;
use zid_identity_core::IdentityCore;
use zid_policy::PolicyEngine;
use zid_storage::Storage;

use super::{AuthMethodsService, CF_CHALLENGES, CF_OAUTH_STATES, CF_USED_NONCES};

/// Default cleanup interval in seconds (5 minutes)
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300;

/// Maximum number of entries to process per cleanup run
const MAX_ENTRIES_PER_RUN: usize = 10_000;

/// Cleanup statistics
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    /// Number of expired nonces removed
    pub nonces_removed: usize,
    /// Number of expired challenges removed
    pub challenges_removed: usize,
    /// Number of expired OAuth states removed
    pub oauth_states_removed: usize,
    /// Total duration of cleanup in milliseconds
    pub duration_ms: u64,
}

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Perform cleanup of expired data.
    ///
    /// This method should be called periodically (e.g., every 5 minutes) to
    /// remove expired entries and prevent unbounded growth of:
    /// - Used nonces (stored for replay attack prevention)
    /// - Expired challenges
    /// - Expired OAuth states
    ///
    /// # Returns
    ///
    /// Statistics about what was cleaned up
    pub async fn cleanup_expired_data(&self) -> Result<CleanupStats> {
        let start = std::time::Instant::now();
        let current_time = current_timestamp();

        debug!("Starting cleanup of expired data at timestamp {}", current_time);

        let nonces_removed = self.cleanup_expired_nonces(current_time).await?;
        let challenges_removed = self.cleanup_expired_challenges(current_time).await?;
        let oauth_states_removed = self.cleanup_expired_oauth_states(current_time).await?;

        let duration_ms = start.elapsed().as_millis() as u64;

        let stats = CleanupStats {
            nonces_removed,
            challenges_removed,
            oauth_states_removed,
            duration_ms,
        };

        if stats.nonces_removed > 0 || stats.challenges_removed > 0 || stats.oauth_states_removed > 0
        {
            info!(
                nonces = stats.nonces_removed,
                challenges = stats.challenges_removed,
                oauth_states = stats.oauth_states_removed,
                duration_ms = stats.duration_ms,
                "Cleanup completed"
            );
        } else {
            debug!(duration_ms = stats.duration_ms, "Cleanup completed with no expired entries");
        }

        Ok(stats)
    }

    /// Clean up expired used nonces.
    ///
    /// Nonces are stored with their expiry timestamp as the value.
    /// This method scans for nonces whose expiry has passed.
    async fn cleanup_expired_nonces(&self, current_time: u64) -> Result<usize> {
        let entries: Vec<(Vec<u8>, u64)> = self
            .storage
            .scan_all(CF_USED_NONCES)
            .await
            .map_err(AuthMethodsError::Storage)?;

        let mut removed = 0;
        let mut batch = self.storage.batch();

        for (key, expiry_time) in entries.into_iter().take(MAX_ENTRIES_PER_RUN) {
            if current_time > expiry_time {
                // Use raw delete since we have the key bytes directly
                if let Err(e) = batch.delete_raw(CF_USED_NONCES, key.clone()) {
                    warn!("Failed to queue nonce deletion: {}", e);
                    continue;
                }
                removed += 1;
            }
        }

        if removed > 0 {
            batch.commit().await.map_err(AuthMethodsError::Storage)?;
            debug!("Removed {} expired nonces", removed);
        } else {
            batch.rollback();
        }

        Ok(removed)
    }

    /// Clean up expired challenges.
    ///
    /// Challenges have an `exp` field indicating their expiry time.
    async fn cleanup_expired_challenges(&self, current_time: u64) -> Result<usize> {
        use zid_crypto::Challenge;

        let entries: Vec<(Vec<u8>, Challenge)> = self
            .storage
            .scan_all(CF_CHALLENGES)
            .await
            .map_err(AuthMethodsError::Storage)?;

        let mut removed = 0;
        let mut batch = self.storage.batch();

        for (key, challenge) in entries.into_iter().take(MAX_ENTRIES_PER_RUN) {
            if current_time > challenge.exp {
                if let Err(e) = batch.delete_raw(CF_CHALLENGES, key.clone()) {
                    warn!("Failed to queue challenge deletion: {}", e);
                    continue;
                }
                removed += 1;
            }
        }

        if removed > 0 {
            batch.commit().await.map_err(AuthMethodsError::Storage)?;
            debug!("Removed {} expired challenges", removed);
        } else {
            batch.rollback();
        }

        Ok(removed)
    }

    /// Clean up expired OAuth states.
    ///
    /// OAuth states have a `created_at` field and expire after 10 minutes.
    async fn cleanup_expired_oauth_states(&self, current_time: u64) -> Result<usize> {
        use crate::types::OAuthState;

        const OAUTH_STATE_TTL_SECS: u64 = 600; // 10 minutes

        let entries: Vec<(Vec<u8>, OAuthState)> = self
            .storage
            .scan_all(CF_OAUTH_STATES)
            .await
            .map_err(AuthMethodsError::Storage)?;

        let mut removed = 0;
        let mut batch = self.storage.batch();

        for (key, state) in entries.into_iter().take(MAX_ENTRIES_PER_RUN) {
            if current_time > state.created_at + OAUTH_STATE_TTL_SECS {
                if let Err(e) = batch.delete_raw(CF_OAUTH_STATES, key.clone()) {
                    warn!("Failed to queue OAuth state deletion: {}", e);
                    continue;
                }
                removed += 1;
            }
        }

        if removed > 0 {
            batch.commit().await.map_err(AuthMethodsError::Storage)?;
            debug!("Removed {} expired OAuth states", removed);
        } else {
            batch.rollback();
        }

        Ok(removed)
    }
}

/// Start a background cleanup task that runs periodically.
///
/// This function spawns a tokio task that periodically calls `cleanup_expired_data`
/// on the provided service.
///
/// # Arguments
///
/// * `service` - The auth methods service to perform cleanup on
/// * `interval_secs` - Cleanup interval in seconds (use `DEFAULT_CLEANUP_INTERVAL_SECS` for default)
///
/// # Returns
///
/// A `tokio::task::JoinHandle` for the background task
pub fn start_cleanup_task<I, P, S>(
    service: std::sync::Arc<AuthMethodsService<I, P, S>>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()>
where
    I: IdentityCore + 'static,
    P: PolicyEngine + 'static,
    S: Storage + 'static,
{
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        // Skip the first immediate tick
        interval.tick().await;

        info!(
            interval_secs = interval_secs,
            "Started nonce cleanup background task"
        );

        loop {
            interval.tick().await;

            match service.cleanup_expired_data().await {
                Ok(_stats) => {
                    // Stats are logged inside cleanup_expired_data
                }
                Err(e) => {
                    warn!("Cleanup task error: {}", e);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_stats_default() {
        let stats = CleanupStats::default();
        assert_eq!(stats.nonces_removed, 0);
        assert_eq!(stats.challenges_removed, 0);
        assert_eq!(stats.oauth_states_removed, 0);
        assert_eq!(stats.duration_ms, 0);
    }
}
