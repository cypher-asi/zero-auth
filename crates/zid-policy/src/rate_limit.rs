//! Rate limiting implementation with optional persistence.
//!
//! Provides two rate limiter implementations:
//! - `RateLimiter`: In-memory only, fast but loses state on restart
//! - `PersistentRateLimiter`: Uses storage for persistence across restarts

use crate::{errors::PolicyError, types::RateLimit};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// Column family for rate limit persistence
pub const CF_RATE_LIMITS: &str = "rate_limits";

/// Rate limiter for tracking attempts per identity/IP
pub struct RateLimiter {
    limits: Arc<Mutex<HashMap<String, LimitState>>>,
}

/// Helper to handle mutex lock with poison recovery
fn lock_limits(
    mutex: &Mutex<HashMap<String, LimitState>>,
) -> Result<MutexGuard<'_, HashMap<String, LimitState>>, PolicyError> {
    mutex.lock().or_else(|poisoned| {
        // Recover the guard from the poisoned mutex - the data is still accessible
        // Log this in production but continue operating
        tracing::warn!("Rate limiter mutex was poisoned, recovering");
        Ok(poisoned.into_inner())
    })
}

const MAX_ENTRIES: usize = 10_000;

/// Rate limit state for a single key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitState {
    /// Number of attempts in current window
    pub attempts: u32,
    /// Unix timestamp when window started
    pub window_start: u64,
    /// Window duration in seconds
    pub window_seconds: u64,
    /// Maximum allowed attempts
    pub max_attempts: u32,
    /// Last time this key was accessed
    pub last_seen: u64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new() -> Self {
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a key is rate limited
    ///
    /// Returns `Some(RateLimit)` with remaining attempts, or `None` if rate limited
    pub fn check(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) -> Option<RateLimit> {
        let mut limits = match lock_limits(&self.limits) {
            Ok(guard) => guard,
            Err(_) => return None, // If lock is poisoned, deny requests as a safety measure
        };

        let rate_limit = {
            let state = limits.entry(key.to_string()).or_insert(LimitState {
                attempts: 0,
                window_start: current_time,
                window_seconds,
                max_attempts,
                last_seen: current_time,
            });

            // Check if window has expired
            if current_time >= state.window_start + state.window_seconds {
                // Reset window
                state.window_start = current_time;
                state.attempts = 0;
            }

            // Check if rate limited
            if state.attempts >= state.max_attempts {
                None
            } else {
                // Increment attempts
                state.attempts += 1;
                state.last_seen = current_time;

                Some(RateLimit {
                    window_seconds: state.window_seconds,
                    max_attempts: state.max_attempts,
                    remaining: state.max_attempts - state.attempts,
                    reset_at: state.window_start + state.window_seconds,
                })
            }
        };

        cleanup_limits(&mut limits, current_time);

        rate_limit
    }

    /// Record a failed attempt
    pub fn record_failure(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) {
        let mut limits = match lock_limits(&self.limits) {
            Ok(guard) => guard,
            Err(_) => return, // If lock is poisoned, skip recording but don't panic
        };

        {
            let state = limits.entry(key.to_string()).or_insert(LimitState {
                attempts: 0,
                window_start: current_time,
                window_seconds,
                max_attempts,
                last_seen: current_time,
            });

            // Check if window has expired
            if current_time >= state.window_start + state.window_seconds {
                // Reset window
                state.window_start = current_time;
                state.attempts = 0;
            }

            state.attempts += 1;
            state.last_seen = current_time;
        }

        cleanup_limits(&mut limits, current_time);
    }

    /// Reset rate limit for a key
    pub fn reset(&self, key: &str) {
        if let Ok(mut limits) = lock_limits(&self.limits) {
            limits.remove(key);
        }
    }

    /// Clear all rate limits (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut limits) = lock_limits(&self.limits) {
            limits.clear();
        }
    }
}

fn cleanup_limits(limits: &mut HashMap<String, LimitState>, current_time: u64) {
    if limits.len() <= MAX_ENTRIES {
        return;
    }

    remove_expired(limits, current_time);

    if limits.len() > MAX_ENTRIES {
        evict_oldest(limits);
    }
}

fn remove_expired(limits: &mut HashMap<String, LimitState>, current_time: u64) {
    limits.retain(|_, state| current_time < state.window_start + state.window_seconds);
}

fn evict_oldest(limits: &mut HashMap<String, LimitState>) {
    let mut entries: Vec<_> = limits
        .iter()
        .map(|(key, state)| (key.clone(), state.last_seen))
        .collect();

    entries.sort_by_key(|(_, last_seen)| *last_seen);
    let remove_count = limits.len().saturating_sub(MAX_ENTRIES);

    for (key, _) in entries.into_iter().take(remove_count) {
        limits.remove(&key);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Persistent Rate Limiter
// ============================================================================

use async_trait::async_trait;
use zid_storage::Storage;

/// Persistent rate limiter that stores state in RocksDB
///
/// Uses a write-through cache strategy:
/// - In-memory cache for fast lookups
/// - Async persistence to storage on every write
/// - Loads state from storage on startup
pub struct PersistentRateLimiter<S: Storage> {
    /// In-memory cache for fast access
    cache: Arc<Mutex<HashMap<String, LimitState>>>,
    /// Storage backend for persistence
    storage: Arc<S>,
}

impl<S: Storage> PersistentRateLimiter<S> {
    /// Create a new persistent rate limiter
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            storage,
        }
    }

    /// Load rate limit state from storage into memory cache
    ///
    /// Should be called at startup to restore state
    pub async fn load_from_storage(&self) -> Result<usize, PolicyError> {
        let entries: Vec<(Vec<u8>, LimitState)> = self
            .storage
            .scan_all(CF_RATE_LIMITS)
            .await
            .map_err(|e| PolicyError::StorageError(e.to_string()))?;

        let current_time = Self::current_time();
        let mut cache = lock_limits(&self.cache)?;

        let mut loaded = 0;
        for (key_bytes, state) in entries {
            // Skip expired entries
            if current_time >= state.window_start + state.window_seconds {
                continue;
            }

            // Deserialize key (try bincode first since that's what we use to store)
            let key: Option<String> = bincode::deserialize(&key_bytes).ok();
            
            if let Some(key) = key {
                cache.insert(key, state);
                loaded += 1;
            } else {
                tracing::debug!(
                    "Failed to deserialize rate limit key, skipping"
                );
            }
        }

        tracing::info!(loaded = loaded, "Loaded rate limit state from storage");
        Ok(loaded)
    }

    /// Check if a key is rate limited (with persistence)
    ///
    /// Returns `Some(RateLimit)` with remaining attempts, or `None` if rate limited
    pub async fn check(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) -> Option<RateLimit> {
        let rate_limit = {
            let mut cache = match lock_limits(&self.cache) {
                Ok(guard) => guard,
                Err(_) => return None,
            };

            let state = cache.entry(key.to_string()).or_insert(LimitState {
                attempts: 0,
                window_start: current_time,
                window_seconds,
                max_attempts,
                last_seen: current_time,
            });

            // Check if window has expired
            if current_time >= state.window_start + state.window_seconds {
                state.window_start = current_time;
                state.attempts = 0;
            }

            // Check if rate limited
            if state.attempts >= state.max_attempts {
                None
            } else {
                state.attempts += 1;
                state.last_seen = current_time;

                Some((
                    RateLimit {
                        window_seconds: state.window_seconds,
                        max_attempts: state.max_attempts,
                        remaining: state.max_attempts - state.attempts,
                        reset_at: state.window_start + state.window_seconds,
                    },
                    state.clone(),
                ))
            }
        };

        // Persist state asynchronously
        if let Some((rate_limit, state)) = rate_limit {
            self.persist_state(key, &state).await;
            cleanup_limits_async(&self.cache, current_time);
            Some(rate_limit)
        } else {
            None
        }
    }

    /// Record a failed attempt (with persistence)
    pub async fn record_failure(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) {
        let state = {
            let mut cache = match lock_limits(&self.cache) {
                Ok(guard) => guard,
                Err(_) => return,
            };

            let state = cache.entry(key.to_string()).or_insert(LimitState {
                attempts: 0,
                window_start: current_time,
                window_seconds,
                max_attempts,
                last_seen: current_time,
            });

            // Check if window has expired
            if current_time >= state.window_start + state.window_seconds {
                state.window_start = current_time;
                state.attempts = 0;
            }

            state.attempts += 1;
            state.last_seen = current_time;

            state.clone()
        };

        self.persist_state(key, &state).await;
        cleanup_limits_async(&self.cache, current_time);
    }

    /// Reset rate limit for a key (with persistence)
    pub async fn reset(&self, key: &str) {
        if let Ok(mut cache) = lock_limits(&self.cache) {
            cache.remove(key);
        }

        // Delete from storage
        if let Err(e) = self.storage.delete(CF_RATE_LIMITS, &key.to_string()).await {
            tracing::warn!(key = key, error = %e, "Failed to delete rate limit from storage");
        }
    }

    /// Persist state to storage
    async fn persist_state(&self, key: &str, state: &LimitState) {
        if let Err(e) = self.storage.put(CF_RATE_LIMITS, &key.to_string(), state).await {
            tracing::warn!(
                key = key,
                error = %e,
                "Failed to persist rate limit state, continuing with in-memory only"
            );
        }
    }

    /// Get current timestamp
    fn current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

fn cleanup_limits_async(cache: &Mutex<HashMap<String, LimitState>>, current_time: u64) {
    if let Ok(mut limits) = lock_limits(cache) {
        if limits.len() > MAX_ENTRIES {
            remove_expired(&mut limits, current_time);
            if limits.len() > MAX_ENTRIES {
                evict_oldest(&mut limits);
            }
        }
    }
}

/// Async trait for rate limiting operations
#[async_trait]
pub trait AsyncRateLimiter: Send + Sync {
    /// Check rate limit for a key
    async fn check_async(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) -> Option<RateLimit>;

    /// Record a failed attempt
    async fn record_failure_async(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    );

    /// Reset rate limit for a key
    async fn reset_async(&self, key: &str);
}

#[async_trait]
impl<S: Storage + 'static> AsyncRateLimiter for PersistentRateLimiter<S> {
    async fn check_async(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) -> Option<RateLimit> {
        self.check(key, window_seconds, max_attempts, current_time).await
    }

    async fn record_failure_async(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) {
        self.record_failure(key, window_seconds, max_attempts, current_time).await
    }

    async fn reset_async(&self, key: &str) {
        self.reset(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allow() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_some());

        let limit = result.unwrap();
        assert_eq!(limit.remaining, 4);
    }

    #[test]
    fn test_rate_limit_exceed() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        // Use up all attempts
        for _ in 0..5 {
            let _ = limiter.check(key, 60, 5, 1000);
        }

        // Should be rate limited
        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        // Use up all attempts
        for _ in 0..5 {
            let _ = limiter.check(key, 60, 5, 1000);
        }

        // Should be rate limited
        assert!(limiter.check(key, 60, 5, 1000).is_none());

        // Move past window
        let result = limiter.check(key, 60, 5, 1061);
        assert!(result.is_some());

        let limit = result.unwrap();
        assert_eq!(limit.remaining, 4);
    }

    #[test]
    fn test_rate_limit_reset() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        // Use up all attempts
        for _ in 0..5 {
            let _ = limiter.check(key, 60, 5, 1000);
        }

        // Reset
        limiter.reset(key);

        // Should be allowed
        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_some());
    }

    #[test]
    fn test_record_failure() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        limiter.record_failure(key, 60, 5, 1000);
        limiter.record_failure(key, 60, 5, 1000);

        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_some());

        let limit = result.unwrap();
        assert_eq!(limit.remaining, 2); // 2 failures + 1 check = 3 attempts used
    }
}
