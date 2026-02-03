//! # zid-policy
//!
//! Policy Engine for authorization, rate limiting, and approval requirements.

#![warn(clippy::all)]

pub mod engine;
pub mod errors;
pub mod evaluator;
pub mod rate_limit;
pub mod types;

pub use engine::{PolicyEngine, PolicyEngineImpl};
pub use errors::{PolicyError, Result};
pub use evaluator::PolicyEvaluator;
pub use rate_limit::{AsyncRateLimiter, LimitState, PersistentRateLimiter, RateLimiter};
pub use types::*;
