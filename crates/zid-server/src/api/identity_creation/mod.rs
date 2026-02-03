//! Identity creation API endpoints for managed identities.
//!
//! This module provides endpoints for creating new identities via:
//! - Email + password
//! - OAuth providers (Google, X, Epic Games)
//! - Wallet signatures (Ethereum, Solana)
//!
//! All identity creation endpoints return auth tokens (access_token, refresh_token)
//! so users are automatically logged in after signup.

mod handlers;
mod helpers;
mod types;

pub use handlers::{
    complete_oauth_identity, complete_wallet_identity, create_email_identity, get_tier_status,
    initiate_oauth_identity, initiate_wallet_identity, upgrade_identity,
};
