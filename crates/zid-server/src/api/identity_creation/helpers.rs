//! Helper functions for identity creation handlers.

use zid_methods::types::{OAuthProvider, WalletType};

use crate::error::ApiError;

pub fn parse_oauth_provider(provider: &str) -> Result<OAuthProvider, ApiError> {
    match provider.to_lowercase().as_str() {
        "google" => Ok(OAuthProvider::Google),
        "x" | "twitter" => Ok(OAuthProvider::X),
        "epic" | "epic_games" => Ok(OAuthProvider::EpicGames),
        _ => Err(ApiError::InvalidRequest(format!(
            "Unknown OAuth provider: {}",
            provider
        ))),
    }
}

pub fn parse_wallet_type(wallet_type: &str) -> Result<WalletType, ApiError> {
    match wallet_type.to_lowercase().as_str() {
        "ethereum" | "eth" => Ok(WalletType::Ethereum),
        "polygon" | "matic" => Ok(WalletType::Polygon),
        "arbitrum" | "arb" => Ok(WalletType::Arbitrum),
        "base" => Ok(WalletType::Base),
        "solana" | "sol" => Ok(WalletType::Solana),
        _ => Err(ApiError::InvalidRequest(format!(
            "Unknown wallet type: {}. Supported: ethereum, polygon, arbitrum, base, solana",
            wallet_type
        ))),
    }
}

pub fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;

    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn parse_hex_64(hex_str: &str) -> Result<[u8; 64], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;

    if bytes.len() != 64 {
        return Err(ApiError::InvalidRequest(format!(
            "Expected 64 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Format expires_at timestamp from expires_in seconds
pub fn format_expires_at(expires_in: u64) -> Result<String, ApiError> {
    use crate::api::helpers::format_timestamp_rfc3339;

    let now = chrono::Utc::now().timestamp() as u64;
    let expires_at = now
        .checked_add(expires_in)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Timestamp overflow")))?;

    format_timestamp_rfc3339(expires_at)
}

/// Get display name for OAuth provider
pub fn provider_display_name(provider: OAuthProvider) -> &'static str {
    match provider {
        OAuthProvider::Google => "Google",
        OAuthProvider::X => "X",
        OAuthProvider::EpicGames => "Epic Games",
    }
}

/// Truncate wallet address for display (e.g., "0x1234...5678")
pub fn truncate_wallet_address(address: &str) -> String {
    if address.len() <= 13 {
        return address.to_string();
    }

    // For EVM addresses (0x...) show first 6 and last 4
    if address.starts_with("0x") && address.len() >= 10 {
        format!("{}...{}", &address[..6], &address[address.len() - 4..])
    } else {
        // For other addresses (Solana base58) show first 4 and last 4
        format!("{}...{}", &address[..4], &address[address.len() - 4..])
    }
}
