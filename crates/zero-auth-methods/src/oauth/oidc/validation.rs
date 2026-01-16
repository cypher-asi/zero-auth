//! ID token validation with JWT signature verification.

use crate::errors::*;
use crate::oauth::oidc::discovery::discover_oidc_config;
use crate::oauth::oidc::jwks::{fetch_jwks_cached, fetch_jwks_fresh};
use crate::oauth::oidc::types::{IdTokenClaims, JwksCacheEntry};
use crate::oauth::types::OAuthProvider;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Get current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Validate ID token from OIDC provider (without caching)
pub async fn validate_id_token(
    id_token: &str,
    provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
) -> Result<IdTokenClaims> {
    // Step 1: Decode header to get key ID
    let header = decode_header(id_token)
        .map_err(|e| AuthMethodsError::JwtDecodeError(format!("Failed to decode header: {}", e)))?;

    let kid = header
        .kid
        .ok_or_else(|| AuthMethodsError::KeyNotFound {
            kid: "missing".to_string(),
        })?;

    // Step 2: Fetch OIDC configuration
    let oidc_config = discover_oidc_config(provider).await?;

    // Step 3: Fetch JWKS
    let jwks = crate::oauth::oidc::jwks::fetch_jwks(&oidc_config.jwks_uri).await?;

    // Step 4: Find matching key
    let jwk = jwks.find_key(&kid).ok_or_else(|| AuthMethodsError::KeyNotFound {
        kid: kid.clone(),
    })?;

    // Step 5: Verify algorithm
    if header.alg != Algorithm::RS256 {
        return Err(AuthMethodsError::InvalidAlgorithm {
            expected: "RS256".to_string(),
            got: format!("{:?}", header.alg),
        });
    }

    // Step 6: Build validation parameters
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&oidc_config.issuer]);
    validation.set_audience(&[expected_client_id]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.leeway = 60; // 60 second clock skew tolerance

    // Step 7: Create decoding key from RSA components (base64url strings)
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| AuthMethodsError::InvalidRsaKey(format!("Invalid RSA key: {}", e)))?;

    // Step 8: Validate JWT signature and claims
    let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| AuthMethodsError::InvalidJwtSignature(format!("JWT validation failed: {}", e)))?;

    let claims = token_data.claims;

    // Step 9: Verify nonce (CRITICAL for replay protection)
    let token_nonce = claims
        .nonce
        .as_ref()
        .ok_or(AuthMethodsError::MissingNonce)?;

    if token_nonce != expected_nonce {
        return Err(AuthMethodsError::NonceMismatch {
            expected: expected_nonce.to_string(),
            got: token_nonce.clone(),
        });
    }

    // Step 10: Additional timestamp validation
    let current_time = current_timestamp();

    if claims.exp < current_time {
        return Err(AuthMethodsError::TokenExpired {
            expired_at: claims.exp,
            current_time,
        });
    }

    if claims.iat > current_time + 60 {
        return Err(AuthMethodsError::TokenIssuedInFuture {
            issued_at: claims.iat,
            current_time,
        });
    }

    Ok(claims)
}

/// Validate ID token with automatic JWKS refresh on failure
pub async fn validate_id_token_with_cache(
    id_token: &str,
    provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
    jwks_cache: &Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>>,
) -> Result<IdTokenClaims> {
    // First attempt with cached JWKS
    match validate_id_token_internal(
        id_token,
        provider,
        expected_nonce,
        expected_client_id,
        jwks_cache,
        false,  // use cache
    ).await {
        Ok(claims) => Ok(claims),
        Err(AuthMethodsError::InvalidJwtSignature(_)) | Err(AuthMethodsError::KeyNotFound { .. }) => {
            // Signature validation failed or key not found - might be key rotation
            // Retry with fresh JWKS (only once)
            validate_id_token_internal(
                id_token,
                provider,
                expected_nonce,
                expected_client_id,
                jwks_cache,
                true,  // force refresh
            ).await
        }
        Err(e) => Err(e),
    }
}

/// Internal validation with cache control
async fn validate_id_token_internal(
    id_token: &str,
    provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
    jwks_cache: &Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>>,
    force_refresh: bool,
) -> Result<IdTokenClaims> {
    // Step 1: Decode header to get key ID
    let header = decode_header(id_token)
        .map_err(|e| AuthMethodsError::JwtDecodeError(format!("Failed to decode header: {}", e)))?;

    let kid = header
        .kid
        .ok_or_else(|| AuthMethodsError::KeyNotFound {
            kid: "missing".to_string(),
        })?;

    // Step 2: Get OIDC configuration (always fresh - it's small and rarely changes)
    let oidc_config = discover_oidc_config(provider).await?;

    // Step 3: Fetch JWKS (with or without cache)
    let jwks = if force_refresh {
        fetch_jwks_fresh(provider, jwks_cache).await?
    } else {
        fetch_jwks_cached(provider, jwks_cache).await?
    };

    // Step 4: Find matching key
    let jwk = jwks.find_key(&kid).ok_or_else(|| AuthMethodsError::KeyNotFound {
        kid: kid.clone(),
    })?;

    // Step 5: Verify algorithm
    if header.alg != Algorithm::RS256 {
        return Err(AuthMethodsError::InvalidAlgorithm {
            expected: "RS256".to_string(),
            got: format!("{:?}", header.alg),
        });
    }

    // Step 6: Build validation parameters
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&oidc_config.issuer]);
    validation.set_audience(&[expected_client_id]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.leeway = 60; // 60 second clock skew tolerance

    // Step 7: Create decoding key from RSA components (base64url strings)
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| AuthMethodsError::InvalidRsaKey(format!("Invalid RSA key: {}", e)))?;

    // Step 8: Validate JWT signature and claims
    let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| AuthMethodsError::InvalidJwtSignature(format!("JWT validation failed: {}", e)))?;

    let claims = token_data.claims;

    // Step 9: Verify nonce (CRITICAL for replay protection)
    let token_nonce = claims
        .nonce
        .as_ref()
        .ok_or(AuthMethodsError::MissingNonce)?;

    if token_nonce != expected_nonce {
        return Err(AuthMethodsError::NonceMismatch {
            expected: expected_nonce.to_string(),
            got: token_nonce.clone(),
        });
    }

    // Step 10: Additional timestamp validation
    let current_time = current_timestamp();

    if claims.exp < current_time {
        return Err(AuthMethodsError::TokenExpired {
            expired_at: claims.exp,
            current_time,
        });
    }

    if claims.iat > current_time + 60 {
        return Err(AuthMethodsError::TokenIssuedInFuture {
            issued_at: claims.iat,
            current_time,
        });
    }

    Ok(claims)
}
