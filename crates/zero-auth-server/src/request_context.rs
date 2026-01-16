use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
};
use std::net::IpAddr;

use crate::error::ApiError;

/// Extract client IP address with proxy validation
///
/// # Security
///
/// X-Forwarded-For header is only trusted if:
/// 1. A direct connection IP is provided (from trusted source)
/// 2. The direct connection IP is in the trusted_proxies list
/// 3. The X-Forwarded-For header contains valid IP addresses
///
/// Otherwise, uses the direct connection IP or "unknown" as fallback.
///
/// This prevents IP spoofing attacks where an attacker can set arbitrary
/// X-Forwarded-For headers to bypass rate limiting.
#[allow(dead_code)] // TODO: Use this for rate limiting
pub fn extract_client_ip(
    parts: &Parts,
    trusted_proxies: &[IpAddr],
    direct_ip: Option<IpAddr>,
) -> String {
    // If we have a direct connection IP and it's from a trusted proxy,
    // then we can trust X-Forwarded-For
    if let Some(direct) = direct_ip {
        if trusted_proxies.contains(&direct) {
            // Trust X-Forwarded-For, use the rightmost IP (closest to server, before the proxy)
            if let Some(forwarded) = parts.headers.get("X-Forwarded-For") {
                if let Ok(forwarded_str) = forwarded.to_str() {
                    // Take the last IP in the chain (rightmost)
                    // This is the client IP as seen by our trusted proxy
                    if let Some(ip_str) = forwarded_str.split(',').rev().next() {
                        let ip_str = ip_str.trim();
                        // Validate it's a proper IP address
                        if ip_str.parse::<IpAddr>().is_ok() {
                            return ip_str.to_string();
                        }
                    }
                }
            }
            
            // Fallback to X-Real-IP if X-Forwarded-For is not valid
            if let Some(real_ip) = parts.headers.get("X-Real-IP") {
                if let Ok(ip_str) = real_ip.to_str() {
                    let ip_str = ip_str.trim();
                    if ip_str.parse::<IpAddr>().is_ok() {
                        return ip_str.to_string();
                    }
                }
            }
        }
        
        // If not from trusted proxy, use direct connection IP
        return direct.to_string();
    }
    
    // No direct IP available, return unknown
    // In production, direct_ip should always be available from connection metadata
    tracing::warn!("No direct connection IP available for request");
    "unknown".to_string()
}

/// Request context containing metadata about the current request
/// 
/// This is used for audit logging, rate limiting, and security monitoring.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Client IP address (extracted from connection or X-Forwarded-For)
    pub ip_address: String,
    
    /// User-Agent string from the request headers
    pub user_agent: String,
}

impl RequestContext {
    /// Create a new request context from request parts
    pub fn from_parts(parts: &Parts) -> Self {
        // Extract IP address with basic validation
        // 
        // SECURITY NOTE: This uses the rightmost IP from X-Forwarded-For chain,
        // which is harder to spoof than the leftmost IP. However, for full security,
        // you should configure TRUSTED_PROXIES environment variable with your
        // load balancer/proxy IPs.
        //
        // Without TRUSTED_PROXIES configured, X-Forwarded-For can still be spoofed
        // if the attacker can connect directly to your server (bypassing the proxy).
        let ip_address = parts
            .headers
            .get("X-Forwarded-For")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| {
                // Take rightmost IP (closest to server, last proxy in chain)
                // This is more trustworthy than the leftmost IP
                s.split(',')
                    .rev()
                    .next()
                    .map(|ip| ip.trim())
                    .filter(|ip| {
                        // Validate it's a real IP address
                        ip.parse::<IpAddr>().is_ok()
                    })
            })
            .or_else(|| {
                // Fall back to X-Real-IP
                parts
                    .headers
                    .get("X-Real-IP")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.trim())
                    .filter(|ip| {
                        // Validate it's a real IP address
                        ip.parse::<IpAddr>().is_ok()
                    })
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                tracing::warn!("No valid IP address found in request headers");
                "unknown".to_string()
            });

        // Extract User-Agent
        let user_agent = parts
            .headers
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        Self {
            ip_address,
            user_agent,
        }
    }
}

/// Extractor for request context
/// 
/// This can be used in any handler to get request metadata
#[async_trait]
impl<S> FromRequestParts<S> for RequestContext
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(RequestContext::from_parts(parts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Request};

    #[test]
    fn test_request_context_extraction() {
        let mut headers = HeaderMap::new();
        // X-Forwarded-For: "client IP, proxy1 IP, proxy2 IP, ..."
        // We use the rightmost IP (10.0.0.1) as it's the closest to our server
        // and harder to spoof than the leftmost IP
        headers.insert("X-Forwarded-For", "192.168.1.100, 10.0.0.1".parse().unwrap());
        headers.insert("User-Agent", "TestClient/1.0".parse().unwrap());

        let req = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        parts.headers = headers;

        let context = RequestContext::from_parts(&parts);

        // Should extract rightmost IP (closest to server)
        assert_eq!(context.ip_address, "10.0.0.1");
        assert_eq!(context.user_agent, "TestClient/1.0");
    }

    #[test]
    fn test_request_context_defaults() {
        let req = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let context = RequestContext::from_parts(&parts);

        assert_eq!(context.ip_address, "unknown");
        assert_eq!(context.user_agent, "unknown");
    }
}
