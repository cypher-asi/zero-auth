# zero-auth API Documentation

This documentation covers the zero-auth REST API for identity management, authentication, and session handling.

## Base URL

| Environment | URL |
|-------------|-----|
| Production (Cypher-hosted) | `https://auth.zero.tech` |
| Local Development | `http://127.0.0.1:9999` |

All API endpoints are versioned. The current version is **v1**, accessible at `/v1/*`.

## Authentication

The API uses multiple authentication mechanisms depending on the endpoint type.

### JWT Bearer Tokens

Most endpoints require a valid JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Access tokens are obtained through the authentication endpoints (`/v1/auth/login/*`) and are short-lived (15 minutes by default). Use the refresh token to obtain new access tokens without re-authenticating.

**Token Claims:**

| Claim | Description |
|-------|-------------|
| `sub` | Identity ID (UUID) |
| `machine_id` | Machine key ID used for authentication |
| `namespace_id` | Active namespace context |
| `session_id` | Current session ID |
| `mfa_verified` | Whether MFA was verified for this session |
| `capabilities` | Machine key capabilities array |
| `scope` | Authorized scopes |
| `exp` | Token expiration timestamp |

### mTLS (Mutual TLS)

Integration endpoints (`/v1/integrations/*`, `/v1/events/*`) require mutual TLS authentication. The client certificate fingerprint is validated against registered services.

**Required Headers (set by reverse proxy):**

| Header | Description |
|--------|-------------|
| `X-Client-Cert-Fingerprint` | SHA-256 fingerprint of client certificate (hex, 64 chars) |
| `X-Client-Cert` | Full client certificate in PEM format (alternative) |

### Public Endpoints

The following endpoints do not require authentication:

- `GET /health` - Liveness probe
- `GET /ready` - Readiness probe
- `POST /v1/identity` - Create new identity
- `GET /v1/auth/challenge` - Get authentication challenge
- `GET /v1/auth/oauth/:provider` - Initiate OAuth flow
- `GET /.well-known/jwks.json` - JWT public keys

## Request Format

### Content Type

All requests with a body must use:

```
Content-Type: application/json
```

### Data Encoding

| Type | Format | Example |
|------|--------|---------|
| UUID | Standard UUID format | `550e8400-e29b-41d4-a716-446655440000` |
| Timestamps | RFC 3339 | `2025-01-21T12:00:00Z` |
| Public Keys | Hex-encoded (64 chars for 32 bytes) | `a1b2c3...` |
| Signatures | Hex-encoded (128 chars for 64 bytes) | `d4e5f6...` |
| Binary Data | Hex or Base64 (endpoint-specific) | See endpoint docs |

## Response Format

### Success Responses

Successful responses return JSON with appropriate HTTP status codes:

| Status | Usage |
|--------|-------|
| `200 OK` | Successful GET, POST, PATCH |
| `201 Created` | Resource created |
| `204 No Content` | Successful DELETE or action with no response body |

### Error Responses

All errors follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description",
    "details": { }
  }
}
```

See [errors.md](errors.md) for the complete error reference.

## Rate Limiting

The API enforces rate limits at multiple levels to prevent abuse.

### Rate Limit Headers

All responses include rate limit information:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in the window |
| `X-RateLimit-Remaining` | Remaining requests in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |

### Default Limits

| Level | Window | Limit | Notes |
|-------|--------|-------|-------|
| IP Address | 1 minute | 100 requests | Prevents brute force from single source |
| Identity | 1 hour | 1000 requests | Prevents account abuse |
| Failed Auth | 15 minutes | 5 failures | Temporary lockout after repeated failures |

When rate limited, the API returns `429 Too Many Requests`.

## Quick Start

### 1. Create an Identity

```bash
# Generate keys client-side (using zero-auth-client or your own implementation)
# Then register with the server:

curl -X POST http://127.0.0.1:9999/v1/identity \
  -H "Content-Type: application/json" \
  -d '{
    "identity_id": "550e8400-e29b-41d4-a716-446655440000",
    "identity_signing_public_key": "<64-char-hex>",
    "authorization_signature": "<128-char-hex>",
    "machine_key": {
      "machine_id": "660e8400-e29b-41d4-a716-446655440001",
      "signing_public_key": "<64-char-hex>",
      "encryption_public_key": "<64-char-hex>",
      "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
      "device_name": "My Laptop",
      "device_platform": "macos"
    },
    "namespace_name": "Personal",
    "created_at": 1705838400
  }'
```

### 2. Authenticate with Machine Key

```bash
# Step 1: Get a challenge
curl "http://127.0.0.1:9999/v1/auth/challenge?machine_id=660e8400-e29b-41d4-a716-446655440001"

# Response:
# {
#   "challenge_id": "...",
#   "challenge": "<base64-encoded-challenge>",
#   "expires_at": "2025-01-21T12:01:00Z"
# }

# Step 2: Sign the challenge and submit
curl -X POST http://127.0.0.1:9999/v1/auth/login/machine \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "<challenge_id>",
    "machine_id": "660e8400-e29b-41d4-a716-446655440001",
    "signature": "<128-char-hex-signature>"
  }'

# Response:
# {
#   "access_token": "eyJ...",
#   "refresh_token": "...",
#   "session_id": "...",
#   "machine_id": "...",
#   "expires_at": "2025-01-21T12:15:00Z"
# }
```

### 3. Make Authenticated Requests

```bash
# Use the access token for authenticated endpoints
curl http://127.0.0.1:9999/v1/identity/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer eyJ..."
```

### 4. Refresh Tokens

```bash
# Before access token expires, refresh it
curl -X POST http://127.0.0.1:9999/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>",
    "session_id": "<session_id>",
    "machine_id": "<machine_id>"
  }'
```

## SDK and Client Libraries

### Official CLI Client

The `zero-auth-client` crate provides a command-line interface:

```bash
cargo run -p zero-auth-client -- create-identity --device-name "My Device"
cargo run -p zero-auth-client -- login
```

### Rust Integration

For Rust applications, use the `zero-auth-crypto` crate for client-side cryptographic operations:

```toml
[dependencies]
zero-auth-crypto = { git = "https://github.com/cypher-agi/zero-auth" }
```

### Local JWT Validation

For better performance, validate JWTs locally using the JWKS endpoint:

```bash
curl http://127.0.0.1:9999/.well-known/jwks.json
```

The response contains Ed25519 public keys in JWK format for signature verification.

## API Reference

- [v1-reference.md](v1-reference.md) - Complete endpoint documentation
- [errors.md](errors.md) - Error codes and troubleshooting

## Related Documentation

- [Main README](../../README.md) - System overview and architecture
- [zero-auth-client README](../../crates/zero-auth-client/README.md) - CLI client documentation
