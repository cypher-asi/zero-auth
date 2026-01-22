# zero-id API Error Reference

This document describes all error codes returned by the zero-id API, their HTTP status codes, and troubleshooting guidance.

## Error Response Format

All errors follow a consistent JSON structure:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description of the error",
    "details": { }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `code` | string | Machine-readable error code (use for programmatic handling) |
| `message` | string | Human-readable description |
| `details` | object | Additional context (optional, error-specific) |

## Error Codes

### INVALID_REQUEST

**HTTP Status:** `400 Bad Request`

The request contains invalid data, missing required fields, or malformed values.

**Common Causes:**

| Cause | Example Message |
|-------|-----------------|
| Invalid hex encoding | `"Invalid hex encoding"` |
| Wrong byte length | `"Expected 32 bytes"` |
| Invalid capability | `"Invalid capability: UNKNOWN"` |
| Missing required field | `"machine_id required"` |
| Invalid email format | `"Invalid email format"` |
| Weak password | `"Password must be at least 8 characters"` |
| Invalid timestamp | `"Invalid timestamp format"` |
| Invalid nonce length | `"Nonce must be 24 bytes"` |
| Invalid algorithm | `"Only xchacha20poly1305 encryption is supported"` |
| Invalid role | `"Invalid role: xyz. Must be one of: owner, admin, member"` |
| Invalid OAuth provider | `"Unknown OAuth provider: xyz"` |
| Invalid scope | `"Invalid scope: xyz"` |
| Multi-party approval missing | `"Multi-party approval required for security-related freeze"` |

**Troubleshooting:**

1. Verify all hex-encoded fields use lowercase hexadecimal characters
2. Check that public keys are 64 hex characters (32 bytes)
3. Check that signatures are 128 hex characters (64 bytes)
4. Ensure UUIDs are in standard format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
5. Validate required fields are present in the request body
6. Check that capability names match exactly (case-sensitive)

**Example:**

```bash
# Wrong: uppercase hex
curl -X POST /v1/identity -d '{"identity_signing_public_key": "A1B2C3..."}'

# Correct: lowercase hex
curl -X POST /v1/identity -d '{"identity_signing_public_key": "a1b2c3..."}'
```

---

### UNAUTHORIZED

**HTTP Status:** `401 Unauthorized`

Authentication failed or credentials are missing.

**Common Causes:**

| Cause | Scenario |
|-------|----------|
| Missing token | No `Authorization` header provided |
| Invalid token | JWT signature verification failed |
| Expired token | Access token has expired |
| Invalid credentials | Wrong email/password combination |
| Wallet not registered | Wallet address not linked to any identity |
| Invalid refresh token | Refresh token is invalid or expired |

**Troubleshooting:**

1. Ensure the `Authorization` header is present: `Authorization: Bearer <token>`
2. Check that the token hasn't expired (default: 15 minutes for access tokens)
3. Use the refresh token endpoint to obtain a new access token
4. Verify credentials are correct for email/password authentication
5. For wallet auth, ensure the wallet is registered with an identity

**Example:**

```bash
# Refresh an expired access token
curl -X POST /v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<your_refresh_token>",
    "session_id": "<your_session_id>",
    "machine_id": "<your_machine_id>"
  }'
```

---

### FORBIDDEN

**HTTP Status:** `403 Forbidden`

The authenticated user does not have permission to perform this action.

**Common Causes:**

| Cause | Example Message |
|-------|-----------------|
| Not a namespace member | `"Not a member of this namespace"` |
| Insufficient role | `"Insufficient permissions"` |
| Wrong identity | `"Session does not belong to authenticated identity"` |
| Cannot remove owner | `"Cannot remove namespace owner"` |

**Troubleshooting:**

1. Verify you're a member of the namespace you're trying to access
2. Check that your role has sufficient permissions (owner > admin > member)
3. Ensure you're operating on resources that belong to your identity
4. For namespace operations, verify ownership or admin status

**Permission Requirements:**

| Operation | Required Role |
|-----------|---------------|
| View namespace | Any member |
| Update namespace | Owner or Admin |
| Delete namespace | Owner only |
| Add members | Owner or Admin |
| Update member roles | Owner or Admin |
| Remove members | Owner or Admin |
| Deactivate/Reactivate | Owner only |

---

### NOT_FOUND

**HTTP Status:** `404 Not Found`

The requested resource does not exist.

**Common Causes:**

| Resource | Example Message |
|----------|-----------------|
| Identity | `"Identity not found"` |
| Machine | `"Machine not found"` |
| Namespace | `"Namespace not found"` |
| Session | `"Session not found"` |
| Membership | `"Membership not found"` |

**Troubleshooting:**

1. Verify the UUID is correct and properly formatted
2. Check that the resource was created successfully
3. Ensure the resource hasn't been deleted
4. For machines, verify the machine belongs to your identity

---

### CONFLICT

**HTTP Status:** `409 Conflict`

The request conflicts with the current state of a resource.

**Common Causes:**

| Cause | Example Message |
|-------|-----------------|
| Duplicate identity | `"Identity already exists"` |
| Duplicate machine | `"Machine already exists"` |
| Duplicate email | `"Email already registered"` |
| OAuth already linked | `"OAuth account already linked to another identity"` |
| Namespace not empty | `"Namespace has other members"` |
| MFA already enabled | `"MFA already enabled"` |
| Member already exists | `"Identity is already a member"` |

**Troubleshooting:**

1. For identity/machine creation, generate new UUIDs
2. For email registration, use a different email address or recover the existing account
3. For OAuth linking, unlink from the other identity first
4. For namespace deletion, remove all members first

---

### RATE_LIMITED

**HTTP Status:** `429 Too Many Requests`

Too many requests have been made in a given time window.

**Rate Limit Levels:**

| Level | Window | Limit | Description |
|-------|--------|-------|-------------|
| IP Address | 1 minute | 100 | Per source IP |
| Identity | 1 hour | 1000 | Per authenticated identity |
| Failed Auth | 15 minutes | 5 | Failed authentication attempts |

**Response Headers:**

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705838460
```

**Troubleshooting:**

1. Check the `X-RateLimit-Reset` header to know when the limit resets
2. Implement exponential backoff in your client
3. Cache responses where appropriate
4. For failed auth limits, wait 15 minutes or verify credentials

**Example Backoff:**

```python
import time

def make_request_with_backoff(max_retries=5):
    for attempt in range(max_retries):
        response = make_request()
        if response.status_code == 429:
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            wait_time = max(reset_time - time.time(), 2 ** attempt)
            time.sleep(wait_time)
        else:
            return response
    raise Exception("Rate limited after max retries")
```

---

### IDENTITY_FROZEN

**HTTP Status:** `403 Forbidden`

The identity has been frozen and cannot perform operations until unfrozen.

**Troubleshooting:**

1. Contact support if freeze was administrative
2. If you froze your own identity, initiate the unfreeze ceremony
3. Unfreeze requires multi-party approval from 2+ enrolled devices

**Unfreeze Process:**

```bash
# Requires signatures from 2+ machines
curl -X POST /v1/identity/unfreeze \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "approver_machine_ids": ["<machine1>", "<machine2>"],
    "approval_signatures": ["<sig1>", "<sig2>"]
  }'
```

---

### MACHINE_REVOKED

**HTTP Status:** `403 Forbidden`

The machine key used for authentication has been revoked.

**Troubleshooting:**

1. Use a different enrolled device to authenticate
2. Enroll a new machine key from an active device
3. If all devices are revoked, use account recovery

**Recovery Steps:**

1. Authenticate from another enrolled device
2. Enroll a new machine key for the compromised device
3. If no devices available, use Neural Shard recovery

---

### MFA_REQUIRED

**HTTP Status:** `403 Forbidden`

The operation requires MFA verification, but the current session has not verified MFA.

**High-Risk Operations Requiring MFA:**

- Rotate Neural Key
- Disable MFA
- Revoke all sessions
- Change password

**Troubleshooting:**

1. Re-authenticate with your MFA code included:

```bash
curl -X POST /v1/auth/login/email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your_password",
    "mfa_code": "123456"
  }'
```

2. Use the new session token (with `mfa_verified: true`) for the high-risk operation

---

### CHALLENGE_EXPIRED

**HTTP Status:** `400 Bad Request`

The authentication challenge has expired (challenges are valid for 60 seconds).

**Troubleshooting:**

1. Request a new challenge
2. Sign and submit the challenge within 60 seconds
3. Ensure system clocks are synchronized (NTP)

**Example Flow:**

```bash
# 1. Get fresh challenge
CHALLENGE=$(curl -s "/v1/auth/challenge?machine_id=<id>" | jq -r '.challenge')

# 2. Sign immediately (within 60 seconds)
SIGNATURE=$(sign_challenge "$CHALLENGE")

# 3. Submit
curl -X POST /v1/auth/login/machine \
  -d "{\"challenge_id\":\"...\",\"machine_id\":\"...\",\"signature\":\"$SIGNATURE\"}"
```

---

### INVALID_SIGNATURE

**HTTP Status:** `400 Bad Request`

A cryptographic signature verification failed.

**Common Causes:**

| Cause | Description |
|-------|-------------|
| Wrong key | Signed with a different key than expected |
| Corrupted signature | Signature bytes are invalid |
| Wrong message | Message doesn't match what was signed |
| Malleability | Signature was modified |

**Troubleshooting:**

1. **Authorization signatures**: Ensure you're signing with the Identity Signing Key
2. **Challenge responses**: Sign the exact challenge bytes (base64 decode first)
3. **Approval signatures**: Each approver must sign with their Machine Signing Key
4. **Rotation signatures**: Sign `"rotate" || identity_id || new_public_key`

**Signature Verification Checklist:**

- [ ] Using Ed25519 algorithm
- [ ] Signing with the correct private key
- [ ] Message matches expected format exactly
- [ ] Signature is 64 bytes (128 hex characters)
- [ ] No byte corruption during transmission

---

### INTERNAL_ERROR

**HTTP Status:** `500 Internal Server Error`

An unexpected server error occurred.

**Response:**

```json
{
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "An internal error occurred"
  }
}
```

**Note:** Details are intentionally omitted for security. Check server logs for debugging.

**Troubleshooting:**

1. Retry the request (may be transient)
2. Check the `/ready` endpoint for service health
3. Contact support if the error persists
4. Include the `X-Request-ID` header value when reporting issues

---

## HTTP Status Code Summary

| Status | Codes | Description |
|--------|-------|-------------|
| `200` | - | Success (GET, POST, PATCH) |
| `201` | - | Resource created |
| `204` | - | Success with no body (DELETE) |
| `400` | `INVALID_REQUEST`, `CHALLENGE_EXPIRED`, `INVALID_SIGNATURE` | Client error |
| `401` | `UNAUTHORIZED` | Authentication required |
| `403` | `FORBIDDEN`, `IDENTITY_FROZEN`, `MACHINE_REVOKED`, `MFA_REQUIRED` | Permission denied |
| `404` | `NOT_FOUND` | Resource not found |
| `409` | `CONFLICT` | Resource conflict |
| `429` | `RATE_LIMITED` | Too many requests |
| `500` | `INTERNAL_ERROR` | Server error |
| `503` | - | Service unavailable (readiness check) |

---

## Best Practices for Error Handling

### 1. Handle Errors by Code, Not Message

```javascript
// Good: Use error code
if (error.code === 'UNAUTHORIZED') {
  refreshToken();
}

// Bad: Parse message string
if (error.message.includes('expired')) {
  refreshToken();
}
```

### 2. Implement Token Refresh

```javascript
async function apiCall(endpoint, options) {
  let response = await fetch(endpoint, options);
  
  if (response.status === 401) {
    await refreshAccessToken();
    response = await fetch(endpoint, options);
  }
  
  return response;
}
```

### 3. Handle Rate Limits Gracefully

```javascript
async function apiCallWithBackoff(endpoint, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    const response = await fetch(endpoint, options);
    
    if (response.status === 429) {
      const resetTime = response.headers.get('X-RateLimit-Reset');
      const waitMs = (resetTime * 1000) - Date.now();
      await sleep(Math.max(waitMs, 1000 * Math.pow(2, i)));
      continue;
    }
    
    return response;
  }
  throw new Error('Rate limited after max retries');
}
```

### 4. Log Request IDs for Support

```javascript
async function apiCall(endpoint, options) {
  const response = await fetch(endpoint, options);
  const requestId = response.headers.get('X-Request-ID');
  
  if (!response.ok) {
    console.error(`Request ${requestId} failed:`, await response.json());
  }
  
  return response;
}
```

### 5. Validate Before Sending

```javascript
function validateHex(value, expectedBytes) {
  const hexRegex = /^[a-f0-9]+$/i;
  if (!hexRegex.test(value)) {
    throw new Error('Invalid hex encoding');
  }
  if (value.length !== expectedBytes * 2) {
    throw new Error(`Expected ${expectedBytes} bytes (${expectedBytes * 2} hex chars)`);
  }
}

// Usage
validateHex(publicKey, 32);  // 32 bytes = 64 hex chars
validateHex(signature, 64);  // 64 bytes = 128 hex chars
```
