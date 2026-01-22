# zero-id API v1 Reference

Complete endpoint reference for the zero-id REST API.

## Table of Contents

- [Health](#health)
- [Identity Management](#identity-management)
- [Machine Keys](#machine-keys)
- [Namespaces](#namespaces)
- [Authentication](#authentication)
- [Sessions](#sessions)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Credentials](#credentials)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Integrations](#integrations)

---

## Health

Health check endpoints for monitoring and orchestration.

### GET /health

Liveness probe. Returns 200 if the server process is running.

**Authentication:** None

**Response:**

```json
{
  "status": "ok",
  "version": "0.1.0",
  "timestamp": 1705838400
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"ok"` if responding |
| `version` | string | Server version from Cargo.toml |
| `timestamp` | integer | Current Unix timestamp (seconds) |

---

### GET /ready

Readiness probe. Returns 200 if the server is ready to accept traffic, including database connectivity.

**Authentication:** None

**Response (200 OK):**

```json
{
  "status": "ready",
  "database": "connected",
  "timestamp": 1705838400
}
```

**Response (503 Service Unavailable):**

```json
{
  "status": "not_ready",
  "database": "disconnected",
  "timestamp": 1705838400
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"ready"` or `"not_ready"` |
| `database` | string | `"connected"` or `"disconnected"` |
| `timestamp` | integer | Current Unix timestamp (seconds) |

---

## Identity Management

Endpoints for creating and managing cryptographic identities.

### POST /v1/identity

Create a new identity with an initial machine key.

**Authentication:** None (public endpoint)

**Request Body:**

```json
{
  "identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "identity_signing_public_key": "a1b2c3d4...",
  "authorization_signature": "e5f6g7h8...",
  "machine_key": {
    "machine_id": "660e8400-e29b-41d4-a716-446655440001",
    "signing_public_key": "i9j0k1l2...",
    "encryption_public_key": "m3n4o5p6...",
    "key_scheme": "classical",
    "pq_signing_public_key": null,
    "pq_encryption_public_key": null,
    "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
    "device_name": "My Laptop",
    "device_platform": "macos"
  },
  "namespace_name": "Personal",
  "created_at": 1705838400
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity_id` | UUID | Yes | Client-generated identity ID |
| `identity_signing_public_key` | string | Yes | Ed25519 public key (hex, 64 chars) |
| `authorization_signature` | string | Yes | Signature proving key ownership (hex, 128 chars) |
| `machine_key` | object | Yes | Initial machine key for this identity |
| `machine_key.machine_id` | UUID | Yes | Client-generated machine ID |
| `machine_key.signing_public_key` | string | Yes | Ed25519 public key (hex, 64 chars) |
| `machine_key.encryption_public_key` | string | Yes | X25519 public key (hex, 64 chars) |
| `machine_key.key_scheme` | string | No | Key scheme: `classical` (default) or `pq_hybrid` |
| `machine_key.pq_signing_public_key` | string | No | ML-DSA-65 public key (hex, 3904 chars). Required if `key_scheme` is `pq_hybrid` |
| `machine_key.pq_encryption_public_key` | string | No | ML-KEM-768 public key (hex, 2368 chars). Required if `key_scheme` is `pq_hybrid` |
| `machine_key.capabilities` | array | Yes | Capability strings (see below) |
| `machine_key.device_name` | string | Yes | Human-readable device name |
| `machine_key.device_platform` | string | Yes | Platform identifier (e.g., "macos", "windows", "linux", "ios", "android") |
| `namespace_name` | string | Yes | Name for the personal namespace |
| `created_at` | integer | Yes | Unix timestamp (must match signature) |

**Machine Key Capabilities:**

| Capability | Description |
|------------|-------------|
| `FULL_DEVICE` | All capabilities (convenience alias) |
| `AUTHENTICATE` | Can authenticate to zero-id |
| `SIGN` | Can sign challenges and messages |
| `ENCRYPT` | Can encrypt/decrypt data |
| `SVK_UNWRAP` | Can unwrap vault keys (zero-vault integration) |
| `MLS_MESSAGING` | Can participate in MLS messaging groups |
| `VAULT_OPERATIONS` | Can access vault operations |
| `SERVICE_MACHINE` | Service-level machine (automated systems) |

**Key Scheme (Optional Post-Quantum Support):**

The `key_scheme` field controls whether post-quantum keys are included alongside classical keys. This is optional and defaults to `classical`.

| Scheme | Description |
|--------|-------------|
| `classical` | Ed25519 + X25519 only (default, OpenMLS compatible) |
| `pq_hybrid` | Classical keys + ML-DSA-65 + ML-KEM-768 (post-quantum protection) |

When using `pq_hybrid`, the machine key includes additional post-quantum public keys:

| Field | Size | Description |
|-------|------|-------------|
| `pq_signing_public_key` | 3,904 hex chars (1,952 bytes) | ML-DSA-65 public key (FIPS 204) |
| `pq_encryption_public_key` | 2,368 hex chars (1,184 bytes) | ML-KEM-768 public key (FIPS 203) |

**Note:** PQ-Hybrid support is always available. Both classical and post-quantum key schemes can be used without any feature flags.

**Response (200 OK):**

```json
{
  "identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "machine_id": "660e8400-e29b-41d4-a716-446655440001",
  "namespace_id": "550e8400-e29b-41d4-a716-446655440000",
  "key_scheme": "classical",
  "created_at": "2025-01-21T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `identity_id` | UUID | Created identity ID |
| `machine_id` | UUID | Enrolled machine ID |
| `namespace_id` | UUID | Personal namespace ID (same as identity_id) |
| `key_scheme` | string | Key scheme used: `classical` or `pq_hybrid` |
| `created_at` | string | RFC 3339 timestamp |

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Invalid hex encoding, missing fields, invalid capabilities, or PQ key size mismatch |
| `INVALID_SIGNATURE` | Authorization signature verification failed |
| `CONFLICT` | Identity or machine ID already exists |

---

### GET /v1/identity/:identity_id

Get identity details.

**Authentication:** Bearer token required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `identity_id` | UUID | Identity to retrieve |

**Response (200 OK):**

```json
{
  "identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "identity_signing_public_key": "a1b2c3d4...",
  "status": "active",
  "created_at": "2025-01-21T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `identity_id` | UUID | Identity ID |
| `identity_signing_public_key` | string | Current public key (hex, 64 chars) |
| `status` | string | One of: `active`, `frozen`, `disabled`, `deleted` |
| `created_at` | string | RFC 3339 timestamp |

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `NOT_FOUND` | Identity does not exist |

---

### POST /v1/identity/freeze

Freeze an identity. Frozen identities cannot authenticate until unfrozen.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "approver_machine_ids": [
    "660e8400-e29b-41d4-a716-446655440001",
    "770e8400-e29b-41d4-a716-446655440002"
  ],
  "approval_signatures": [
    "a1b2c3d4...",
    "e5f6g7h8..."
  ],
  "reason": "security_incident"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `approver_machine_ids` | array | Conditional | Machine IDs providing approval (required for security-related freezes) |
| `approval_signatures` | array | Conditional | Signatures from approvers (hex, 128 chars each) |
| `reason` | string | Yes | Freeze reason |

**Freeze Reasons:**

| Reason | Multi-party Required | Description |
|--------|---------------------|-------------|
| `security_incident` | Yes | Suspected security breach |
| `suspicious_activity` | Yes | Unusual account activity detected |
| `user_requested` | No | User-initiated freeze |
| `administrative` | No | Administrative action |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Identity frozen successfully"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Multi-party approval required but not provided |
| `INVALID_SIGNATURE` | Approval signature verification failed |

---

### POST /v1/identity/unfreeze

Unfreeze a previously frozen identity. Requires multi-party approval.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "approver_machine_ids": [
    "660e8400-e29b-41d4-a716-446655440001",
    "770e8400-e29b-41d4-a716-446655440002"
  ],
  "approval_signatures": [
    "a1b2c3d4...",
    "e5f6g7h8..."
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `approver_machine_ids` | array | Yes | Machine IDs providing approval (minimum 2) |
| `approval_signatures` | array | Yes | Signatures from approvers (hex, 128 chars each) |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Identity unfrozen successfully"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Insufficient approvals |
| `INVALID_SIGNATURE` | Approval signature verification failed |

---

### POST /v1/identity/recovery

Perform identity recovery ceremony. Used when the Neural Key is lost and must be reconstructed from shards.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "new_identity_signing_public_key": "a1b2c3d4...",
  "approver_machine_ids": [
    "660e8400-e29b-41d4-a716-446655440001",
    "770e8400-e29b-41d4-a716-446655440002"
  ],
  "approval_signatures": [
    "e5f6g7h8...",
    "i9j0k1l2..."
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `new_identity_signing_public_key` | string | Yes | New Ed25519 public key (hex, 64 chars) |
| `approver_machine_ids` | array | Yes | Machine IDs providing approval |
| `approval_signatures` | array | Yes | Signatures from approvers (hex, 128 chars each) |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Identity recovered successfully"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Missing required fields |
| `INVALID_SIGNATURE` | Approval signature verification failed |

---

### POST /v1/identity/rotation

Rotate the identity signing key. This is a high-risk operation requiring MFA verification and multi-party approval.

**Authentication:** Bearer token required (MFA must be verified)

**Request Body:**

```json
{
  "new_identity_signing_public_key": "a1b2c3d4...",
  "rotation_signature": "e5f6g7h8...",
  "approver_machine_ids": [
    "660e8400-e29b-41d4-a716-446655440001",
    "770e8400-e29b-41d4-a716-446655440002"
  ],
  "approval_signatures": [
    "i9j0k1l2...",
    "m3n4o5p6..."
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `new_identity_signing_public_key` | string | Yes | New Ed25519 public key (hex, 64 chars) |
| `rotation_signature` | string | Yes | Signature from current identity key proving authorization (hex, 128 chars) |
| `approver_machine_ids` | array | Yes | Machine IDs providing approval (minimum 2) |
| `approval_signatures` | array | Yes | Signatures from approvers (hex, 128 chars each) |

**Rotation Signature Format:**

The `rotation_signature` must sign the message: `"rotate" || identity_id || new_identity_signing_public_key`

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Identity signing key rotated successfully"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `MFA_REQUIRED` | MFA verification required for this operation |
| `INVALID_REQUEST` | Missing required fields or insufficient approvals |
| `INVALID_SIGNATURE` | Rotation or approval signature verification failed |

---

## Machine Keys

Endpoints for managing enrolled devices.

### POST /v1/machines/enroll

Enroll a new machine key for an existing identity.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "machine_id": "770e8400-e29b-41d4-a716-446655440002",
  "namespace_id": "550e8400-e29b-41d4-a716-446655440000",
  "signing_public_key": "a1b2c3d4...",
  "encryption_public_key": "e5f6g7h8...",
  "key_scheme": "classical",
  "pq_signing_public_key": null,
  "pq_encryption_public_key": null,
  "capabilities": ["AUTHENTICATE", "SIGN"],
  "device_name": "My Phone",
  "device_platform": "ios",
  "authorization_signature": "i9j0k1l2..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `machine_id` | UUID | Yes | Client-generated machine ID |
| `namespace_id` | UUID | No | Target namespace (defaults to personal namespace) |
| `signing_public_key` | string | Yes | Ed25519 public key (hex, 64 chars) |
| `encryption_public_key` | string | Yes | X25519 public key (hex, 64 chars) |
| `key_scheme` | string | No | Key scheme: `classical` (default) or `pq_hybrid` |
| `pq_signing_public_key` | string | No | ML-DSA-65 public key (hex, 3904 chars). Required if `key_scheme` is `pq_hybrid` |
| `pq_encryption_public_key` | string | No | ML-KEM-768 public key (hex, 2368 chars). Required if `key_scheme` is `pq_hybrid` |
| `capabilities` | array | Yes | Capability strings |
| `device_name` | string | Yes | Human-readable device name |
| `device_platform` | string | Yes | Platform identifier |
| `authorization_signature` | string | Yes | Signature from identity key (hex, 128 chars) |

**Response (200 OK):**

```json
{
  "machine_id": "770e8400-e29b-41d4-a716-446655440002",
  "namespace_id": "550e8400-e29b-41d4-a716-446655440000",
  "key_scheme": "classical",
  "enrolled_at": "2025-01-21T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `machine_id` | UUID | Enrolled machine ID |
| `namespace_id` | UUID | Namespace the machine is enrolled in |
| `key_scheme` | string | Key scheme used: `classical` or `pq_hybrid` |
| `enrolled_at` | string | RFC 3339 timestamp |

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Invalid hex encoding, capabilities, or PQ key size mismatch |
| `INVALID_SIGNATURE` | Authorization signature verification failed |
| `CONFLICT` | Machine ID already exists |

---

### GET /v1/machines

List enrolled machines for the authenticated identity.

**Authentication:** Bearer token required

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace_id` | UUID | No | Filter by namespace (defaults to personal namespace) |

**Response (200 OK):**

```json
{
  "machines": [
    {
      "machine_id": "660e8400-e29b-41d4-a716-446655440001",
      "device_name": "My Laptop",
      "device_platform": "macos",
      "key_scheme": "classical",
      "has_pq_keys": false,
      "created_at": "2025-01-21T12:00:00Z",
      "last_used_at": "2025-01-21T14:30:00Z",
      "revoked": false
    },
    {
      "machine_id": "770e8400-e29b-41d4-a716-446655440002",
      "device_name": "My Phone",
      "device_platform": "ios",
      "key_scheme": "pq_hybrid",
      "has_pq_keys": true,
      "created_at": "2025-01-22T10:00:00Z",
      "last_used_at": null,
      "revoked": false
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `machines` | array | List of machine info objects |
| `machines[].machine_id` | UUID | Machine ID |
| `machines[].device_name` | string | Human-readable name |
| `machines[].device_platform` | string | Platform identifier |
| `machines[].key_scheme` | string | Key scheme: `classical` or `pq_hybrid` |
| `machines[].has_pq_keys` | boolean | Whether machine has post-quantum keys |
| `machines[].created_at` | string | RFC 3339 timestamp |
| `machines[].last_used_at` | string | RFC 3339 timestamp or `null` |
| `machines[].revoked` | boolean | Whether the machine is revoked |

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |

---

### DELETE /v1/machines/:machine_id

Revoke a machine key.

**Authentication:** Bearer token required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `machine_id` | UUID | Machine to revoke |

**Request Body:**

```json
{
  "reason": "Device lost"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | Yes | Reason for revocation |

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `NOT_FOUND` | Machine does not exist |
| `FORBIDDEN` | Cannot revoke machine belonging to another identity |

---

## Namespaces

Endpoints for namespace management and membership.

### POST /v1/namespaces

Create a new namespace.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
  "name": "My Organization"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `namespace_id` | UUID | No | Client-generated ID (auto-generated if omitted) |
| `name` | string | Yes | Namespace name |

**Response (201 Created):**

```json
{
  "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
  "name": "My Organization",
  "owner_identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "active": true,
  "created_at": "2025-01-21T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `namespace_id` | UUID | Created namespace ID |
| `name` | string | Namespace name |
| `owner_identity_id` | UUID | Identity that owns this namespace |
| `active` | boolean | Whether the namespace is active |
| `created_at` | string | RFC 3339 timestamp |

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `CONFLICT` | Namespace ID already exists |

---

### GET /v1/namespaces

List namespaces the authenticated identity belongs to.

**Authentication:** Bearer token required

**Response (200 OK):**

```json
{
  "namespaces": [
    {
      "namespace_id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Personal",
      "owner_identity_id": "550e8400-e29b-41d4-a716-446655440000",
      "active": true,
      "created_at": "2025-01-21T12:00:00Z"
    },
    {
      "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
      "name": "My Organization",
      "owner_identity_id": "550e8400-e29b-41d4-a716-446655440000",
      "active": true,
      "created_at": "2025-01-22T10:00:00Z"
    }
  ]
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |

---

### GET /v1/namespaces/:namespace_id

Get namespace details.

**Authentication:** Bearer token required (must be a member)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Namespace to retrieve |

**Response (200 OK):**

```json
{
  "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
  "name": "My Organization",
  "owner_identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "active": true,
  "created_at": "2025-01-21T12:00:00Z"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Not a member of this namespace |
| `NOT_FOUND` | Namespace does not exist |

---

### PATCH /v1/namespaces/:namespace_id

Update namespace details.

**Authentication:** Bearer token required (owner or admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Namespace to update |

**Request Body:**

```json
{
  "name": "Updated Name"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | New namespace name |

**Response (200 OK):**

```json
{
  "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
  "name": "Updated Name",
  "owner_identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "active": true,
  "created_at": "2025-01-21T12:00:00Z"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Insufficient permissions |
| `NOT_FOUND` | Namespace does not exist |

---

### POST /v1/namespaces/:namespace_id/deactivate

Deactivate a namespace.

**Authentication:** Bearer token required (owner only)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Namespace to deactivate |

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Not the namespace owner |
| `NOT_FOUND` | Namespace does not exist |

---

### POST /v1/namespaces/:namespace_id/reactivate

Reactivate a previously deactivated namespace.

**Authentication:** Bearer token required (owner only)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Namespace to reactivate |

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Not the namespace owner |
| `NOT_FOUND` | Namespace does not exist |

---

### DELETE /v1/namespaces/:namespace_id

Delete a namespace. The namespace must be empty (no members except owner).

**Authentication:** Bearer token required (owner only)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Namespace to delete |

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Not the namespace owner |
| `NOT_FOUND` | Namespace does not exist |
| `CONFLICT` | Namespace has other members |

---

### GET /v1/namespaces/:namespace_id/members

List members of a namespace.

**Authentication:** Bearer token required (must be a member)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Namespace to list members for |

**Response (200 OK):**

```json
{
  "members": [
    {
      "identity_id": "550e8400-e29b-41d4-a716-446655440000",
      "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
      "role": "owner",
      "joined_at": "2025-01-21T12:00:00Z"
    },
    {
      "identity_id": "990e8400-e29b-41d4-a716-446655440004",
      "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
      "role": "member",
      "joined_at": "2025-01-22T15:00:00Z"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `members` | array | List of membership records |
| `members[].identity_id` | UUID | Member's identity ID |
| `members[].namespace_id` | UUID | Namespace ID |
| `members[].role` | string | One of: `owner`, `admin`, `member` |
| `members[].joined_at` | string | RFC 3339 timestamp |

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Not a member of this namespace |
| `NOT_FOUND` | Namespace does not exist |

---

### POST /v1/namespaces/:namespace_id/members

Add a member to a namespace.

**Authentication:** Bearer token required (owner or admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Target namespace |

**Request Body:**

```json
{
  "identity_id": "990e8400-e29b-41d4-a716-446655440004",
  "role": "member"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity_id` | UUID | Yes | Identity to add |
| `role` | string | Yes | Role to assign: `owner`, `admin`, or `member` |

**Response (201 Created):**

```json
{
  "identity_id": "990e8400-e29b-41d4-a716-446655440004",
  "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
  "role": "member",
  "joined_at": "2025-01-22T15:00:00Z"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Insufficient permissions |
| `INVALID_REQUEST` | Invalid role |
| `NOT_FOUND` | Namespace or identity does not exist |
| `CONFLICT` | Identity is already a member |

---

### PATCH /v1/namespaces/:namespace_id/members/:identity_id

Update a member's role.

**Authentication:** Bearer token required (owner or admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Target namespace |
| `identity_id` | UUID | Member to update |

**Request Body:**

```json
{
  "role": "admin"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `role` | string | Yes | New role: `owner`, `admin`, or `member` |

**Response (200 OK):**

```json
{
  "identity_id": "990e8400-e29b-41d4-a716-446655440004",
  "namespace_id": "880e8400-e29b-41d4-a716-446655440003",
  "role": "admin",
  "joined_at": "2025-01-22T15:00:00Z"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Insufficient permissions |
| `INVALID_REQUEST` | Invalid role |
| `NOT_FOUND` | Membership does not exist |

---

### DELETE /v1/namespaces/:namespace_id/members/:identity_id

Remove a member from a namespace.

**Authentication:** Bearer token required (owner or admin)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `namespace_id` | UUID | Target namespace |
| `identity_id` | UUID | Member to remove |

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Insufficient permissions or trying to remove owner |
| `NOT_FOUND` | Membership does not exist |

---

## Authentication

Endpoints for authenticating and obtaining tokens.

### GET /v1/auth/challenge

Get an authentication challenge for machine key authentication.

**Authentication:** None

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `machine_id` | UUID | Yes | Machine requesting authentication |

**Response (200 OK):**

```json
{
  "challenge_id": "aa0e8400-e29b-41d4-a716-446655440005",
  "challenge": "eyJjaGFsbGVuZ2VfaWQiOi...",
  "expires_at": "2025-01-21T12:01:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `challenge_id` | UUID | Challenge identifier |
| `challenge` | string | Base64-encoded challenge data to sign |
| `expires_at` | string | RFC 3339 expiration (60 seconds from creation) |

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Missing machine_id parameter |
| `NOT_FOUND` | Machine not found |

---

### POST /v1/auth/login/machine

Authenticate using a machine key by responding to a challenge.

**Authentication:** None

**Request Body:**

```json
{
  "challenge_id": "aa0e8400-e29b-41d4-a716-446655440005",
  "machine_id": "660e8400-e29b-41d4-a716-446655440001",
  "signature": "a1b2c3d4..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `challenge_id` | UUID | Yes | Challenge ID from `/v1/auth/challenge` |
| `machine_id` | UUID | Yes | Machine performing authentication |
| `signature` | string | Yes | Ed25519 signature of challenge (hex, 128 chars) |

**Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_a1b2c3d4e5f6...",
  "session_id": "bb0e8400-e29b-41d4-a716-446655440006",
  "machine_id": "660e8400-e29b-41d4-a716-446655440001",
  "expires_at": "2025-01-21T12:15:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | string | JWT access token (15 min expiry) |
| `refresh_token` | string | Opaque refresh token (30 day expiry) |
| `session_id` | UUID | Session identifier |
| `machine_id` | UUID | Authenticated machine ID |
| `expires_at` | string | Access token expiration (RFC 3339) |
| `warning` | string | Optional warning message |

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Invalid hex encoding |
| `INVALID_SIGNATURE` | Signature verification failed |
| `CHALLENGE_EXPIRED` | Challenge has expired |
| `MACHINE_REVOKED` | Machine key has been revoked |
| `IDENTITY_FROZEN` | Identity is frozen |
| `RATE_LIMITED` | Too many failed attempts |

---

### POST /v1/auth/login/email

Authenticate using email and password.

**Authentication:** None

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "secure_password",
  "machine_id": "660e8400-e29b-41d4-a716-446655440001",
  "mfa_code": "123456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address |
| `password` | string | Yes | Password |
| `machine_id` | UUID | No | Specific machine to use (required if identity has multiple machines) |
| `mfa_code` | string | No | TOTP code if MFA is enabled |

**Response (200 OK):**

Same as [POST /v1/auth/login/machine](#post-v1authloginmachine).

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Invalid email format, machine_id required but not provided |
| `UNAUTHORIZED` | Invalid email or password |
| `MFA_REQUIRED` | MFA code required but not provided |
| `IDENTITY_FROZEN` | Identity is frozen |
| `RATE_LIMITED` | Too many failed attempts |

---

### POST /v1/auth/login/wallet

Authenticate using an EVM wallet signature (EIP-191).

**Authentication:** None

**Request Body:**

```json
{
  "wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
  "signature": "a1b2c3d4...",
  "message": "Sign in to zero-id\nTimestamp: 1705838400\nWallet: 0x1234..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wallet_address` | string | Yes | Ethereum address (0x-prefixed, 42 chars) |
| `signature` | string | Yes | EIP-191 signature (hex, 130 chars for 65 bytes) |
| `message` | string | Yes | Signed message (must match expected format) |

**Message Format:**

```
Sign in to zero-id
Timestamp: <unix_timestamp>
Wallet: <wallet_address>
```

The timestamp must be within 5 minutes of the current time.

**Response (200 OK):**

Same as [POST /v1/auth/login/machine](#post-v1authloginmachine).

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Invalid signature format, message format, or expired timestamp |
| `UNAUTHORIZED` | Signature verification failed or wallet not registered |
| `IDENTITY_FROZEN` | Identity is frozen |

---

### GET /v1/auth/oauth/:provider

Initiate an OAuth authentication flow.

**Authentication:** None

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | OAuth provider: `google`, `x` (or `twitter`), `epic` |

**Response (200 OK):**

```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "random_state_string"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `authorization_url` | string | URL to redirect user to for OAuth consent |
| `state` | string | State parameter for CSRF protection |

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Unknown OAuth provider |

---

### POST /v1/auth/oauth/:provider/callback

Complete an OAuth authentication flow.

**Authentication:** None

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | OAuth provider: `google`, `x`, `epic` |

**Request Body:**

```json
{
  "code": "oauth_authorization_code",
  "state": "random_state_string"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | Authorization code from OAuth provider |
| `state` | string | Yes | State parameter (must match initiation) |

**Response (200 OK):**

Same as [POST /v1/auth/login/machine](#post-v1authloginmachine).

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Invalid state or code |
| `UNAUTHORIZED` | OAuth account not linked to any identity |

---

## Sessions

Endpoints for session management and token operations.

### POST /v1/auth/refresh

Refresh an access token using a refresh token.

**Authentication:** None (uses refresh token)

**Request Body:**

```json
{
  "refresh_token": "rt_a1b2c3d4e5f6...",
  "session_id": "bb0e8400-e29b-41d4-a716-446655440006",
  "machine_id": "660e8400-e29b-41d4-a716-446655440001"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | Yes | Current refresh token |
| `session_id` | UUID | Yes | Session ID |
| `machine_id` | UUID | Yes | Machine ID |

**Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_g7h8i9j0k1l2...",
  "expires_at": "2025-01-21T12:30:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | string | New JWT access token |
| `refresh_token` | string | New refresh token (old one is invalidated) |
| `expires_at` | string | Access token expiration (RFC 3339) |

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Invalid or expired refresh token |
| `FORBIDDEN` | Refresh token reuse detected (all tokens revoked) |

---

### POST /v1/session/revoke

Revoke a specific session.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "session_id": "bb0e8400-e29b-41d4-a716-446655440006"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | UUID | Yes | Session to revoke |

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `FORBIDDEN` | Session belongs to a different identity |
| `NOT_FOUND` | Session does not exist |

---

### POST /v1/session/revoke-all

Revoke all sessions for the authenticated identity. This is a high-risk operation requiring MFA verification.

**Authentication:** Bearer token required (MFA must be verified)

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `MFA_REQUIRED` | MFA verification required |

---

### POST /v1/auth/introspect

Introspect a token to validate it and retrieve claims.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "token": "eyJhbGciOiJFZERTQSIs...",
  "operation_type": "vault:read"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | Yes | Token to introspect |
| `operation_type` | string | No | Operation for capability check |

**Operation Types for Capability Checks:**

| Operation | Required Capability |
|-----------|---------------------|
| `vault:read` | `VAULT_OPERATIONS` |
| `vault:write` | `VAULT_OPERATIONS` |
| `sign` | `SIGN` |
| `encrypt` | `ENCRYPT` |
| `svk_unwrap` | `SVK_UNWRAP` |
| `mls_messaging` | `MLS_MESSAGING` |

**Response (200 OK) - Active Token:**

```json
{
  "active": true,
  "identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "machine_id": "660e8400-e29b-41d4-a716-446655440001",
  "namespace_id": "550e8400-e29b-41d4-a716-446655440000",
  "mfa_verified": false,
  "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
  "scope": ["default"],
  "revocation_epoch": 0,
  "exp": 1705839300
}
```

**Response (200 OK) - Inactive Token:**

```json
{
  "active": false,
  "identity_id": null,
  "machine_id": null,
  "namespace_id": null,
  "mfa_verified": null,
  "capabilities": null,
  "scope": null,
  "revocation_epoch": null,
  "exp": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `active` | boolean | Whether the token is valid |
| `identity_id` | UUID | Identity ID (null if inactive) |
| `machine_id` | UUID | Machine ID (null if inactive) |
| `namespace_id` | UUID | Namespace ID (null if inactive) |
| `mfa_verified` | boolean | MFA status (null if inactive) |
| `capabilities` | array | Machine capabilities (null if inactive) |
| `scope` | array | Authorized scopes (null if inactive) |
| `revocation_epoch` | integer | Current revocation epoch (null if inactive) |
| `exp` | integer | Expiration timestamp (null if inactive) |

**Note:** If `operation_type` is provided and the token lacks the required capability, `active` will be `false` even if the token is otherwise valid.

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid bearer token |
| `FORBIDDEN` | Token belongs to a different identity |

---

### GET /.well-known/jwks.json

Get the JSON Web Key Set for JWT verification.

**Authentication:** None

**Response (200 OK):**

```json
{
  "keys": [
    {
      "kty": "OKP",
      "kid": "key-id-1",
      "alg": "EdDSA",
      "use": "sig",
      "crv": "Ed25519",
      "x": "base64url_encoded_public_key"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `keys` | array | Array of JWK keys |
| `keys[].kty` | string | Key type (always `"OKP"` for Ed25519) |
| `keys[].kid` | string | Key ID (use to match JWT `kid` header) |
| `keys[].alg` | string | Algorithm (always `"EdDSA"`) |
| `keys[].use` | string | Key usage (always `"sig"`) |
| `keys[].crv` | string | Curve (always `"Ed25519"`) |
| `keys[].x` | string | Base64url-encoded public key |

---

## Multi-Factor Authentication

Endpoints for TOTP-based multi-factor authentication.

### POST /v1/mfa/setup

Set up TOTP-based MFA for an identity.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "encrypted_totp_secret": {
    "ciphertext": "a1b2c3d4...",
    "nonce": "e5f6g7h8i9j0k1l2m3n4o5p6...",
    "algorithm": "xchacha20poly1305"
  },
  "backup_code_hashes": [
    "hash1...",
    "hash2...",
    "hash3..."
  ],
  "verification_code": "123456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `encrypted_totp_secret` | object | Yes | Client-encrypted TOTP secret |
| `encrypted_totp_secret.ciphertext` | string | Yes | Encrypted secret (hex) |
| `encrypted_totp_secret.nonce` | string | Yes | 24-byte nonce (hex, 48 chars) |
| `encrypted_totp_secret.algorithm` | string | Yes | Must be `"xchacha20poly1305"` |
| `backup_code_hashes` | array | Yes | Pre-hashed backup codes (hex, 1-20 codes) |
| `verification_code` | string | Yes | TOTP code to verify setup |

**Response (200 OK):**

```json
{
  "mfa_enabled": true,
  "enabled_at": "2025-01-21T12:00:00Z",
  "totp_secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/zero-id:user?secret=JBSWY3DPEHPK3PXP&issuer=zero-id",
  "backup_codes": [
    "XXXX-XXXX-XXXX",
    "YYYY-YYYY-YYYY",
    "ZZZZ-ZZZZ-ZZZZ"
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mfa_enabled` | boolean | Always `true` on success |
| `enabled_at` | string | RFC 3339 timestamp |
| `totp_secret` | string | Base32-encoded secret (show once!) |
| `qr_code_url` | string | URL for QR code generation |
| `backup_codes` | array | Plaintext backup codes (show once!) |

**Important:** The `totp_secret` and `backup_codes` are only returned once. Users must save them securely.

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Invalid algorithm, nonce length, or verification code |
| `CONFLICT` | MFA already enabled |

---

### DELETE /v1/mfa

Disable MFA for an identity.

**Authentication:** Bearer token required (MFA must be verified)

**Request Body:**

```json
{
  "mfa_code": "123456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mfa_code` | string | Yes | Current TOTP code or backup code |

**Response:** `204 No Content`

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `MFA_REQUIRED` | MFA verification required for this operation |
| `INVALID_REQUEST` | Invalid MFA code |

---

## Credentials

Endpoints for managing authentication credentials (email, OAuth links).

### POST /v1/credentials/email

Add an email/password credential to an existing identity.

**Authentication:** Bearer token required

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "secure_password"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address |
| `password` | string | Yes | Password (minimum requirements apply) |

**Response (200 OK):**

```json
{
  "message": "Email credential 'user@example.com' added successfully"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Invalid email format or weak password |
| `CONFLICT` | Email already registered |

---

### POST /v1/credentials/oauth/:provider

Initiate linking an OAuth account to the authenticated identity.

**Authentication:** Bearer token required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | OAuth provider: `google`, `x`, `epic` |

**Response (200 OK):**

```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "random_state_string"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Unknown OAuth provider |

---

### POST /v1/credentials/oauth/:provider/callback

Complete linking an OAuth account.

**Authentication:** Bearer token required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | OAuth provider: `google`, `x`, `epic` |

**Request Body:**

```json
{
  "code": "oauth_authorization_code",
  "state": "random_state_string"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | Authorization code from OAuth provider |
| `state` | string | Yes | State parameter (must match initiation) |

**Response (200 OK):**

```json
{
  "message": "OAuth credential linked successfully"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Missing or invalid token |
| `INVALID_REQUEST` | Invalid state or code |
| `CONFLICT` | OAuth account already linked to another identity |

---

## Post-Quantum Cryptography

zero-id supports optional post-quantum (PQ) cryptographic keys alongside classical keys to provide defense against future quantum computers.

### Overview

Machine keys can be created with two key schemes:

| Scheme | Classical Keys | Post-Quantum Keys | Use Case |
|--------|---------------|-------------------|----------|
| `classical` | Ed25519 + X25519 | None | Default, OpenMLS compatible, smaller keys |
| `pq_hybrid` | Ed25519 + X25519 | ML-DSA-65 + ML-KEM-768 | Post-quantum protection with backward compatibility |

In PQ-Hybrid mode, classical keys are **always present** for backward compatibility. The PQ keys provide additional protection for application-level protocols.

### Key Sizes

| Key Type | Algorithm | Hex Size | Byte Size | Standard |
|----------|-----------|----------|-----------|----------|
| Signing (classical) | Ed25519 | 64 chars | 32 bytes | RFC 8032 |
| Encryption (classical) | X25519 | 64 chars | 32 bytes | RFC 7748 |
| PQ Signing | ML-DSA-65 | 3,904 chars | 1,952 bytes | FIPS 204 |
| PQ Encryption | ML-KEM-768 | 2,368 chars | 1,184 bytes | FIPS 203 |

### Signature Sizes

| Algorithm | Hex Size | Byte Size |
|-----------|----------|-----------|
| Ed25519 | 128 chars | 64 bytes |
| ML-DSA-65 | 6,618 chars | 3,309 bytes |

### Availability

PQ-Hybrid support is always available on zero-id servers. Both `classical` and `pq_hybrid` key schemes are supported without any additional configuration.

### Example: Creating Identity with PQ-Hybrid Keys

```json
{
  "identity_id": "550e8400-e29b-41d4-a716-446655440000",
  "identity_signing_public_key": "a1b2c3d4...",
  "authorization_signature": "e5f6g7h8...",
  "machine_key": {
    "machine_id": "660e8400-e29b-41d4-a716-446655440001",
    "signing_public_key": "i9j0k1l2...",
    "encryption_public_key": "m3n4o5p6...",
    "key_scheme": "pq_hybrid",
    "pq_signing_public_key": "q7r8s9t0...(3904 hex chars)...",
    "pq_encryption_public_key": "u1v2w3x4...(2368 hex chars)...",
    "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
    "device_name": "My Laptop",
    "device_platform": "macos"
  },
  "namespace_name": "Personal",
  "created_at": 1705838400
}
```

### Client-Side Key Derivation

Use `zero-id-crypto` to derive PQ-Hybrid keys:

```rust
use zero_id_crypto::{
    derive_machine_keypair_with_scheme, KeyScheme, MachineKeyCapabilities,
};

let keypair = derive_machine_keypair_with_scheme(
    &neural_key,
    &identity_id,
    &machine_id,
    epoch,
    MachineKeyCapabilities::FULL_DEVICE,
    KeyScheme::PqHybrid,
)?;

// Access classical keys (always present)
let signing_pk = keypair.signing_public_key();       // 32 bytes
let encryption_pk = keypair.encryption_public_key(); // 32 bytes

// Access PQ keys (only in PqHybrid mode)
if let Some(pq_sign_pk) = keypair.pq_signing_public_key() {
    // 1,952 bytes ML-DSA-65 public key
}
if let Some(pq_kem_pk) = keypair.pq_encryption_public_key() {
    // 1,184 bytes ML-KEM-768 public key
}
```

### Security Considerations

- **NIST Level 3**: ML-DSA-65 and ML-KEM-768 provide 128-bit post-quantum security
- **Hybrid security**: If either classical or PQ algorithm is secure, the system remains secure
- **Storage impact**: PQ keys are significantly larger (~60x for signatures, ~37x for encryption keys)
- **Bandwidth**: Consider the increased payload size for mobile or constrained clients

For detailed migration strategy and threat analysis, see [Quantum Considerations](../encryption/quantum.md).

---

## Integrations

Endpoints for external service integration.

### POST /v1/integrations/register

Register an external service for receiving revocation events.

**Authentication:** mTLS required (client certificate)

**Request Body:**

```json
{
  "service_name": "My Application",
  "scopes": [
    "events:machine_revoked",
    "events:session_revoked",
    "events:identity_frozen"
  ],
  "namespace_filters": [
    "880e8400-e29b-41d4-a716-446655440003"
  ],
  "webhook_url": "https://example.com/webhook",
  "webhook_secret": "a1b2c3d4e5f6..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service_name` | string | Yes | Human-readable service name |
| `scopes` | array | Yes | Event scopes to subscribe to |
| `namespace_filters` | array | Yes | Namespaces to receive events for |
| `webhook_url` | string | No | HTTPS URL for webhook delivery |
| `webhook_secret` | string | No | 32-byte secret for webhook signatures (hex, 64 chars) |

**Available Scopes:**

| Scope | Description |
|-------|-------------|
| `events:machine_revoked` | Machine key revocation events |
| `events:session_revoked` | Session revocation events |
| `events:identity_frozen` | Identity freeze events |

**Response (200 OK):**

```json
{
  "service_id": "cc0e8400-e29b-41d4-a716-446655440007",
  "registered_at": "2025-01-21T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `service_id` | UUID | Registered service ID |
| `registered_at` | string | RFC 3339 timestamp |

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Missing mTLS certificate, invalid scopes, or invalid webhook secret |

---

### GET /v1/events/stream

Subscribe to real-time revocation events via Server-Sent Events (SSE).

**Authentication:** mTLS required (client certificate must match registered service)

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service_id` | UUID | Yes | Registered service ID |
| `last_sequence` | integer | No | Resume from sequence number (for reconnection) |

**Response:** `text/event-stream`

**Event Format:**

```
id: 12345
event: machine_revoked
data: {"event_type":"machine_revoked","machine_id":"...","identity_id":"...","timestamp":1705838400,"sequence":12345}

id: 12346
event: session_revoked
data: {"event_type":"session_revoked","session_id":"...","identity_id":"...","timestamp":1705838401,"sequence":12346}
```

**Event Types:**

| Event | Fields |
|-------|--------|
| `machine_revoked` | `event_type`, `machine_id`, `identity_id`, `namespace_id`, `timestamp`, `sequence` |
| `session_revoked` | `event_type`, `session_id`, `identity_id`, `namespace_id`, `timestamp`, `sequence` |
| `identity_frozen` | `event_type`, `identity_id`, `namespace_id`, `reason`, `timestamp`, `sequence` |

**Errors:**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Missing mTLS certificate |
| `UNAUTHORIZED` | Service not registered or certificate mismatch |
