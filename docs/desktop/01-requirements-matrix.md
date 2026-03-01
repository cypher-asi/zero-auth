# Zero-ID Desktop App — Requirements Matrix

This document captures every functional and non-functional requirement for the native
desktop identity application (`Rust + egui`). Each requirement traces back to the
v0.1.1 specification and the server API surface.

---

## 1  Identity Lifecycle

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| ID-01 | As a user I can create a self-sovereign identity so that I control my own root key | `POST /v1/identity` | Neural Key generated client-side, never transmitted; ISK derived via HKDF; canonical creation message signed with ISK | Identity record returned with `tier: SelfSovereign`, DID in `did:key` format, initial machine enrolled | `required_for_parity` |
| ID-02 | As a user I can view my identity details (DID, tier, status, timestamps) | `GET /v1/identity` | Access token required; identity data is non-sensitive | Dashboard shows identity_id, DID, tier, status, created/updated timestamps | `required_for_parity` |
| ID-03 | As an operator I can disable/enable an identity | `POST /v1/identity/disable`, `POST /v1/identity/enable` | Requires admin policy; status transitions enforced (Active↔Disabled) | Status toggles correctly; disabled identity cannot authenticate | `optional_for_v1` |
| ID-04 | As a user I can freeze my identity after a security incident | `POST /v1/identity/freeze` | Any active machine can freeze; all machine auth fails while frozen; sessions continue until next refresh | Freeze succeeds, auth attempts return 403, freeze reason stored | `optional_for_v1` |
| ID-05 | As a user I can unfreeze my identity with multi-machine approval | `POST /v1/identity/unfreeze` | Requires ≥2 active machine approvals; each approval signed with MPK; timestamps within 900 s | Unfreeze succeeds only with quorum; identity returns to Active | `advanced` |
| ID-06 | As a user I can see my identity tier and understand capabilities | — (local display) | — | UI clearly labels Managed vs Self-Sovereign with capability tooltips | `required_for_parity` |

## 2  Neural Key Lifecycle

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| NK-01 | As a user I can generate a Neural Key during identity creation | — (client-only) | 32-byte CSPRNG; never leaves client memory; zeroized after shard split | Key generated, used for derivation, then zeroized; no disk trace | `required_for_parity` |
| NK-02 | As a user I can split the Neural Key into 3-of-5 Shamir shards | — (client-only) | Threshold 3, total 5; shards 1–2 kept on device (shard 2 passphrase-encrypted); shards 3–5 given to user | Five shards produced; user shown shards 3–5 as hex; shard 2 encrypted with Argon2id-derived KEK | `required_for_parity` |
| NK-03 | As a user I can protect shard 2 with a passphrase | — (client-only) | Argon2id (64 MiB, 3 iterations) → KEK; XChaCha20-Poly1305 with AAD `"cypher:share-backup:v1" \|\| identity_id \|\| shard_index` | Encrypted shard stored; decryption requires correct passphrase; wrong passphrase fails with clear error | `required_for_parity` |
| NK-04 | As a user I can reconstruct the Neural Key from any 3 shards for login | — (client-only, then `POST /v1/auth/login/machine`) | Reconstruct in-memory only; zeroize after use; never persist full key | Login succeeds with any valid 3-of-5 combination; key memory zeroed post-use | `required_for_parity` |
| NK-05 | As a user I can rotate my Neural Key with multi-machine ceremony | `POST /v1/identity/rotate` | ≥2 active machine approvals; old machines revoked; new machines enrolled from new key | New commitment stored; old machines revoked; new shards distributed | `advanced` |

## 3  Machine Lifecycle

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| MC-01 | As a user I can enroll a new machine (device) | `POST /v1/identity/machines` | Machine keypair derived from Neural Key; canonical enrollment message signed with ISK; epoch tracked | Machine appears in list with signing/encryption public keys and capabilities | `required_for_parity` |
| MC-02 | As a user I can list all enrolled machines | `GET /v1/identity/machines` | Access token required | Table shows machine_id, capabilities, key scheme (classical/PQ-hybrid), epoch, created_at | `required_for_parity` |
| MC-03 | As a user I can revoke a machine | `DELETE /v1/identity/machines/{id}` | Policy check; RevocationEvent published; epoch rotation triggered | Machine removed from list; subsequent auth with that machine fails; downstream events fired | `required_for_parity` |
| MC-04 | As a user I can see whether a machine uses classical or PQ-hybrid keys | `GET /v1/identity/machines` | — | Key scheme badge displayed per machine (e.g., "Ed25519" vs "ML-DSA-65 + Ed25519") | `optional_for_v1` |

## 4  Linked Identities (Credentials)

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| LI-01 | As a user I can link an email credential to my identity | `POST /v1/credentials/email` | Password hashed with Argon2id server-side; AuthLinkRecord created | Email appears in linked credentials list; login via email works | `optional_for_v1` |
| LI-02 | As a user I can link an OAuth provider (Google, X, Epic) | `GET /v1/oauth/{provider}/initiate`, `POST /v1/oauth/callback` | PKCE S256; state param 32 bytes, 10 min TTL; ID token validated | OAuth link shown in credentials list; login via OAuth works | `optional_for_v1` |
| LI-03 | As a user I can link a wallet (EVM/Solana) | `POST /v1/credentials/wallet` | Challenge-response with EIP-191 personal_sign; ecrecover validation | Wallet address shown in credentials list; login via wallet works | `optional_for_v1` |
| LI-04 | As a user I can list all linked credentials | `GET /v1/credentials` (implied) | Access token required | List shows method_type, method_id, primary flag, verified status | `optional_for_v1` |
| LI-05 | As a user I can revoke a linked credential | `DELETE /v1/credentials/{type}/{id}` (implied) | Cannot revoke last/primary method without replacement | Credential removed; auth via that method fails | `optional_for_v1` |
| LI-06 | As a user I can set a credential as primary | `PUT /v1/credentials/{type}/{id}/primary` (implied) | Must be verified | Primary flag updated; old primary cleared | `optional_for_v1` |

## 5  Authentication & Sessions

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| AU-01 | As a user I can log in with my machine key via challenge-response | `GET /v1/auth/challenge`, `POST /v1/auth/login/machine` | Challenge nonce 32 bytes, 60 s expiry, one-time use; signature verified against enrolled MPK | Session created; access + refresh tokens returned | `required_for_parity` |
| AU-02 | As a user I can log in with email/password | `POST /v1/auth/login/email` | Argon2id password verification; MFA check if enabled | Session created; MFA prompt if configured | `optional_for_v1` |
| AU-03 | As a user I can log in with OAuth | `GET /v1/oauth/{provider}/initiate`, `POST /v1/oauth/callback` | PKCE, state validation | Session created after OAuth callback | `optional_for_v1` |
| AU-04 | As a user I can log in with a wallet signature | `POST /v1/auth/login/wallet` | Challenge-response; ecrecover | Session created | `optional_for_v1` |
| AU-05 | As a user I can refresh my access token transparently | `POST /v1/auth/refresh` | Generation tracking; reuse of old generation revokes entire token family | New access + refresh tokens issued; old refresh invalidated | `required_for_parity` |
| AU-06 | As a user I can introspect my token to see session details | `POST /v1/auth/introspect` | Signature + expiry + audience + session revocation checks | Introspection result with active flag, claims, capabilities | `required_for_parity` |
| AU-07 | As a user I can revoke my current session | `POST /v1/auth/revoke` (implied) | Session marked revoked; refresh tokens invalidated | Subsequent refresh/access attempts fail | `required_for_parity` |

## 6  MFA (Multi-Factor Authentication)

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| MF-01 | As a user I can set up TOTP MFA and receive a QR code | `POST /v1/mfa/setup` | TOTP HMAC-SHA1, 6 digits, 30 s period; 10 backup codes generated; secret shown as Base32 | QR code displayed; backup codes shown once and must be saved | `optional_for_v1` |
| MF-02 | As a user I can enable MFA by verifying an initial TOTP code | `POST /v1/mfa/enable` | Code must validate (±1 period) | MFA enabled; subsequent logins require TOTP | `optional_for_v1` |
| MF-03 | As a user I can disable MFA | `POST /v1/mfa/disable` | Requires current valid TOTP or backup code | MFA disabled; logins no longer prompt for TOTP | `optional_for_v1` |
| MF-04 | As a user I can verify MFA during login | `POST /v1/mfa/verify` | ±1 period tolerance (90 s window); backup codes Argon2id hashed, single-use | Auth completes after valid code; backup code consumed on use | `optional_for_v1` |

## 7  Recovery & Ceremonies

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| RC-01 | As a user I can recover my identity by providing ≥3 shards | `POST /v1/identity/recovery` | Shards combined in-memory; Neural Key reconstructed; new machine enrolled; old machines revoked; new shards distributed | Recovery succeeds; new credentials saved; old machines invalidated | `required_for_parity` |
| RC-02 | As a user I receive new shards after recovery | — (client-only) | Re-split into fresh 3-of-5; new passphrase for shard 2 | New user shards (3–5) displayed; shard 2 re-encrypted | `required_for_parity` |
| RC-03 | As a user I can participate in a multi-approval unfreeze ceremony | `POST /v1/identity/unfreeze` | ≥2 machine approvals; signatures verified; timestamps within 900 s | Unfreeze succeeds with quorum; fails without | `advanced` |
| RC-04 | As a user I can participate in a key rotation ceremony | `POST /v1/identity/rotate` | ≥2 machine approvals; old commitment replaced; new machines enrolled | Rotation completes; old keys zeroized; new shards issued | `advanced` |

## 8  Namespaces & Membership

| ID | User Story | API Dependency | Security Constraints | Acceptance Criteria | Priority |
|----|-----------|----------------|---------------------|---------------------|----------|
| NS-01 | As a user I can view namespaces I belong to | `GET /v1/namespaces` (implied) | Access token scoped | List shows namespace name, role (Owner/Admin/Member), joined_at | `optional_for_v1` |
| NS-02 | As a user I can switch my active namespace context | Client-side context switch; server uses `namespace_id` in token claims | Namespace must be active; membership verified | Token claims reflect selected namespace; UI updates context | `optional_for_v1` |
| NS-03 | As a namespace owner I can create/deactivate a namespace | `POST /v1/namespaces`, `PUT /v1/namespaces/{id}` (implied) | Owner-only operations | Namespace created/deactivated; membership operations reflect state | `optional_for_v1` |
| NS-04 | As a namespace admin I can manage members | `POST /v1/namespaces/{id}/members`, `DELETE /v1/namespaces/{id}/members/{mid}` (implied) | Admin+ role; cannot remove owner; cannot promote above own role | Members added/removed; role constraints enforced | `optional_for_v1` |

---

## 9  Non-Functional Requirements

| ID | Category | Requirement | Acceptance Criteria | Priority |
|----|----------|------------|---------------------|----------|
| NF-01 | Secure Storage | Neural Key and shards must never be written to disk in plaintext (full key) | Audit: no plaintext root key in credentials file; shards 2 encrypted | `required_for_parity` |
| NF-02 | Memory Handling | All secret material (Neural Key, ISK, KEK) must be zeroized after use | `zeroize` crate used on all secret types; no lingering copies | `required_for_parity` |
| NF-03 | Auditability | All security-relevant actions must be logged locally | Log file or structured events for create, login, revoke, recover, freeze | `optional_for_v1` |
| NF-04 | Offline Behavior | App must degrade gracefully when server is unreachable | Clear error messages; cached identity data viewable; no operations that require server silently fail | `optional_for_v1` |
| NF-05 | Error Handling | All API errors must surface user-friendly messages | Server error codes mapped to descriptive messages; no raw JSON shown | `required_for_parity` |
| NF-06 | Performance | Crypto operations (Argon2id, Shamir) must not block the UI thread | Heavy crypto runs on `tokio` background tasks; UI shows progress indicator | `required_for_parity` |
| NF-07 | Platform | Single native binary, no web runtime dependency | Builds via `cargo build --release`; no Electron/Tauri/wasm runtime | `required_for_parity` |
| NF-08 | Credential Storage | Local credentials file must have restrictive permissions | 0600 on Unix; ACL-restricted on Windows; path `~/.zid/credentials.json` | `required_for_parity` |
| NF-09 | Rate Limit Handling | Client must respect and surface rate limit responses (429) | Retry-After header honored; user informed of wait time | `required_for_parity` |
| NF-10 | Token Lifecycle | Access token refresh must be automatic and transparent | Background refresh before expiry; seamless to user; fallback to re-login on family revocation | `required_for_parity` |
