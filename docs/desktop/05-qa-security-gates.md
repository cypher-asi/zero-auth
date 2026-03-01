# Zero-ID Desktop App — Test Plan & Security Release Gates

This document defines the test strategy, functional test cases per requirement,
security-sensitive test scenarios, interoperability checks, and release gates.

---

## 1  Test Strategy Overview

### Test Layers

| Layer | Scope | Framework | Runs In |
|-------|-------|-----------|---------|
| **Unit** | Service functions, crypto adapter, state transitions | `#[cfg(test)]` + `tokio::test` | `cargo test` |
| **Integration** | Service → HTTP client → server round-trips | `tests/` workspace crate | Requires running server |
| **E2E / Smoke** | Full flows through UI (headless egui or scripted) | Custom harness | Requires running server |
| **Security** | Secret handling, memory, permissions, error paths | Dedicated security test suite | `cargo test --features security-tests` |

### Coverage Targets

| Area | Minimum | Goal |
|------|---------|------|
| Service layer (business logic) | 80% line | 90% |
| Crypto adapter | 95% line | 100% |
| Key/shard operations | 95% line | 100% |
| Infra layer | 70% line | 80% |
| UI layer | Not measured (manual + smoke tests) | — |

---

## 2  Functional Test Cases by Requirement

### 2.1  Identity Lifecycle

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| ID-01 | Create self-sovereign identity with valid Neural Key | Integration | Server returns identity with `tier: SelfSovereign`, valid DID |
| ID-01 | Create identity with invalid ISK signature | Unit | Server rejects with signature verification error |
| ID-01 | Create identity when server unreachable | Unit | `AppError::ServerUnreachable` returned; no partial state |
| ID-02 | Fetch identity details for authenticated user | Integration | Response matches created identity fields |
| ID-02 | Fetch identity with expired token | Integration | 401 returned; triggers refresh flow |
| ID-03 | Disable identity (admin) | Integration | Status changes to Disabled; auth attempts fail |
| ID-04 | Freeze identity | Integration | Status Frozen; machine auth returns 403 |
| ID-05 | Unfreeze with 2 valid approvals | Integration | Status returns to Active |
| ID-05 | Unfreeze with 1 approval (insufficient) | Integration | Rejected — quorum not met |
| ID-05 | Unfreeze with expired approval timestamp | Integration | Rejected — approval expired |
| ID-06 | Display tier label for Managed identity | Unit | View model shows "Managed" |
| ID-06 | Display tier label for Self-Sovereign identity | Unit | View model shows "Self-Sovereign" |

### 2.2  Neural Key Lifecycle

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| NK-01 | Generated key is 32 bytes | Unit | Length assertion |
| NK-01 | Generated key is random (two calls differ) | Unit | Inequality assertion |
| NK-01 | Key memory is zeroized after scope exit | Security | `Zeroizing<T>` drop verified; memory scan shows zeros |
| NK-02 | 3-of-5 split produces 5 shards | Unit | 5 shards returned |
| NK-02 | Any 3 shards reconstruct the original key | Unit | All C(5,3)=10 combinations tested |
| NK-02 | 2 shards fail to reconstruct | Unit | Combine fails or produces wrong key |
| NK-03 | Shard encrypted with passphrase decrypts correctly | Unit | Round-trip: encrypt → decrypt → original shard |
| NK-03 | Wrong passphrase fails decryption | Unit | Decryption returns error (AEAD tag mismatch) |
| NK-03 | AAD includes identity_id and shard_index | Unit | Decryption with wrong AAD fails |
| NK-04 | Login reconstructs key from shards 1 + 2(decrypted) + 3 | Integration | Derived machine key signs valid challenge |
| NK-05 | Key rotation with 2 approvals succeeds | Integration | New commitment stored; old machines revoked |

### 2.3  Machine Lifecycle

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| MC-01 | Enroll machine with valid ISK signature | Integration | Machine record created with correct public keys |
| MC-01 | Enroll machine with invalid signature | Integration | Server rejects |
| MC-01 | Enroll machine while identity frozen | Integration | Rejected — identity frozen |
| MC-02 | List machines returns all enrolled machines | Integration | Count and IDs match expectations |
| MC-03 | Revoke machine | Integration | Machine no longer in list; auth with revoked key fails |
| MC-03 | Revoke last machine (without recovery) | Integration | Succeeds (policy warning only; not blocked server-side) |
| MC-04 | PQ-hybrid machine shows correct key scheme | Unit | View model badge = "ML-DSA-65 + Ed25519" |

### 2.4  Authentication & Sessions

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| AU-01 | Challenge-response login succeeds | Integration | SessionTokens returned; access token validates |
| AU-01 | Login with expired challenge (> 60 s) | Integration | Rejected — challenge expired |
| AU-01 | Login with reused challenge nonce | Integration | Rejected — nonce already used |
| AU-01 | Login with wrong machine key | Integration | Rejected — signature mismatch |
| AU-02 | Email/password login succeeds | Integration | Session created |
| AU-02 | Email login with wrong password | Integration | Rejected — invalid credentials |
| AU-03 | OAuth login end-to-end | Integration | Session created after callback |
| AU-04 | Wallet login succeeds | Integration | Session created |
| AU-05 | Token refresh with valid refresh token | Integration | New tokens issued; old refresh invalidated |
| AU-05 | Token refresh with reused (old generation) token | Integration | Entire token family revoked |
| AU-05 | Auto-refresh fires before access token expiry | Unit | Timer schedules refresh at `expiry - 60s` |
| AU-06 | Token introspection returns correct claims | Integration | Active=true; claims match |
| AU-06 | Introspection of revoked session | Integration | Active=false |
| AU-07 | Session revocation | Integration | Subsequent refresh fails; introspection returns inactive |

### 2.5  MFA

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| MF-01 | MFA setup returns secret, QR URL, backup codes | Integration | All fields populated; 10 backup codes |
| MF-02 | Enable MFA with valid TOTP code | Integration | MFA active; logins require TOTP |
| MF-02 | Enable MFA with invalid code | Integration | Rejected — code incorrect |
| MF-03 | Disable MFA with valid code | Integration | MFA disabled |
| MF-04 | Login with MFA: valid TOTP code | Integration | Auth completes |
| MF-04 | Login with MFA: code from wrong period | Integration | Rejected (unless ±1 tolerance) |
| MF-04 | Login with MFA: backup code | Integration | Auth completes; code consumed |
| MF-04 | Login with MFA: reused backup code | Integration | Rejected — already consumed |

### 2.6  Recovery & Ceremonies

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| RC-01 | Recovery with 3 valid shards | Integration | New machine enrolled; old machines revoked; new session active |
| RC-01 | Recovery with 2 shards (insufficient) | Unit | Combine fails |
| RC-01 | Recovery with corrupted shard | Unit | Combine produces wrong key; server rejects |
| RC-02 | Post-recovery re-shard produces new 5 shards | Unit | New shards differ from old; 3-of-5 reconstruction works |
| RC-03 | Multi-approval unfreeze with quorum | Integration | Identity unfrozen |
| RC-04 | Key rotation with quorum | Integration | New commitment; old machines revoked |

### 2.7  Linked Identities

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| LI-01 | Link email credential | Integration | Credential appears in list |
| LI-02 | Link OAuth (Google) | Integration | Credential appears in list |
| LI-03 | Link wallet (EVM) | Integration | Credential appears in list |
| LI-04 | List credentials | Integration | All linked methods returned |
| LI-05 | Revoke non-primary credential | Integration | Credential removed |
| LI-05 | Revoke primary credential | Integration | Rejected — must change primary first |
| LI-06 | Set credential as primary | Integration | Primary flag updated |

### 2.8  Namespaces

| Req | Test Case | Type | Pass Criteria |
|-----|----------|------|---------------|
| NS-01 | List namespace memberships | Integration | Memberships with roles returned |
| NS-02 | Switch active namespace | Unit | AppState updated; next API call includes namespace |
| NS-03 | Create namespace (owner) | Integration | Namespace created; creator is Owner |
| NS-04 | Add member (admin) | Integration | Member added with specified role |

---

## 3  Security-Sensitive Test Scenarios

### 3.1  Secret Material Tests

| ID | Scenario | Verification Method |
|----|---------|-------------------|
| SEC-01 | Neural Key zeroized after identity creation | Assert `Zeroizing<T>` drop; optionally scan process memory |
| SEC-02 | ISK zeroized after signing | Assert `Zeroizing<T>` drop on ISK wrapper |
| SEC-03 | KEK zeroized after shard encrypt/decrypt | Assert zeroization of Argon2id output |
| SEC-04 | Passphrase string zeroized after use | Assert passphrase buffer zeroed post-KDF |
| SEC-05 | No plaintext Neural Key in credentials file | Parse `credentials.json`; assert no 32-byte hex field outside shard structure |
| SEC-06 | Shard 2 encrypted on disk | Parse credentials; assert `data_encrypted` + `nonce` present, no `data` field |
| SEC-07 | Credentials file has restrictive permissions | Check file mode ≤ 0600 (Unix) or ACL (Windows) |

### 3.2  Replay & Expiry Tests

| ID | Scenario | Verification Method |
|----|---------|-------------------|
| SEC-08 | Challenge nonce cannot be reused | Second login with same challenge returns error |
| SEC-09 | Expired challenge rejected (> 60 s) | Sleep 61 s between challenge and login; assert rejection |
| SEC-10 | Expired access token rejected | Use token after 15 min; assert 401 |
| SEC-11 | Expired refresh token rejected | Use refresh token after 30 days; assert 401 |

### 3.3  Token Theft Detection Tests

| ID | Scenario | Verification Method |
|----|---------|-------------------|
| SEC-12 | Refresh token reuse (generation replay) revokes family | Use generation N token after generation N+1 issued; assert all sessions in family revoked |
| SEC-13 | After family revocation, all tokens invalid | Attempt refresh and access with any family token; both fail |

### 3.4  Brute Force & Rate Limit Tests

| ID | Scenario | Verification Method |
|----|---------|-------------------|
| SEC-14 | Wrong passphrase does not reveal shard content | 10 wrong attempts; assert only AEAD error, no partial data |
| SEC-15 | Rate limited response handled | Trigger 429; assert `Retry-After` honored; user sees wait message |
| SEC-16 | Failed login attempts tracked | 5 wrong passwords; assert lockout or increased delay |

### 3.5  Error Path Security Tests

| ID | Scenario | Verification Method |
|----|---------|-------------------|
| SEC-17 | Server error does not leak raw JSON to user | All 4xx/5xx mapped to `AppError`; UI shows friendly message |
| SEC-18 | Network timeout does not leave secrets in memory | Timeout during login; assert Neural Key zeroized despite error |
| SEC-19 | Corrupted credentials file handled gracefully | Truncate/corrupt JSON; assert clear error, no crash |
| SEC-20 | Missing credentials file → onboarding | Delete file; app launches to Welcome screen |

---

## 4  Interoperability Checks

| ID | Check | Method |
|----|-------|--------|
| IOP-01 | Desktop-created identity visible via CLI | Create via desktop; `zid-client` GET identity succeeds |
| IOP-02 | CLI-created identity importable to desktop | Create via CLI; desktop loads credentials and logs in |
| IOP-03 | Machine enrolled on desktop, revoked via API | Enroll on desktop; revoke via direct API call; desktop detects revocation on next refresh |
| IOP-04 | Token issued by desktop validates on server | Use desktop access token in curl introspect call; assert active |
| IOP-05 | Server version compatibility | Desktop works with server at current commit; version check on startup optional |
| IOP-06 | Credentials file format compatible between CLI and desktop | Both read/write same `~/.zid/credentials.json` schema |

---

## 5  Release Gates

### 5.1  MVP Release Gate Checklist

| Gate | Requirement | Verification |
|------|------------|-------------|
| **G-01** | No plaintext root secrets at rest | SEC-05, SEC-06 pass |
| **G-02** | All zeroization assertions pass | SEC-01 through SEC-04 pass |
| **G-03** | Identity creation flow passes end-to-end | ID-01 integration test green |
| **G-04** | Login + challenge-response flow passes | AU-01 integration test green |
| **G-05** | Token refresh works (happy path + theft detection) | AU-05, SEC-12, SEC-13 pass |
| **G-06** | Machine enroll/list/revoke all pass | MC-01, MC-02, MC-03 pass |
| **G-07** | Recovery flow works with 3 shards | RC-01, RC-02 pass |
| **G-08** | Shard passphrase encrypt/decrypt round-trips | NK-03 pass |
| **G-09** | Wrong passphrase produces clear error, no data leak | SEC-14 pass |
| **G-10** | Rate limit responses handled | SEC-15 pass |
| **G-11** | Credentials file permissions set correctly | SEC-07 pass |
| **G-12** | All critical error paths return friendly messages | SEC-17, SEC-19, SEC-20 pass |
| **G-13** | No crashes on corrupted/missing credentials | SEC-19, SEC-20 pass |
| **G-14** | CLI interoperability | IOP-01, IOP-02, IOP-06 pass |
| **G-15** | All unit tests pass | `cargo test` exit 0 |
| **G-16** | All integration tests pass | Integration test suite exit 0 |

### 5.2  V1 Release Gate Additions

| Gate | Requirement | Verification |
|------|------------|-------------|
| **G-17** | Email/OAuth/wallet login flows pass | AU-02, AU-03, AU-04 pass |
| **G-18** | MFA full lifecycle (setup → enable → verify → disable) | MF-01 through MF-04 pass |
| **G-19** | Credential link/revoke/primary management | LI-01 through LI-06 pass |
| **G-20** | Namespace visibility and switching | NS-01, NS-02 pass |
| **G-21** | Freeze identity blocks auth | ID-04, SEC tests for frozen state |
| **G-22** | Backup code single-use enforcement | MF-04 reused backup test passes |

### 5.3  Advanced Release Gate Additions

| Gate | Requirement | Verification |
|------|------------|-------------|
| **G-23** | Multi-approval unfreeze ceremony | RC-03, ID-05 pass |
| **G-24** | Key rotation ceremony | RC-04, NK-05 pass |
| **G-25** | Approval expiry enforcement (900 s) | ID-05 expired approval test |

---

## 6  Test Automation & CI

### Recommended Pipeline

```
cargo fmt --check                    # Formatting
cargo clippy -- -D warnings          # Linting
cargo test                           # Unit tests
cargo test --features security-tests # Security-specific tests
cargo test -p tests                  # Integration tests (requires server)
```

### Test Data Management

- **Fixtures**: Pre-generated test identities, shards, credentials stored in `tests/fixtures/`.
- **Server**: Integration tests spin up an in-process server instance via `zid-server` test helpers.
- **Isolation**: Each integration test creates a fresh identity to avoid cross-test contamination.
- **Secrets in tests**: Test Neural Keys are deterministic (seeded CSPRNG) for reproducibility; marked clearly as test-only.

### Regression Protocol

- Every bug fix must include a regression test before the fix is merged.
- Security-sensitive fixes require both a unit test and a security test.
- Ceremony flow bugs require an integration test covering the exact failure scenario.
