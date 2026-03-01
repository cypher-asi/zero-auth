# Zero-ID Desktop App — Technical Architecture & Module Boundaries

This document defines the layered architecture, module boundaries, concurrency
model, secret-handling rules, and the mapping from server endpoints to desktop
service modules for the `Rust + egui` desktop application.

---

## 1  Layered Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     UI Layer (egui)                       │
│  Pages, dialogs, reusable components, theme/tokens       │
│  No business logic — reads AppState, dispatches actions   │
├──────────────────────────────────────────────────────────┤
│                    AppState Layer                         │
│  Global state, navigation, async job status, view models  │
│  Owns all mutable state; updated by service results       │
├──────────────────────────────────────────────────────────┤
│                    Service Layer                          │
│  Domain logic modules: identity, machine, credentials,    │
│  MFA, sessions, ceremonies, key/shard                     │
│  Pure functions + async operations; no UI dependencies    │
├──────────────────────────────────────────────────────────┤
│                     Infra Layer                           │
│  HTTP client, secure local storage, OS integrations,      │
│  crypto adapter (wraps zid-crypto)                        │
└──────────────────────────────────────────────────────────┘
```

### Layer Rules

| Layer | May depend on | Must not depend on | Owns |
|-------|--------------|-------------------|------|
| UI | AppState (read), Service (dispatch) | Infra | Rendering, user input |
| AppState | — | UI, Service, Infra | All mutable app state, navigation |
| Service | Infra, zid-crypto, zid crate | UI, AppState directly | Domain logic, request construction |
| Infra | OS APIs, network, filesystem | UI, AppState, Service | HTTP, storage, platform |

---

## 2  Module Boundaries

### 2.1  Service Modules

Each service module owns a single domain and exposes an async trait.

| Module | Responsibility | Key Types |
|--------|---------------|-----------|
| `identity` | Create/view identity, freeze/unfreeze, disable/enable, tier management | `Identity`, `CreateIdentityRequest`, `FreezeRequest` |
| `key_shard` | Neural Key generation, HKDF derivation, Shamir split/combine, passphrase encrypt/decrypt, zeroization | `NeuralKey`, `Shard`, `ShardSet`, `DerivedKeys` |
| `machine` | Enroll/list/revoke machines, capability and key-scheme display | `MachineKey`, `EnrollRequest`, `MachineListResponse` |
| `credentials` | Link/list/revoke/set-primary for email, OAuth, wallet credentials | `AuthLinkRecord`, `LinkEmailRequest`, `OAuthFlow` |
| `session` | Login (all methods), token refresh, introspection, revocation | `SessionTokens`, `LoginRequest`, `TokenClaims` |
| `mfa` | Setup/enable/disable/verify TOTP, backup code management | `MfaSetup`, `TotpVerifyRequest` |
| `ceremonies` | Multi-approval unfreeze, key rotation, recovery ceremony orchestration | `Approval`, `RotationRequest`, `RecoveryRequest` |

### 2.2  Infra Modules

| Module | Responsibility |
|--------|---------------|
| `http_client` | Typed HTTP client wrapping `reqwest`; base URL, auth header injection, error mapping, rate-limit handling |
| `local_storage` | Read/write `~/.zid/credentials.json`; file permissions; atomic writes |
| `crypto_adapter` | Wraps `zid-crypto` and `zid` crate operations; exposes high-level functions for key derivation, signing, encryption |
| `os_integration` | Clipboard access, system browser launch (OAuth), file permission setting |

### 2.3  UI Modules

```
ui/
├── components/
│   ├── core/           # Button, Input, Modal, Toast, Badge, DataTable,
│   │                   # ConfirmDialog, ProgressStepper, Spinner, etc.
│   └── domain/         # IdentityBadge, MachineCard, ShardCard,
│                       # CredentialLinkCard, SessionCard, TotpInput, etc.
├── pages/
│   ├── onboarding/     # CreateIdentityPage, RecoverIdentityPage, LoginPage
│   ├── dashboard/      # DashboardPage
│   ├── machines/       # MachinesPage
│   ├── credentials/    # LinkedIdentitiesPage
│   ├── mfa/            # MfaPage
│   ├── sessions/       # SessionsPage
│   ├── namespaces/     # NamespacesPage
│   └── security/       # SecurityPage (freeze, ceremonies)
├── layout/             # Sidebar, PageHeader, ActionBar, FrozenBanner
└── theme/              # Design tokens, colors, spacing, typography
```

### 2.4  AppState Structure

```rust
struct AppState {
    // Navigation
    current_page: Page,
    navigation_stack: Vec<Page>,

    // Identity
    identity: Option<IdentityViewModel>,
    identity_status: LoadStatus,

    // Machines
    machines: Vec<MachineViewModel>,
    machines_status: LoadStatus,

    // Credentials
    credentials: Vec<CredentialViewModel>,
    credentials_status: LoadStatus,

    // MFA
    mfa_status: MfaState,     // Disabled | SetupInProgress(MfaSetup) | Enabled

    // Sessions
    current_session: Option<SessionViewModel>,
    active_sessions: Vec<SessionViewModel>,

    // Namespaces
    namespaces: Vec<NamespaceViewModel>,
    active_namespace: Option<NamespaceId>,

    // Security
    frozen_state: Option<FrozenInfo>,

    // Async jobs
    pending_jobs: HashMap<JobId, JobStatus>,

    // Notifications
    toasts: Vec<ToastMessage>,

    // Auth tokens (kept separate for security)
    token_store: TokenStore,
}

enum LoadStatus { Idle, Loading, Loaded, Error(String) }
enum Page { Onboarding(OnboardingStep), Dashboard, Machines, /* ... */ }
```

---

## 3  Concurrency Model

### Runtime

- **Main thread**: `egui` event loop via `eframe`. All rendering happens here.
- **Async runtime**: `tokio` multi-threaded runtime, started alongside `eframe`.
- **Background tasks**: Service operations (API calls, crypto) spawn on `tokio`.

### Communication Pattern

```
UI Thread                          Tokio Runtime
─────────                          ─────────────
User action
  │
  ├─► dispatch(Action)
  │     │
  │     ├─► spawn async task ──────► service.do_work()
  │     │                               │
  │     │                               ├─► infra.http_call()
  │     │                               │
  │     │     ◄─── mpsc channel ◄───────┘ Result<T, Error>
  │     │
  │     ├─► update AppState
  │     │
  ◄────┘ ctx.request_repaint()
```

- **Channel**: `tokio::sync::mpsc` (unbounded) for task → UI messages.
- **Repaint**: `ctx.request_repaint()` called on every message receipt to wake `egui`.
- **No shared mutable state**: AppState owned by UI thread; tasks send immutable results.

### Task Types

| Type | Runs On | Examples |
|------|---------|---------|
| API call | tokio | Login, refresh, list machines, enroll |
| Crypto | tokio (blocking spawn) | Argon2id KDF, Shamir combine, HKDF derivation |
| File I/O | tokio | Read/write credentials file |
| Timer | tokio | Auto-refresh scheduler, toast auto-dismiss |

---

## 4  Secret-Handling Boundaries

### Trust Zones

```
┌─────────────────────────────────────────────────┐
│  TRUSTED ZONE (service + crypto_adapter)         │
│  Neural Key, ISK, machine private keys, KEK,     │
│  raw shards — live here only, zeroized after use  │
├─────────────────────────────────────────────────┤
│  BOUNDARY (AppState)                             │
│  Only public keys, identifiers, status enums,    │
│  view model data cross into AppState             │
├─────────────────────────────────────────────────┤
│  UNTRUSTED ZONE (UI)                             │
│  Renders public data only; passphrase entered     │
│  via Input component → passed to service → never  │
│  stored in AppState                               │
└─────────────────────────────────────────────────┘
```

### Rules

1. **Neural Key**: Exists only inside `key_shard` service functions. Zeroized via `zeroize::Zeroize` trait before function returns.
2. **ISK / machine private keys**: Derived in `crypto_adapter`, used for signing in `session` service, zeroized immediately after.
3. **Passphrase**: Received as `String` from UI Input → passed to `key_shard::decrypt_shard()` → Argon2id → zeroized.
4. **Shards (cleartext)**: Only in `key_shard` service during combine/split. Hex display values constructed and returned as `String` — these are the only shard representations that leave the service layer, and only during initial display or recovery.
5. **Tokens**: `access_token` and `refresh_token` stored in `TokenStore` (in AppState). Access token included in HTTP Authorization header by `http_client`. Refresh token used only by `session::refresh()`.
6. **No raw secret in UI state**: AppState must never contain `NeuralKey`, `ISK`, `MachinePrivateKey`, `KEK`, or decrypted shards.

---

## 5  Server Endpoint → Service Module Mapping

### Identity Service

| Endpoint | Method | Service Function | View Model Output |
|----------|--------|-----------------|-------------------|
| `POST /v1/identity` | POST | `identity::create_self_sovereign()` | `IdentityViewModel` |
| `GET /v1/identity` | GET | `identity::get_current()` | `IdentityViewModel` |
| `POST /v1/identity/freeze` | POST | `identity::freeze()` | `FrozenInfo` |
| `POST /v1/identity/unfreeze` | POST | `ceremonies::unfreeze()` | `IdentityViewModel` |
| `POST /v1/identity/disable` | POST | `identity::disable()` | `IdentityViewModel` |
| `POST /v1/identity/enable` | POST | `identity::enable()` | `IdentityViewModel` |

### Machine Service

| Endpoint | Method | Service Function | View Model Output |
|----------|--------|-----------------|-------------------|
| `POST /v1/identity/machines` | POST | `machine::enroll()` | `MachineViewModel` |
| `GET /v1/identity/machines` | GET | `machine::list()` | `Vec<MachineViewModel>` |
| `DELETE /v1/identity/machines/{id}` | DELETE | `machine::revoke(id)` | `()` |

### Session Service

| Endpoint | Method | Service Function | View Model Output |
|----------|--------|-----------------|-------------------|
| `GET /v1/auth/challenge` | GET | `session::request_challenge()` | `Challenge` |
| `POST /v1/auth/login/machine` | POST | `session::login_machine()` | `SessionTokens` |
| `POST /v1/auth/login/email` | POST | `session::login_email()` | `SessionTokens` |
| `POST /v1/auth/login/oauth` | POST | `session::login_oauth()` | `SessionTokens` |
| `POST /v1/auth/login/wallet` | POST | `session::login_wallet()` | `SessionTokens` |
| `POST /v1/auth/refresh` | POST | `session::refresh()` | `SessionTokens` |
| `POST /v1/auth/introspect` | POST | `session::introspect()` | `TokenIntrospection` |
| `POST /v1/auth/revoke` | POST | `session::revoke()` | `()` |

### Credentials Service

| Endpoint | Method | Service Function | View Model Output |
|----------|--------|-----------------|-------------------|
| `POST /v1/credentials/email` | POST | `credentials::link_email()` | `CredentialViewModel` |
| `POST /v1/credentials/wallet` | POST | `credentials::link_wallet()` | `CredentialViewModel` |
| `GET /v1/oauth/{provider}/initiate` | GET | `credentials::initiate_oauth()` | `OAuthInitiateResponse` |
| `POST /v1/oauth/callback` | POST | `credentials::complete_oauth()` | `CredentialViewModel` |
| `DELETE /v1/credentials/{type}/{id}` | DELETE | `credentials::revoke()` | `()` |
| `PUT /v1/credentials/{type}/{id}/primary` | PUT | `credentials::set_primary()` | `CredentialViewModel` |

### MFA Service

| Endpoint | Method | Service Function | View Model Output |
|----------|--------|-----------------|-------------------|
| `POST /v1/mfa/setup` | POST | `mfa::setup()` | `MfaSetup` |
| `POST /v1/mfa/enable` | POST | `mfa::enable()` | `()` |
| `POST /v1/mfa/disable` | POST | `mfa::disable()` | `()` |
| `POST /v1/mfa/verify` | POST | `mfa::verify()` | `AuthResult` |

### Ceremonies Service

| Endpoint | Method | Service Function | View Model Output |
|----------|--------|-----------------|-------------------|
| `POST /v1/identity/unfreeze` | POST | `ceremonies::unfreeze()` | `IdentityViewModel` |
| `POST /v1/identity/rotate` | POST | `ceremonies::rotate_key()` | `RotationResult` |
| `POST /v1/identity/recovery` | POST | `ceremonies::recover()` | `RecoveryResult` |

### Key/Shard Service (Client-Only — No Server Endpoints)

| Operation | Service Function | Notes |
|-----------|-----------------|-------|
| Generate Neural Key | `key_shard::generate_neural_key()` | CSPRNG, returns `Zeroizing<[u8; 32]>` |
| Derive ISK | `key_shard::derive_isk()` | HKDF from Neural Key |
| Derive machine keypair | `key_shard::derive_machine_key()` | HKDF from Neural Key + epoch |
| Split into shards | `key_shard::split_shards()` | Shamir 3-of-5 |
| Combine shards | `key_shard::combine_shards()` | Any 3 of 5 |
| Encrypt shard | `key_shard::encrypt_shard()` | Argon2id → KEK → XChaCha20 |
| Decrypt shard | `key_shard::decrypt_shard()` | Reverse of encrypt |
| Zeroize secrets | Automatic via `Zeroizing<T>` wrapper | Drop trait |

---

## 6  Crate Dependency Map (Desktop App)

```
zid-desktop
├── eframe / egui          (UI framework)
├── tokio                   (async runtime)
├── reqwest                 (HTTP client)
├── serde / serde_json      (serialization)
├── zeroize                 (secret cleanup)
├── zid-crypto              (key derivation, encryption, Shamir)
├── zid (external)          (PQ-hybrid crypto, DID, commitment, server types)
├── tracing                 (structured logging)
├── directories             (platform-specific paths)
├── arboard                 (clipboard)
├── open                    (system browser launch)
└── image + qrcode          (QR code rendering for MFA)
```

---

## 7  Error Handling Strategy

### Server Error Mapping

```rust
enum AppError {
    // Network
    ServerUnreachable,
    Timeout,
    RateLimited { retry_after: Duration },

    // Auth
    InvalidCredentials,
    SessionExpired,
    TokenFamilyRevoked,
    MfaRequired,
    IdentityFrozen,

    // Validation
    InvalidInput(String),
    ShardCombineFailed,
    PassphraseIncorrect,

    // Server
    ServerError(u16, String),
    NotFound(String),
    Conflict(String),

    // Local
    StorageError(String),
    CryptoError(String),
}
```

Each `AppError` variant maps to a user-friendly message string via a `Display` impl.
The UI layer only sees `AppError` — never raw HTTP status codes or JSON error bodies.

---

## 8  Screen → Page Module → Service Module Map

| Screen | Page Module | Primary Services | Key AppState Fields |
|--------|------------|-----------------|-------------------|
| Welcome / Create | `onboarding::create` | `key_shard`, `identity`, `machine`, `session` | `identity`, `machines`, `current_session` |
| Recover | `onboarding::recover` | `key_shard`, `ceremonies` | `identity`, `machines` |
| Login | `onboarding::login` | `key_shard`, `session` | `current_session`, `token_store` |
| Dashboard | `dashboard` | `identity`, `session` | `identity`, `current_session` |
| Machines | `machines` | `machine` | `machines`, `machines_status` |
| Linked Identities | `credentials` | `credentials` | `credentials`, `credentials_status` |
| MFA | `mfa` | `mfa` | `mfa_status` |
| Sessions | `sessions` | `session` | `active_sessions` |
| Namespaces | `namespaces` | (namespace service, implied) | `namespaces`, `active_namespace` |
| Security | `security` | `identity`, `ceremonies` | `frozen_state`, `identity` |
