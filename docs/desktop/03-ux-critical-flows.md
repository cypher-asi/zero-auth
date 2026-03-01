# Zero-ID Desktop App — UX & Safety Flow Specification

This document defines the user-facing flows, navigation model, safety prompts,
and component composition for every key journey in the `egui` desktop app.

---

## 1  Navigation Model

### Screen Map

```
┌─────────────────────────────────────────────────────────┐
│  Onboarding (no identity)                               │
│  ├─ Create Identity                                     │
│  ├─ Recover Identity                                    │
│  └─ Import (paste shards)                               │
├─────────────────────────────────────────────────────────┤
│  Main App (authenticated)                               │
│  ├─ Dashboard          (identity summary, session)      │
│  ├─ Machines            (list, enroll, revoke)          │
│  ├─ Linked Identities   (email, OAuth, wallet)          │
│  ├─ MFA                 (setup, enable, disable)        │
│  ├─ Sessions            (active sessions, revoke)       │
│  ├─ Namespaces          (list, switch, manage)          │
│  └─ Security            (freeze, ceremonies, shards)    │
├─────────────────────────────────────────────────────────┤
│  Settings                                               │
│  ├─ Server URL                                          │
│  ├─ Credential file location                            │
│  └─ Theme / display preferences                         │
└─────────────────────────────────────────────────────────┘
```

### Navigation Rules

- **Sidebar** navigation for main sections; always visible when authenticated.
- **Onboarding** screens are full-page with no sidebar (identity does not exist yet).
- **Destructive actions** (revoke, disable, freeze) always require a confirmation dialog.
- **Ceremony screens** (rotation, unfreeze) are modal overlays that block other navigation until completed or cancelled.
- **Back navigation**: breadcrumb trail for sub-pages; Escape key returns to parent.

---

## 2  Flow: First-Run Identity Creation

### Steps

```
[Welcome Screen]
    │
    ▼
[Create Identity]
  1. Generate Neural Key (background task, spinner)
  2. Derive ISK + first machine keypair
  3. Sign canonical creation message with ISK
  4. POST /v1/identity → receive identity record
    │
    ▼
[Passphrase Entry]
  1. Prompt: "Choose a strong passphrase to protect your backup shard."
  2. Passphrase strength indicator (zxcvbn or equivalent)
  3. Confirm passphrase (re-type)
  4. Encrypt shard 2 with Argon2id-derived KEK
    │
    ▼
[Shard Backup]
  1. Display shards 3, 4, 5 as hex strings in copyable fields
  2. ⚠ WARNING: "These shards are the ONLY way to recover your identity.
     Store each shard in a different secure location. They will NOT be
     shown again."
  3. Checkbox: "I have securely stored all three shards"
  4. [Continue] button disabled until checkbox checked
    │
    ▼
[Dashboard]
  Identity created, session active, machine enrolled.
```

### Safety Prompts

| Trigger | Prompt | Type | Blocking |
|---------|--------|------|----------|
| Shard display | "These recovery shards will only be shown once. Store each in a separate secure location." | Warning banner | Yes — must acknowledge |
| Weak passphrase | "This passphrase is weak. A stronger passphrase protects your identity backup." | Inline warning | No — allow proceed |
| Creation failure | "Identity creation failed: {error}. Your Neural Key has been securely erased." | Error dialog | Yes — retry or cancel |

### Component Composition

```
CreateIdentityPage
  ├─ ProgressStepper (steps: Generate → Passphrase → Backup → Done)
  ├─ PassphraseInput
  │   ├─ Input (password, masked)
  │   ├─ StrengthBar
  │   └─ Input (confirm)
  ├─ ShardDisplay
  │   ├─ ShardCard × 3 (hex string, copy button)
  │   └─ AcknowledgeCheckbox
  └─ ActionBar (Back, Continue)
```

---

## 3  Flow: Login + Session Renewal

### Steps

```
[Login Screen]
  1. Load stored credentials (~/.zid/credentials.json)
  2. If no credentials → redirect to Onboarding
  3. Prompt for passphrase to decrypt shard 2
  4. Combine shards 1 + 2 + (prompt for one user shard OR use cached)
    │
    ▼
[Challenge-Response]
  1. GET /v1/auth/challenge → nonce
  2. Derive machine signing key from Neural Key
  3. Sign challenge with machine key
  4. POST /v1/auth/login/machine → SessionTokens
  5. Zeroize Neural Key + ISK from memory
    │
    ▼
[Dashboard]
  Session active, auto-refresh scheduled.
```

### Session Renewal (Background)

```
[Access token nearing expiry (< 60 s)]
  1. POST /v1/auth/refresh with current refresh token
  2. On success → store new tokens, reset timer
  3. On 401 (generation mismatch / family revoked) →
     ⚠ "Your session was invalidated. This may indicate unauthorized access.
        Please log in again."
     → redirect to Login
```

### Safety Prompts

| Trigger | Prompt | Type | Blocking |
|---------|--------|------|----------|
| Wrong passphrase | "Incorrect passphrase. Please try again." | Inline error | No — retry |
| Token family revoked | "Session invalidated — possible unauthorized access detected. Log in again to secure your identity." | Warning dialog | Yes — must re-login |
| Server unreachable | "Cannot reach the identity server. Check your connection." | Toast notification | No — retry button |

### Component Composition

```
LoginPage
  ├─ IdentityBadge (shows DID fragment, tier)
  ├─ PassphraseInput
  ├─ ShardEntryForm (if user shard needed)
  │   └─ Input (hex paste field)
  ├─ Spinner (during challenge-response)
  └─ ActionBar (Login, Switch Identity, Recover)
```

---

## 4  Flow: Machine Enrollment / Revocation

### Enroll

```
[Machines Page → Enroll New Machine]
  1. Prompt for passphrase (to reconstruct Neural Key)
  2. Derive new machine keypair
  3. Sign canonical enrollment message with ISK
  4. POST /v1/identity/machines → MachineKey record
  5. Zeroize secrets
  6. Refresh machine list
```

### Revoke

```
[Machines Page → Revoke]
  1. Select machine from list
  2. ConfirmDialog:
     ⚠ "Revoke machine '{machine_id}'?
        This device will immediately lose access. This cannot be undone."
     [Cancel] [Revoke]
  3. DELETE /v1/identity/machines/{id}
  4. Refresh machine list
  5. Toast: "Machine revoked successfully."
```

### Safety Prompts

| Trigger | Prompt | Type | Blocking |
|---------|--------|------|----------|
| Revoke current machine | "You are about to revoke THIS machine. You will be logged out immediately." | Danger dialog | Yes — confirm or cancel |
| Revoke last machine | "This is your only enrolled machine. Revoking it will require recovery to regain access." | Critical warning | Yes — type machine_id to confirm |
| Enroll while frozen | "Your identity is frozen. Machine enrollment is not available." | Error banner | Yes — cannot proceed |

### Component Composition

```
MachinesPage
  ├─ PageHeader ("Machines", enroll button)
  ├─ MachineListPanel
  │   └─ MachineCard × N
  │       ├─ Badge (key scheme: Classical / PQ-Hybrid)
  │       ├─ DataField (machine_id, capabilities, epoch)
  │       ├─ DataField (created_at)
  │       └─ RevokeButton
  ├─ EnrollMachineDialog (modal)
  │   ├─ PassphraseInput
  │   ├─ Spinner
  │   └─ ActionBar (Cancel, Enroll)
  └─ ConfirmDialog (revoke confirmation)
```

---

## 5  Flow: Credential Linking

### Link Email

```
[Linked Identities → Add Email]
  1. Input: email address
  2. Input: password (with strength indicator)
  3. POST /v1/credentials/email
  4. Success toast, refresh list
```

### Link OAuth

```
[Linked Identities → Add OAuth → Select Provider]
  1. GET /v1/oauth/{provider}/initiate → auth_url
  2. Open system browser with auth_url
  3. Wait for callback (localhost redirect or deep link)
  4. POST /v1/oauth/callback with code + state
  5. Success toast, refresh list
```

### Link Wallet

```
[Linked Identities → Add Wallet]
  1. GET /v1/auth/challenge → nonce
  2. Prompt: "Sign this challenge with your wallet"
  3. Input: paste signature (hex)
  4. POST /v1/credentials/wallet
  5. Success toast, refresh list
```

### Revoke Credential

```
[Linked Identities → Revoke]
  1. ConfirmDialog:
     ⚠ "Remove {method_type} credential '{method_id}'?
        You will no longer be able to log in with this method."
  2. DELETE /v1/credentials/{type}/{id}
  3. Refresh list
```

### Safety Prompts

| Trigger | Prompt | Type | Blocking |
|---------|--------|------|----------|
| Revoke primary method | "This is your primary authentication method. Set another method as primary first." | Error dialog | Yes — cannot proceed |
| Revoke last method | "This is your only linked credential. Removing it will leave only machine key auth." | Warning dialog | Yes — confirm |
| OAuth browser handoff | "You will be redirected to {provider} in your browser. Return here after authorization." | Info banner | No |

### Component Composition

```
LinkedIdentitiesPage
  ├─ PageHeader ("Linked Identities", add button)
  ├─ CredentialList
  │   └─ CredentialLinkCard × N
  │       ├─ Badge (method_type)
  │       ├─ DataField (method_id, verified, primary)
  │       ├─ SetPrimaryButton (if not primary)
  │       └─ RevokeButton
  ├─ AddCredentialDialog (modal, tabbed: Email | OAuth | Wallet)
  └─ ConfirmDialog (revoke confirmation)
```

---

## 6  Flow: MFA Setup / Management

### Setup + Enable

```
[MFA Page → Setup MFA]
  1. POST /v1/mfa/setup → secret (Base32), QR URL, backup codes
  2. Display QR code (rendered from URL)
  3. Display backup codes in grid
  4. ⚠ "Save these backup codes securely. They will NOT be shown again."
  5. Checkbox: "I have saved my backup codes"
  6. Input: enter current TOTP code to verify
  7. POST /v1/mfa/enable → MFA active
```

### Disable

```
[MFA Page → Disable MFA]
  1. ConfirmDialog:
     ⚠ "Disable multi-factor authentication?
        Your account will be less secure without MFA."
  2. Input: current TOTP code or backup code
  3. POST /v1/mfa/disable
  4. Success toast
```

### Component Composition

```
MfaPage
  ├─ MfaStatusBadge (Enabled / Disabled)
  ├─ SetupMfaPanel (if disabled)
  │   ├─ QrCodeDisplay
  │   ├─ BackupCodeGrid (10 codes)
  │   ├─ AcknowledgeCheckbox
  │   ├─ TotpInput (6-digit)
  │   └─ ActionBar (Cancel, Enable)
  └─ DisableMfaPanel (if enabled)
      ├─ TotpInput
      └─ ActionBar (Cancel, Disable)
```

---

## 7  Flow: Recovery Ceremony

### Steps

```
[Onboarding → Recover Identity]
  1. ⚠ "Identity recovery requires at least 3 of your 5 recovery shards.
       This will revoke all existing machines and create a new one."
  2. Input: paste ≥3 shard hex values (ShardEntryForm)
  3. Validate: exactly 3+ parseable hex shards
    │
    ▼
[Reconstruct & Recover]
  1. Combine shards → Neural Key (background task)
  2. Derive ISK + new machine keypair
  3. POST /v1/identity/recovery → new machine record
  4. Zeroize old key material
    │
    ▼
[Re-Shard]
  1. New 3-of-5 split
  2. Prompt for new passphrase (shard 2 encryption)
  3. Display new shards 3–5
  4. ⚠ "Your OLD shards are now invalid. Store these NEW shards securely."
  5. Acknowledge checkbox
    │
    ▼
[Dashboard]
  Recovery complete, new session active.
```

### Safety Prompts

| Trigger | Prompt | Type | Blocking |
|---------|--------|------|----------|
| Start recovery | "Recovery will revoke ALL existing machines and sessions. Only proceed if you have lost access to your device." | Danger dialog | Yes — confirm |
| Invalid shards | "Could not reconstruct key. Verify your shards are correct and you have at least 3." | Error dialog | Yes — retry |
| Old shard warning | "Your previous recovery shards are now invalid. Store these new shards immediately." | Warning banner | Yes — acknowledge |
| Recovery server error | "Recovery failed: {error}. Your shards remain valid — try again." | Error dialog | Yes — retry |

### Component Composition

```
RecoverIdentityPage
  ├─ ProgressStepper (steps: Enter Shards → Recovering → New Backup → Done)
  ├─ ShardEntryForm
  │   ├─ ShardInput × 3..5 (hex paste fields with validation indicator)
  │   └─ AddShardButton (up to 5)
  ├─ PassphraseInput (for new shard 2)
  ├─ ShardDisplay (new shards 3–5)
  │   ├─ ShardCard × 3
  │   └─ AcknowledgeCheckbox
  └─ ActionBar (Cancel, Recover)
```

---

## 8  Flow: Freeze / Unfreeze (Advanced)

### Freeze

```
[Security → Freeze Identity]
  1. ConfirmDialog:
     ⚠ "Freezing your identity will immediately block all authentication.
        Active sessions will expire naturally but cannot be refreshed.
        Unfreezing requires approval from multiple machines."
     Input: select freeze reason (SecurityIncident | SuspiciousActivity | UserRequested)
     [Cancel] [Freeze Now]
  2. POST /v1/identity/freeze
  3. UI transitions to frozen state (red banner on all pages)
```

### Unfreeze

```
[Security → Unfreeze Identity]
  1. Info: "Unfreezing requires signatures from ≥2 enrolled machines."
  2. Collect approvals (each machine signs with MPK)
  3. POST /v1/identity/unfreeze with approvals array
  4. Success → frozen banner removed
```

---

## 9  Guardrails for Destructive / High-Risk Operations

| Operation | Risk Level | Required Confirmation |
|-----------|-----------|----------------------|
| Revoke machine | High | ConfirmDialog with machine_id display |
| Revoke current machine | Critical | ConfirmDialog + explicit "I understand" |
| Revoke last machine | Critical | ConfirmDialog + type machine_id to confirm |
| Remove credential | Medium | ConfirmDialog |
| Remove primary credential | Blocked | Error — must change primary first |
| Remove last credential | High | ConfirmDialog with warning |
| Disable MFA | Medium | ConfirmDialog + TOTP verification |
| Freeze identity | High | ConfirmDialog with reason selection |
| Unfreeze identity | High | Multi-machine approval ceremony |
| Neural Key rotation | Critical | Multi-machine approval ceremony |
| Identity recovery | Critical | Danger dialog + shard verification |
| Session revocation | Low | Single-click with toast undo (5 s) |

---

## 10  Component Inventory

### Core Primitives (reusable across all pages)

| Component | Purpose |
|-----------|---------|
| `Button` | Primary, secondary, danger, ghost variants with loading state |
| `Input` | Text, password (masked), hex paste; with validation state |
| `Modal` | Centered overlay with title, body, actions; Escape to close |
| `Toast` | Success, error, warning, info notifications; auto-dismiss |
| `Badge` | Status/type labels (tier, key scheme, role, method type) |
| `DataTable` | Sortable, filterable rows with column definitions |
| `DataField` | Label + value pair for detail views |
| `ConfirmDialog` | Modal with warning icon, message, Cancel + Confirm buttons |
| `ProgressStepper` | Horizontal step indicator (numbered, active/complete states) |
| `Spinner` | Loading indicator for async operations |
| `StrengthBar` | Password/passphrase strength meter |
| `QrCodeDisplay` | Renders QR code from URL string |
| `AcknowledgeCheckbox` | Checkbox that gates a Continue button |

### Domain Components (feature-specific)

| Component | Feature | Purpose |
|-----------|---------|---------|
| `IdentityBadge` | Identity | DID fragment, tier, status indicator |
| `MachineCard` | Machines | Single machine with details and actions |
| `MachineListPanel` | Machines | Scrollable list of MachineCards |
| `CredentialLinkCard` | Credentials | Single linked credential with actions |
| `SessionCard` | Sessions | Session details with revoke action |
| `ShardCard` | Neural Key | Single shard hex display with copy |
| `ShardEntryForm` | Recovery | Multi-field shard input with validation |
| `ShardDisplay` | Backup | Shard cards + acknowledge checkbox |
| `PassphraseInput` | Auth/Backup | Masked input with strength bar and confirm |
| `TotpInput` | MFA | 6-digit code input with auto-submit |
| `BackupCodeGrid` | MFA | Grid display of 10 backup codes |
| `MfaStatusBadge` | MFA | Enabled/Disabled indicator |
| `NamespaceSelector` | Namespaces | Dropdown for active namespace switching |
| `FrozenBanner` | Security | Red warning bar shown when identity is frozen |
| `PageHeader` | Layout | Page title with primary action button |
| `Sidebar` | Layout | Navigation links with active state |
| `ActionBar` | Layout | Bottom-anchored button row (Cancel + Primary) |
