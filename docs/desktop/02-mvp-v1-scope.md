# Zero-ID Desktop App — Scope & Milestone Tags

This document groups every requirement from the [requirements matrix](01-requirements-matrix.md)
into three delivery milestones: **MVP**, **V1 Parity**, and **Advanced**.

---

## Milestone Definitions

| Milestone | Goal | Exit Criteria |
|-----------|------|---------------|
| **MVP** | Usable self-sovereign identity app — create, login, machine management, shard backup/recovery, session refresh | User can create an identity, log in on a machine, list/revoke machines, back up shards, recover, and maintain a session |
| **V1 Parity** | Feature parity with current platform capabilities — linked identities, MFA, namespaces, all auth methods | All auth methods work, MFA lifecycle complete, credential linking/revocation, namespace visibility |
| **Advanced** | Security ceremonies and operational features — freeze/unfreeze, key rotation, PQ visibility, audit views | Multi-approval ceremonies succeed, PQ key details visible, local audit log available |

---

## MVP Scope (`required_for_parity`)

### Identity Core
| Req | Description |
|-----|-------------|
| ID-01 | Create self-sovereign identity (Neural Key → ISK → machine → server) |
| ID-02 | View identity details (DID, tier, status, timestamps) |
| ID-06 | Display identity tier with capability labels |

### Neural Key
| Req | Description |
|-----|-------------|
| NK-01 | Generate Neural Key (32-byte CSPRNG, zeroize after use) |
| NK-02 | Split into 3-of-5 Shamir shards (2 device, 3 user custody) |
| NK-03 | Passphrase-protect shard 2 (Argon2id → KEK → XChaCha20-Poly1305) |
| NK-04 | Reconstruct from any 3 shards for login |

### Machines
| Req | Description |
|-----|-------------|
| MC-01 | Enroll a new machine |
| MC-02 | List all enrolled machines |
| MC-03 | Revoke a machine |

### Authentication & Sessions
| Req | Description |
|-----|-------------|
| AU-01 | Machine key challenge-response login |
| AU-05 | Automatic transparent token refresh |
| AU-06 | Token introspection |
| AU-07 | Session revocation (logout) |

### Recovery
| Req | Description |
|-----|-------------|
| RC-01 | Shard-based identity recovery (≥3 shards) |
| RC-02 | Re-shard and re-encrypt after recovery |

### Non-Functional
| Req | Description |
|-----|-------------|
| NF-01 | No plaintext root key on disk |
| NF-02 | Zeroize all secret material after use |
| NF-05 | User-friendly error messages for all API errors |
| NF-06 | Crypto operations off UI thread (tokio background tasks) |
| NF-07 | Single native binary, no web runtime |
| NF-08 | Restrictive credential file permissions |
| NF-09 | Rate limit handling (429 + Retry-After) |
| NF-10 | Automatic access token refresh |

**Total MVP requirements: 22**

---

## V1 Parity Scope (`optional_for_v1`)

### Identity
| Req | Description |
|-----|-------------|
| ID-03 | Disable/enable identity (admin) |
| ID-04 | Freeze identity (security incident) |

### Machines
| Req | Description |
|-----|-------------|
| MC-04 | Display classical vs PQ-hybrid key scheme per machine |

### Linked Identities
| Req | Description |
|-----|-------------|
| LI-01 | Link email credential |
| LI-02 | Link OAuth provider (Google, X, Epic) |
| LI-03 | Link wallet (EVM/Solana) |
| LI-04 | List all linked credentials |
| LI-05 | Revoke a linked credential |
| LI-06 | Set primary credential |

### Authentication
| Req | Description |
|-----|-------------|
| AU-02 | Email/password login |
| AU-03 | OAuth login |
| AU-04 | Wallet signature login |

### MFA
| Req | Description |
|-----|-------------|
| MF-01 | TOTP setup with QR code |
| MF-02 | Enable MFA with initial verification |
| MF-03 | Disable MFA |
| MF-04 | MFA verification during login |

### Namespaces
| Req | Description |
|-----|-------------|
| NS-01 | View namespace membership |
| NS-02 | Switch active namespace context |
| NS-03 | Create/deactivate namespace (owner) |
| NS-04 | Manage namespace members (admin) |

### Non-Functional
| Req | Description |
|-----|-------------|
| NF-03 | Local audit logging |
| NF-04 | Graceful offline degradation |

**Total V1 requirements: 21**

---

## Advanced Scope (`advanced`)

### Ceremonies
| Req | Description |
|-----|-------------|
| ID-05 | Multi-machine unfreeze ceremony (≥2 approvals) |
| NK-05 | Neural Key rotation ceremony (≥2 approvals) |
| RC-03 | Multi-approval unfreeze participation |
| RC-04 | Key rotation participation |

**Total Advanced requirements: 4**

---

## Scope Summary

| Milestone | Functional | Non-Functional | Total |
|-----------|-----------|---------------|-------|
| MVP | 14 | 8 | 22 |
| V1 Parity | 19 | 2 | 21 |
| Advanced | 4 | 0 | 4 |
| **Grand Total** | **37** | **10** | **47** |

---

## Dependency Graph (Build Order)

```
MVP Phase 1 — Foundation
  NK-01, NK-02, NK-03          (Neural Key generation + shard split)
  ID-01                         (Identity creation, depends on NK)
  MC-01                         (Machine enrollment, depends on ID-01)
  NF-01, NF-02, NF-07, NF-08  (Security + platform non-functionals)

MVP Phase 2 — Auth & Session
  AU-01                         (Machine key login, depends on MC-01)
  AU-05, AU-06, AU-07          (Token lifecycle, depends on AU-01)
  NF-06, NF-09, NF-10          (Async crypto, rate limits, auto-refresh)

MVP Phase 3 — Management & Recovery
  MC-02, MC-03                  (Machine list/revoke)
  ID-02, ID-06                  (Identity display)
  NK-04                         (Reconstruct for login)
  RC-01, RC-02                  (Recovery flow)
  NF-05                         (Error messages)

V1 Phase 1 — Credentials
  LI-01..LI-06                  (Email, OAuth, wallet linking)
  AU-02, AU-03, AU-04          (Alternative login methods)

V1 Phase 2 — MFA & Admin
  MF-01..MF-04                  (Full MFA lifecycle)
  ID-03, ID-04                  (Disable/freeze)
  MC-04                         (PQ key visibility)

V1 Phase 3 — Namespaces
  NS-01..NS-04                  (Namespace management)
  NF-03, NF-04                  (Audit, offline)

Advanced
  ID-05, NK-05, RC-03, RC-04   (Ceremonies, depend on multi-machine quorum)
```
