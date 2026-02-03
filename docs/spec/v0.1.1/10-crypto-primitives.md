# Cryptographic Primitives Specification v0.1.1

## 1. Overview

This document specifies all cryptographic algorithms, constants, and binary formats used throughout Zero-ID. All implementations MUST conform to these specifications.

---

## 2. Algorithms

### 2.1 Symmetric Encryption

| Property | Value |
|----------|-------|
| Algorithm | XChaCha20-Poly1305 |
| Key size | 256 bits (32 bytes) |
| Nonce size | 192 bits (24 bytes) |
| Tag size | 128 bits (16 bytes) |
| Library | `chacha20poly1305` crate |

XChaCha20-Poly1305 is chosen for:
- Large nonce space (safe with random nonces)
- AEAD (authenticated encryption)
- Constant-time implementation
- No padding required

### 2.2 Asymmetric Signing (Classical)

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 |
| Public key size | 256 bits (32 bytes) |
| Private key size | 256 bits (32 bytes) |
| Signature size | 512 bits (64 bytes) |
| Library | `ed25519-dalek` crate |

Ed25519 is chosen for:
- Fast signing and verification
- Deterministic signatures
- Small key and signature sizes
- Resistance to side-channel attacks

### 2.3 Asymmetric Key Exchange (Classical)

| Property | Value |
|----------|-------|
| Algorithm | X25519 (ECDH) |
| Public key size | 256 bits (32 bytes) |
| Private key size | 256 bits (32 bytes) |
| Shared secret size | 256 bits (32 bytes) |
| Library | `x25519-dalek` crate |

### 2.4 Post-Quantum Signing

| Property | Value |
|----------|-------|
| Algorithm | ML-DSA-65 (NIST FIPS 204) |
| Security level | NIST Level 3 |
| Public key size | 1952 bytes |
| Secret key size | 4032 bytes |
| Signature size | 3309 bytes |
| Seed size | 32 bytes |
| Library | `fips204` crate |

### 2.5 Post-Quantum Key Encapsulation

| Property | Value |
|----------|-------|
| Algorithm | ML-KEM-768 (NIST FIPS 203) |
| Security level | NIST Level 3 |
| Encapsulation key size | 1184 bytes |
| Decapsulation key size | 2400 bytes |
| Ciphertext size | 1088 bytes |
| Shared secret size | 32 bytes |
| Seed size | 64 bytes (d || z) |
| Library | `fips203` crate |

### 2.6 Key Derivation

| Property | Value |
|----------|-------|
| Algorithm | HKDF-SHA256 |
| Input key material | Variable |
| Salt | None (empty) |
| Info | Domain separation string |
| Output | 32 bytes (default) |
| Library | `hkdf` crate |

### 2.7 Password Hashing

| Property | Value |
|----------|-------|
| Algorithm | Argon2id |
| Memory cost | 64 MiB |
| Time cost | 3 iterations |
| Parallelism | 1 |
| Output length | 32 bytes |
| Salt length | 32 bytes |
| Library | `argon2` crate |

### 2.8 Fast Hashing

| Property | Value |
|----------|-------|
| Algorithm | BLAKE3 |
| Output size | 256 bits (32 bytes) |
| Library | `blake3` crate |

### 2.9 Secret Sharing

| Property | Value |
|----------|-------|
| Algorithm | Shamir's Secret Sharing |
| Field | GF(256) |
| Threshold | 3 |
| Total shares | 5 |
| Share size | 33 bytes (1 index + 32 data) |
| Library | `sharks` crate |

---

## 3. Constants

### 3.1 Key Sizes

```rust
pub const NEURAL_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const HKDF_OUTPUT_SIZE: usize = 32;
```

### 3.2 Post-Quantum Sizes

```rust
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;
pub const ML_DSA_65_SEED_SIZE: usize = 32;

pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;
pub const ML_KEM_768_SEED_SIZE: usize = 64;
```

### 3.3 Time Constants

```rust
pub const CHALLENGE_EXPIRY_SECONDS: u64 = 60;
pub const SESSION_TOKEN_EXPIRY_SECONDS: u64 = 900;      // 15 min
pub const REFRESH_TOKEN_EXPIRY_SECONDS: u64 = 2_592_000; // 30 days
pub const APPROVAL_EXPIRY_SECONDS: u64 = 900;           // 15 min
pub const OPERATION_EXPIRY_SECONDS: u64 = 3600;         // 1 hour
```

### 3.4 Shamir Constants

```rust
pub const SHAMIR_THRESHOLD: usize = 3;
pub const SHAMIR_TOTAL_SHARES: usize = 5;
```

### 3.5 MFA Constants

```rust
pub const MFA_BACKUP_CODES_COUNT: usize = 10;
pub const CHALLENGE_NONCE_SIZE: usize = 32;
```

---

## 4. Domain Separation Strings

All domain strings follow the format: `cypher:{service}:{purpose}:v{version}`

| Domain String | Concatenation | Purpose |
|---------------|---------------|---------|
| `cypher:id:identity:v1` | `\|\| identity_id` | Identity Signing Key |
| `cypher:managed:identity:v1` | `\|\| method_type \|\| method_id` | Managed ISK |
| `cypher:shared:machine:v1` | `\|\| identity_id \|\| machine_id \|\| epoch` | Machine seed |
| `cypher:shared:machine:sign:v1` | `\|\| machine_id` | Machine signing key |
| `cypher:shared:machine:encrypt:v1` | `\|\| machine_id` | Machine encryption key |
| `cypher:shared:machine:pq-sign:v1` | `\|\| machine_id` | Machine PQ signing key |
| `cypher:shared:machine:pq-kem:v1` | `\|\| machine_id` | Machine PQ KEM key |
| `cypher:id:jwt:v1` | `\|\| key_epoch` | JWT signing key |
| `cypher:id:mfa-kek:v1` | `\|\| identity_id` | MFA KEK |
| `cypher:id:mfa-totp:v1` | `\|\| identity_id` | MFA TOTP AAD |
| `cypher:share-backup-kek:v1` | `\|\| identity_id` | Shard backup KEK |
| `cypher:share-backup:v1` | `\|\| identity_id \|\| share_index` | Shard backup AAD |

---

## 5. Binary Message Formats

All multi-byte integers use **big-endian** (network byte order).

### 5.1 Identity Creation Authorization (137 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     version (0x01)
1       16    identity_id (UUID bytes)
17      32    identity_signing_public_key (Ed25519)
49      16    first_machine_id (UUID bytes)
65      32    machine_signing_key (Ed25519 public)
97      32    machine_encryption_key (X25519 public)
129     8     created_at (u64 big-endian)
------
Total: 137 bytes
```

### 5.2 Machine Enrollment Authorization (109 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     version (0x01)
1       16    machine_id (UUID bytes)
17      16    namespace_id (UUID bytes)
33      32    signing_public_key (Ed25519)
65      32    encryption_public_key (X25519)
97      4     capabilities (u32 big-endian bitflags)
101     8     created_at (u64 big-endian)
------
Total: 109 bytes
```

### 5.3 Recovery Approval (73 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     version (0x01)
1       16    identity_id (UUID bytes)
17      16    recovery_machine_id (UUID bytes)
33      32    recovery_signing_key (Ed25519 public)
65      8     timestamp (u64 big-endian)
------
Total: 73 bytes
```

### 5.4 Rotation Approval (57 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     version (0x01)
1       16    identity_id (UUID bytes)
17      32    new_identity_signing_public_key (Ed25519)
49      8     timestamp (u64 big-endian)
------
Total: 57 bytes
```

### 5.5 Challenge Canonical Format (130 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     version (0x01)
1       16    challenge_id (UUID bytes)
17      16    entity_id (UUID bytes)
33      1     entity_type (0x01=Machine, 0x02=Wallet, 0x03=Email)
34      16    purpose (zero-padded UTF-8)
50      32    aud (zero-padded UTF-8)
82      8     iat (u64 big-endian)
90      8     exp (u64 big-endian)
98      32    nonce (random bytes)
------
Total: 130 bytes
```

### 5.6 Neural Shard (33 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     index (1-255)
1       32    data (share bytes)
------
Total: 33 bytes

Hex encoding: 66 characters
```

---

## 6. Key Derivation Hierarchy

```
NeuralKey [32 bytes, client-generated]
│
├─ HKDF(NK, "cypher:id:identity:v1" || identity_id)
│  └─ Identity Signing Seed [32 bytes]
│     └─ Ed25519KeyPair (ISK)
│
├─ HKDF(NK, "cypher:shared:machine:v1" || identity_id || machine_id || epoch)
│  └─ Machine Seed [32 bytes]
│     │
│     ├─ HKDF(seed, "cypher:shared:machine:sign:v1" || machine_id)
│     │  └─ Machine Signing Seed [32 bytes]
│     │     └─ Ed25519KeyPair (MPK)
│     │
│     ├─ HKDF(seed, "cypher:shared:machine:encrypt:v1" || machine_id)
│     │  └─ Machine Encryption Seed [32 bytes]
│     │     └─ X25519KeyPair
│     │
│     ├─ HKDF(seed, "cypher:shared:machine:pq-sign:v1" || machine_id)
│     │  └─ PQ Signing Seed [32 bytes]
│     │     └─ MlDsaKeyPair (ML-DSA-65)
│     │
│     └─ HKDF(seed, "cypher:shared:machine:pq-kem:v1" || machine_id)
│        └─ PQ KEM Seed [64 bytes]
│           └─ MlKemKeyPair (ML-KEM-768)
│
└─ HKDF(NK, "cypher:id:mfa-kek:v1" || identity_id)
   └─ MFA KEK [32 bytes]

Service Master Key [32 bytes, server-generated]
│
├─ HKDF(SMK, "cypher:id:jwt:v1" || key_epoch)
│  └─ JWT Signing Seed [32 bytes]
│     └─ Ed25519KeyPair
│
└─ HKDF(SMK, "cypher:managed:identity:v1" || method_type || method_id)
   └─ Managed Identity Signing Seed [32 bytes]
      └─ Ed25519KeyPair (Managed ISK)
```

---

## 7. DID Format

### 7.1 did:key Encoding

Zero-ID uses `did:key` format for Decentralized Identifiers:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
       │ └───────────────────────────────────────────────┘
       │                    multibase-encoded public key
       └── multibase prefix (z = base58btc)
```

### 7.2 Encoding Process

1. Take Ed25519 public key (32 bytes)
2. Prepend multicodec prefix `0xed01` (Ed25519 public key)
3. Encode with multibase base58btc (prefix `z`)
4. Prepend `did:key:`

```rust
fn ed25519_to_did_key(public_key: &[u8; 32]) -> String {
    let mut bytes = vec![0xed, 0x01];  // Multicodec for Ed25519
    bytes.extend_from_slice(public_key);
    let encoded = bs58::encode(&bytes).into_string();
    format!("did:key:z{}", encoded)
}
```

### 7.3 Decoding Process

```rust
fn did_key_to_ed25519(did: &str) -> Result<[u8; 32]> {
    let encoded = did.strip_prefix("did:key:z")
        .ok_or(Error::InvalidFormat)?;
    let bytes = bs58::decode(encoded).into_vec()?;
    if bytes.len() != 34 || bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err(Error::InvalidFormat);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[2..34]);
    Ok(key)
}
```

---

## 8. Capability Bitflags

```rust
pub const AUTHENTICATE: u32     = 0b00000001;  // 0x01
pub const SIGN: u32             = 0b00000010;  // 0x02
pub const ENCRYPT: u32          = 0b00000100;  // 0x04
pub const SVK_UNWRAP: u32       = 0b00001000;  // 0x08
pub const MLS_MESSAGING: u32    = 0b00010000;  // 0x10
pub const VAULT_OPERATIONS: u32 = 0b00100000;  // 0x20

// Presets
pub const FULL_DEVICE: u32     = 0b00111111;  // 0x3F
pub const SERVICE_MACHINE: u32 = 0b00100011;  // 0x23
pub const LIMITED_DEVICE: u32  = 0b00010011;  // 0x13
```

---

## 9. Status Codes

### 9.1 Identity Status

```rust
pub const STATUS_ACTIVE: u8   = 0x01;
pub const STATUS_DISABLED: u8 = 0x02;
pub const STATUS_FROZEN: u8   = 0x03;
pub const STATUS_DELETED: u8  = 0x04;
```

### 9.2 Identity Tier

```rust
pub const TIER_MANAGED: u8       = 0x01;
pub const TIER_SELF_SOVEREIGN: u8 = 0x02;
```

### 9.3 Namespace Role

```rust
pub const ROLE_OWNER: u8  = 0x01;
pub const ROLE_ADMIN: u8  = 0x02;
pub const ROLE_MEMBER: u8 = 0x03;
```

### 9.4 Event Type

```rust
pub const EVENT_MACHINE_REVOKED: u8   = 0x01;
pub const EVENT_SESSION_REVOKED: u8   = 0x02;
pub const EVENT_IDENTITY_FROZEN: u8   = 0x03;
pub const EVENT_IDENTITY_DISABLED: u8 = 0x04;
```

### 9.5 Key Status

```rust
pub const KEY_STATUS_ACTIVE: u8   = 0x01;
pub const KEY_STATUS_ROTATING: u8 = 0x02;
pub const KEY_STATUS_RETIRED: u8  = 0x03;
```

---

## 10. Security Requirements

### 10.1 Random Number Generation

- MUST use cryptographically secure RNG
- Use `getrandom` crate for WASM compatibility
- Browser: `crypto.getRandomValues()`
- Native: OS-provided CSPRNG

### 10.2 Zeroization

- All secret material MUST be zeroized after use
- Use `zeroize` crate with `ZeroizeOnDrop`
- Types requiring zeroization:
  - `NeuralKey`
  - `Ed25519KeyPair.private_key`
  - `X25519KeyPair.private_key`
  - All derived seeds

### 10.3 Constant-Time Operations

- Signature verification MUST be constant-time
- Password comparison MUST be constant-time
- Use `subtle` crate for comparisons

### 10.4 Nonce Uniqueness

- XChaCha20 nonces MUST be unique per key
- 192-bit random nonces provide statistical uniqueness
- Birthday bound: 2^96 encryptions before collision risk
