# Quantum Computing Risks and Migration Strategy

This document assesses the quantum computing threat landscape for zero-auth's cryptographic primitives and outlines a migration strategy to post-quantum cryptography (PQC).

## Table of Contents

1. [Quantum Computing Threat Overview](#1-quantum-computing-threat-overview)
2. [Current Cryptographic Inventory](#2-current-cryptographic-inventory)
3. [Risk Assessment for zero-auth](#3-risk-assessment-for-zero-auth)
4. [NIST Post-Quantum Standards](#4-nist-post-quantum-standards)
5. [Migration Strategy](#5-migration-strategy)
6. [Implementation Considerations](#6-implementation-considerations)
7. [References](#7-references)

---

## 1. Quantum Computing Threat Overview

### 1.1 Shor's Algorithm

Shor's algorithm, when run on a sufficiently powerful quantum computer, can solve the following problems in polynomial time:

- **Integer Factorization**: Breaks RSA
- **Discrete Logarithm Problem (DLP)**: Breaks DSA, Diffie-Hellman
- **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: Breaks ECDSA, Ed25519, X25519, ECDH

**Impact on zero-auth**: Ed25519 signatures and X25519 key exchange are vulnerable. A quantum computer with ~2,330 logical qubits could break 256-bit elliptic curve cryptography.

### 1.2 Grover's Algorithm

Grover's algorithm provides a quadratic speedup for unstructured search problems:

- **Symmetric Encryption**: Effective key strength is halved (256-bit → 128-bit post-quantum security)
- **Hash Functions**: Collision resistance is reduced (256-bit → 128-bit post-quantum)

**Impact on zero-auth**: Symmetric primitives remain secure with current key sizes. A 256-bit key (XChaCha20) provides 128-bit post-quantum security, which is considered adequate.

### 1.3 Timeline Estimates

Quantum computing timeline predictions vary significantly:

| Source | Estimate for Cryptographically Relevant QC |
|--------|-------------------------------------------|
| NSA/CNSA 2.0 | Planning for 2030s threat |
| NIST | Recommends starting migration now |
| Industry Consensus | 10-20 years (with significant uncertainty) |

**"Harvest Now, Decrypt Later" (HNDL)**: Adversaries may be recording encrypted communications today to decrypt them once quantum computers become available. This is especially relevant for:
- Long-lived secrets (identity keys, master keys)
- Data with long-term confidentiality requirements

---

## 2. Current Cryptographic Inventory

Based on analysis of `crates/zero-auth-crypto/src/`, the system uses the following algorithms:

| Algorithm | Usage in zero-auth | Key/Output Size | Quantum Status |
|-----------|-------------------|-----------------|----------------|
| **XChaCha20-Poly1305** | Symmetric encryption (AEAD) | 256-bit key, 192-bit nonce | ✅ Safe (128-bit PQ security) |
| **Ed25519** | Digital signatures | 32B public key, 64B signature | ⚠️ **Vulnerable** |
| **X25519** | Key exchange (ECDH) | 32B public key | ⚠️ **Vulnerable** |
| **BLAKE3** | Fast hashing, key IDs | 256-bit output | ✅ Safe (128-bit PQ security) |
| **SHA-256** | HKDF construct | 256-bit output | ✅ Safe (128-bit PQ security) |
| **Argon2id** | Password hashing | 64 MiB memory, 3 iterations | ✅ Safe |
| **HKDF-SHA256** | Key derivation | Variable output | ✅ Safe |
| **Shamir Secret Sharing** | Neural Key protection (3-of-5) | 32B secret | ✅ Safe (information-theoretic) |

### Component Mapping

| Component | Algorithms Used | Files |
|-----------|----------------|-------|
| Identity Signing Key | Ed25519 | `keys.rs`, `signatures.rs` |
| Machine Keys (signing) | Ed25519 | `keys.rs`, `derivation.rs` |
| Machine Keys (encryption) | X25519 | `keys.rs`, `derivation.rs` |
| Data Encryption | XChaCha20-Poly1305 | `encryption.rs` |
| Key Derivation | HKDF-SHA256 | `derivation.rs` |
| Password Auth | Argon2id | `hashing.rs` |
| Neural Key Backup | Shamir 3-of-5 | `shamir.rs` |
| Key Identifiers | BLAKE3 | `hashing.rs` |

---

## 3. Risk Assessment for zero-auth

### 3.1 High Risk Components

#### Ed25519 Signatures (Identity Keys, Machine Keys, JWTs)

**Risk Level**: 🔴 **HIGH**

- **Usage**: Identity signing keys, machine signing keys, JWT signing
- **Threat**: Shor's algorithm completely breaks Ed25519
- **Impact**: 
  - Forged identity signatures
  - Unauthorized machine enrollments
  - JWT token forgery
- **HNDL Risk**: Moderate (signatures don't typically need long-term secrecy, but recorded authentication flows could be replayed)

#### X25519 Key Exchange

**Risk Level**: 🔴 **HIGH**

- **Usage**: Machine encryption keys, ECDH key agreement
- **Threat**: Shor's algorithm completely breaks X25519
- **Impact**:
  - Decryption of key exchange sessions
  - Recovery of derived session keys
- **HNDL Risk**: **Critical** - Recorded key exchanges can be decrypted to recover session keys

### 3.2 Low Risk Components

#### XChaCha20-Poly1305 Symmetric Encryption

**Risk Level**: 🟢 **LOW**

- **Current Security**: 256-bit key
- **Post-Quantum Security**: 128-bit (Grover's algorithm)
- **Status**: No changes required; 128-bit security is considered adequate for the foreseeable future

#### Hash Functions (BLAKE3, SHA-256)

**Risk Level**: 🟢 **LOW**

- **Current Security**: 256-bit output
- **Post-Quantum Security**: 128-bit collision resistance
- **Status**: No changes required

#### Argon2id Password Hashing

**Risk Level**: 🟢 **LOW**

- **Status**: Memory-hard functions are not meaningfully affected by known quantum algorithms
- **Note**: The primary attack vector remains password entropy, not cryptographic weakness

#### Shamir Secret Sharing

**Risk Level**: 🟢 **LOW**

- **Status**: Information-theoretically secure
- **Note**: Security does not depend on computational hardness assumptions

---

## 4. NIST Post-Quantum Standards

NIST finalized the first set of post-quantum cryptographic standards in 2024:

### 4.1 ML-KEM (FIPS 203) - Key Encapsulation

**Replacing**: X25519, ECDH, RSA-KEM

| Parameter Set | Security Level | Public Key | Ciphertext | Shared Secret |
|--------------|----------------|------------|------------|---------------|
| ML-KEM-512 | NIST Level 1 | 800 B | 768 B | 32 B |
| ML-KEM-768 | NIST Level 3 | 1,184 B | 1,088 B | 32 B |
| ML-KEM-1024 | NIST Level 5 | 1,568 B | 1,568 B | 32 B |

**Recommendation for zero-auth**: ML-KEM-768 (128-bit classical / NIST Level 3)

### 4.2 ML-DSA (FIPS 204) - Digital Signatures

**Replacing**: Ed25519, ECDSA, RSA signatures

| Parameter Set | Security Level | Public Key | Signature |
|--------------|----------------|------------|-----------|
| ML-DSA-44 | NIST Level 2 | 1,312 B | 2,420 B |
| ML-DSA-65 | NIST Level 3 | 1,952 B | 3,309 B |
| ML-DSA-87 | NIST Level 5 | 2,592 B | 4,627 B |

**Recommendation for zero-auth**: ML-DSA-65 (128-bit classical / NIST Level 3)

### 4.3 SLH-DSA (FIPS 205) - Hash-Based Signatures

**Use Case**: Stateless hash-based signatures as a conservative backup

| Parameter Set | Security Level | Public Key | Signature |
|--------------|----------------|------------|-----------|
| SLH-DSA-128s | NIST Level 1 | 32 B | 7,856 B |
| SLH-DSA-192s | NIST Level 3 | 48 B | 16,224 B |
| SLH-DSA-256s | NIST Level 5 | 64 B | 29,792 B |

**Note**: SLH-DSA has smaller public keys but significantly larger signatures. Consider for scenarios requiring minimal trust assumptions.

### 4.4 Size Comparison

| Algorithm | Public Key | Signature/Ciphertext |
|-----------|------------|---------------------|
| Ed25519 (current) | 32 B | 64 B |
| ML-DSA-65 (PQC) | 1,952 B | 3,309 B |
| X25519 (current) | 32 B | 32 B shared secret |
| ML-KEM-768 (PQC) | 1,184 B | 1,088 B |

**Storage Impact**: Approximately 60x increase in public key sizes for signatures, 37x for key encapsulation.

---

## 5. Migration Strategy

### Phase 1: Hybrid Mode (Recommended Starting Point)

Implement hybrid cryptography that combines classical and post-quantum algorithms. Security is maintained if either algorithm remains secure.

#### 5.1.1 Hybrid Signatures

Combine Ed25519 with ML-DSA:

```
hybrid_signature = Ed25519_sign(message) || ML-DSA-65_sign(message)
hybrid_verify = Ed25519_verify(sig1) AND ML-DSA-65_verify(sig2)
```

**Benefits**:
- Secure against quantum attackers (ML-DSA)
- Secure against potential PQC implementation flaws (Ed25519)
- Backward compatible with systems that only verify Ed25519

#### 5.1.2 Hybrid Key Exchange

Combine X25519 with ML-KEM:

```
shared_secret = HKDF(X25519_DH(sk, pk) || ML-KEM_decaps(sk, ct))
```

**Benefits**:
- Forward secrecy against quantum and classical attacks
- Protection against "harvest now, decrypt later" attacks

### Phase 2: Algorithm Versioning

Add algorithm version fields to key structures to support parallel key types during transition:

```rust
/// Signature algorithm version for key structures
pub enum SignatureAlgorithm {
    /// Version 1: Ed25519 only (current)
    Ed25519 = 1,
    /// Version 2: Hybrid Ed25519 + ML-DSA-65
    Ed25519MlDsa65 = 2,
    /// Version 3: Pure ML-DSA-65 (post-quantum only)
    MlDsa65 = 3,
}

/// Key encapsulation algorithm version
pub enum KemAlgorithm {
    /// Version 1: X25519 only (current)
    X25519 = 1,
    /// Version 2: Hybrid X25519 + ML-KEM-768
    X25519MlKem768 = 2,
    /// Version 3: Pure ML-KEM-768 (post-quantum only)
    MlKem768 = 3,
}

/// Versioned public key structure
pub struct VersionedPublicKey {
    /// Algorithm version
    pub algorithm: SignatureAlgorithm,
    /// Ed25519 public key (32 bytes, present in v1 and v2)
    pub ed25519_pk: Option<[u8; 32]>,
    /// ML-DSA-65 public key (1952 bytes, present in v2 and v3)
    pub ml_dsa_pk: Option<Vec<u8>>,
}
```

#### Key Migration Protocol

1. Generate new PQC key pairs alongside existing classical keys
2. Sign new PQC public keys with existing Ed25519 identity key (chain of trust)
3. Publish both key sets to allow gradual client migration
4. Set deprecation timeline for classical-only authentication

### Phase 3: Full PQC Migration

Once hybrid mode is stable and ecosystem support matures:

1. **Deprecate classical-only keys**: Refuse authentication from Ed25519-only machines
2. **Enforce PQC for new identities**: All new identity creation requires PQC keys
3. **Re-keying ceremony**: Existing identities rotate to PQC-only keys
4. **Remove hybrid overhead**: Optionally drop classical keys to reduce storage

#### Timeline Considerations

| Milestone | Trigger |
|-----------|---------|
| Begin Phase 1 | NIST standards finalized (2024) ✓ |
| Complete Phase 1 | Rust ecosystem libraries mature |
| Begin Phase 2 | Production deployment of hybrid mode |
| Begin Phase 3 | Industry-wide PQC adoption / quantum threat imminent |

---

## 6. Implementation Considerations

### 6.1 Rust Ecosystem

**Recommended Libraries**:

| Library | Purpose | Status |
|---------|---------|--------|
| `pqcrypto` | Pure Rust PQC implementations | Stable |
| `oqs-rs` | Bindings to liboqs (Open Quantum Safe) | Stable |
| `ml-kem` | RustCrypto ML-KEM implementation | In development |
| `ml-dsa` | RustCrypto ML-DSA implementation | In development |

**Example Cargo.toml additions**:

```toml
[dependencies]
# Post-quantum cryptography
pqcrypto-kyber = "0.8"      # ML-KEM (Kyber)
pqcrypto-dilithium = "0.5"  # ML-DSA (Dilithium)
```

### 6.2 Storage Schema Updates

The significant increase in key and signature sizes requires storage planning:

| Field | Current Size | Hybrid Size | PQC-Only Size |
|-------|-------------|-------------|---------------|
| Identity public key | 32 B | ~2 KB | ~2 KB |
| Machine signing key | 32 B | ~2 KB | ~2 KB |
| Machine encryption key | 32 B | ~1.2 KB | ~1.2 KB |
| Signature | 64 B | ~3.4 KB | ~3.3 KB |

**Database Considerations**:
- Increase column sizes for public key and signature fields
- Consider compression for stored keys
- Update bandwidth estimates for API responses

### 6.3 Performance Impact

Expected performance characteristics (approximate):

| Operation | Ed25519 | ML-DSA-65 | Hybrid |
|-----------|---------|-----------|--------|
| Key Generation | ~50 μs | ~150 μs | ~200 μs |
| Sign | ~70 μs | ~300 μs | ~370 μs |
| Verify | ~200 μs | ~350 μs | ~550 μs |

| Operation | X25519 | ML-KEM-768 | Hybrid |
|-----------|--------|------------|--------|
| Key Generation | ~25 μs | ~50 μs | ~75 μs |
| Encapsulate | ~30 μs | ~70 μs | ~100 μs |
| Decapsulate | ~30 μs | ~60 μs | ~90 μs |

**Benchmarking**: Conduct performance testing with representative workloads before deployment.

### 6.4 Protocol Updates

Areas requiring protocol changes:

1. **Challenge-Response Authentication**: Update challenge canonicalization to include algorithm version
2. **JWT Signing**: Support multiple signature algorithms in token headers
3. **Machine Enrollment**: Extend enrollment message format for larger keys
4. **Key Derivation**: Maintain domain separation for PQC key derivation paths

### 6.5 Backward Compatibility

**Strategy**: 
- Maintain support for classical-only clients during transition
- Use algorithm negotiation in protocols
- Version all serialized key structures
- Provide clear deprecation notices and timelines

---

## 7. References

### Standards and Guidance

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

### IETF Drafts

- [Hybrid Key Exchange in TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [Composite Signatures](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- [X25519Kyber768Draft00](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/)

### Libraries

- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- [pqcrypto Rust crate](https://crates.io/crates/pqcrypto)
- [RustCrypto project](https://github.com/RustCrypto)

### Further Reading

- [Quantum Computing and Cryptography (CISA)](https://www.cisa.gov/quantum)
- [Post-Quantum Cryptography: Current state and quantum mitigation (ENISA)](https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation)

---

## Appendix A: Quick Reference

### Completed Actions ✅

1. ✅ Inventory complete - all cryptographic primitives documented
2. ✅ Risk assessment complete - Ed25519 and X25519 identified as vulnerable
3. ✅ **PQ-Hybrid key derivation implemented** (ML-DSA-65 + ML-KEM-768)
4. ✅ KeyScheme enum added (Classical, PqHybrid)
5. ✅ Domain separation strings for PQ keys
6. ✅ **Always-available implementation** (no feature flag required)

### Remaining Actions

1. Update storage layer for larger key sizes
2. Add algorithm negotiation to authentication protocol
3. Create migration tooling for existing identities
4. Benchmark PQC performance on target hardware

### Implementation Status

| Item | Status |
|------|--------|
| `KeyScheme` enum | ✅ Implemented |
| `MlDsaKeyPair` (ML-DSA-65) | ✅ Implemented |
| `MlKemKeyPair` (ML-KEM-768) | ✅ Implemented |
| PQ key derivation functions | ✅ Implemented |
| `MachineKeyPair` with PQ support | ✅ Implemented |
| `derive_machine_keypair_with_scheme()` | ✅ Implemented |
| PQ domain separation strings | ✅ Implemented |
| Hybrid signature verification | 📋 Pending (app-level) |
| Storage schema updates | 📋 Pending |
| Protocol algorithm negotiation | 📋 Pending |

### Usage

Add `zero-auth-crypto` to your dependencies:

```toml
[dependencies]
zero-auth-crypto = { version = "0.1" }
```

Derive PQ-Hybrid machine keys (always available):

```rust
use zero_auth_crypto::{
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

// Access PQ keys
if let Some(pq_sign_pk) = keypair.pq_signing_public_key() {
    // 1,952-byte ML-DSA-65 public key
}
if let Some(pq_kem_pk) = keypair.pq_encryption_public_key() {
    // 1,184-byte ML-KEM-768 public key
}
```
