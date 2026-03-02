# Post-Quantum Cryptography Implementation

This document describes zid's post-quantum cryptography (PQC) implementation, which provides protection against both classical and quantum computing threats using NIST-standardized algorithms.

## Compliance Summary

**zid implements NIST FIPS 203 and FIPS 204 post-quantum cryptographic standards:**

| Standard | Algorithm | Usage | Security Level |
|----------|-----------|-------|----------------|
| FIPS 203 | ML-KEM-768 | Key encapsulation | NIST Level 3 (128-bit PQ) |
| FIPS 204 | ML-DSA-65 | Digital signatures | NIST Level 3 (128-bit PQ) |

The implementation uses a **PQ-Hybrid approach**, combining classical algorithms (Ed25519, X25519) with post-quantum algorithms (ML-DSA-65, ML-KEM-768). This provides defense-in-depth: security is maintained if either the classical or post-quantum algorithm remains secure.

## Table of Contents

1. [Quantum Computing Threat Overview](#1-quantum-computing-threat-overview)
2. [Cryptographic Inventory](#2-cryptographic-inventory)
3. [Risk Assessment and Mitigations](#3-risk-assessment-and-mitigations)
4. [NIST Post-Quantum Standards](#4-nist-post-quantum-standards)
5. [Implementation Details](#5-implementation-details)
6. [Integration Considerations](#6-integration-considerations)
7. [References](#7-references)

---

## 1. Quantum Computing Threat Overview

### 1.1 Shor's Algorithm

Shor's algorithm, when run on a sufficiently powerful quantum computer, can solve the following problems in polynomial time:

- **Integer Factorization**: Breaks RSA
- **Discrete Logarithm Problem (DLP)**: Breaks DSA, Diffie-Hellman
- **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: Breaks ECDSA, Ed25519, X25519, ECDH

**Impact on zid**: Ed25519 signatures and X25519 key exchange are vulnerable. A quantum computer with ~2,330 logical qubits could break 256-bit elliptic curve cryptography.

### 1.2 Grover's Algorithm

Grover's algorithm provides a quadratic speedup for unstructured search problems:

- **Symmetric Encryption**: Effective key strength is halved (256-bit → 128-bit post-quantum security)
- **Hash Functions**: Collision resistance is reduced (256-bit → 128-bit post-quantum)

**Impact on zid**: Symmetric primitives remain secure with current key sizes. A 256-bit key (XChaCha20) provides 128-bit post-quantum security, which is considered adequate.

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

## 2. Cryptographic Inventory

Based on analysis of `crates/zid-crypto/src/`, the system uses the following algorithms:

| Algorithm | Usage in zid | Key/Output Size | Quantum Status |
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

## 3. Risk Assessment and Mitigations

### 3.1 Quantum-Vulnerable Components (Mitigated)

#### Ed25519 Signatures (Identity Keys, Machine Keys, JWTs)

**Inherent Risk**: 🔴 **HIGH** (without mitigation)

**Current Status**: 🟢 **MITIGATED** via PQ-Hybrid mode

- **Usage**: Identity signing keys, machine signing keys, JWT signing
- **Threat**: Shor's algorithm completely breaks Ed25519
- **Mitigation**: ML-DSA-65 hybrid signatures provide post-quantum protection
  - All keys use PQ-Hybrid mode: both Ed25519 and ML-DSA-65 signatures are generated
  - Security is maintained if either algorithm remains secure
- **Implementation**: `MlDsaKeyPair` in `crates/zid-crypto/src/keys/pq.rs`

#### X25519 Key Exchange

**Inherent Risk**: 🔴 **HIGH** (without mitigation)

**Current Status**: 🟢 **MITIGATED** via PQ-Hybrid mode

- **Usage**: Machine encryption keys, ECDH key agreement
- **Threat**: Shor's algorithm completely breaks X25519
- **Mitigation**: ML-KEM-768 hybrid key encapsulation provides post-quantum protection
  - All keys use PQ-Hybrid mode: both X25519 and ML-KEM-768 keys are derived
  - Shared secrets can be combined: `HKDF(X25519_DH || ML-KEM_decaps)`
- **Implementation**: `MlKemKeyPair` in `crates/zid-crypto/src/keys/pq.rs`
- **HNDL Protection**: ML-KEM-768 protects against "harvest now, decrypt later" attacks

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

**Recommendation for zid**: ML-KEM-768 (128-bit classical / NIST Level 3)

### 4.2 ML-DSA (FIPS 204) - Digital Signatures

**Replacing**: Ed25519, ECDSA, RSA signatures

| Parameter Set | Security Level | Public Key | Signature |
|--------------|----------------|------------|-----------|
| ML-DSA-44 | NIST Level 2 | 1,312 B | 2,420 B |
| ML-DSA-65 | NIST Level 3 | 1,952 B | 3,309 B |
| ML-DSA-87 | NIST Level 5 | 2,592 B | 4,627 B |

**Recommendation for zid**: ML-DSA-65 (128-bit classical / NIST Level 3)

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

### 4.5 zid NIST Compliance

zid's post-quantum implementation is **fully compliant** with NIST FIPS 203 and FIPS 204 standards:

| Requirement | zid Implementation | Status |
|-------------|-------------------|--------|
| **FIPS 203 (ML-KEM)** | | |
| ML-KEM-768 key generation | `MlKemKeyPair::from_seed()` | ✅ Compliant |
| ML-KEM-768 encapsulation | `MlKemKeyPair::encapsulate()` | ✅ Compliant |
| ML-KEM-768 decapsulation | `MlKemKeyPair::decapsulate()` | ✅ Compliant |
| Deterministic key generation | Seed-based via HKDF | ✅ Compliant |
| **FIPS 204 (ML-DSA)** | | |
| ML-DSA-65 key generation | `MlDsaKeyPair::from_seed()` | ✅ Compliant |
| ML-DSA-65 signing | `MlDsaKeyPair::sign()` | ✅ Compliant |
| ML-DSA-65 verification | `MlDsaKeyPair::verify()` | ✅ Compliant |
| Deterministic signing | `MlDsaKeyPair::sign_deterministic()` | ✅ Compliant |
| **Security Level** | | |
| NIST Level 3 (128-bit PQ security) | ML-KEM-768 + ML-DSA-65 | ✅ Achieved |

**Implementation Notes**:

1. **Library**: zid uses the `fips203` and `fips204` Rust crates, which provide NIST-compliant implementations
2. **Determinism**: All key derivation is deterministic from the Neural Key via HKDF with domain separation
3. **Hybrid Mode**: Classical algorithms (Ed25519, X25519) are always present alongside PQ algorithms for defense-in-depth
4. **Always PQ-Hybrid**: All keys use PQ-Hybrid cryptography; there is no classical-only mode

---

## 5. Implementation Details

### 5.1 Hybrid Mode (Implemented)

zid implements hybrid cryptography that combines classical and post-quantum algorithms. Security is maintained if either algorithm remains secure.

#### 5.1.1 Hybrid Signatures (Implemented)

The system supports hybrid Ed25519 + ML-DSA-65 signatures:

```
hybrid_signature = Ed25519_sign(message) || ML-DSA-65_sign(message)
hybrid_verify = Ed25519_verify(sig1) AND ML-DSA-65_verify(sig2)
```

**Implementation**:
- `MlDsaKeyPair::sign()` generates 3,309-byte ML-DSA-65 signatures
- `MlDsaKeyPair::verify()` verifies signatures against public keys
- `MachineKeyPair` provides both `signing_key_pair()` (Ed25519) and `pq_signing_key_pair()` (ML-DSA-65)

**Benefits**:
- Secure against quantum attackers (ML-DSA)
- Secure against potential PQC implementation flaws (Ed25519)
- Backward compatible with systems that only verify Ed25519

#### 5.1.2 Hybrid Key Exchange (Implemented)

The system supports hybrid X25519 + ML-KEM-768 key encapsulation:

```
shared_secret = HKDF(X25519_DH(sk, pk) || ML-KEM_decaps(sk, ct))
```

**Implementation**:
- `MlKemKeyPair::encapsulate()` generates ciphertext and shared secret
- `MlKemKeyPair::decapsulate()` recovers shared secret from ciphertext
- `MachineKeyPair` provides both `encryption_key_pair()` (X25519) and `pq_encryption_key_pair()` (ML-KEM-768)

**Benefits**:
- Forward secrecy against quantum and classical attacks
- Protection against "harvest now, decrypt later" attacks

### 5.2 Algorithm Versioning (Implemented)

Algorithm version fields in key structures support parallel key types:

All machine keys are now PQ-Hybrid, combining classical and post-quantum algorithms:

```rust
pub struct MachineKeyPair {
    /// Ed25519 signing key pair (present for OpenMLS compatibility)
    signing_key: Ed25519SigningKey,
    /// X25519 encryption key pair (present for OpenMLS compatibility)
    encryption_key: X25519KeyPair,
    /// ML-DSA-65 post-quantum signing key pair
    pq_signing_key: MlDsaKeyPair,
    /// ML-KEM-768 post-quantum encryption key pair
    pq_encryption_key: MlKemKeyPair,
    // ...
}
```

#### Key Derivation

PQ-Hybrid keys are derived using `derive_machine_keypair()`:

```rust
let keypair = derive_machine_keypair(
    &neural_key,
    &identity_id,
    &machine_id,
    epoch,
    MachineKeyCapabilities::FULL_DEVICE,
)?;
```

### 5.3 Future Phases

#### Phase 2: PQ-Hybrid Mandatory (Current)

PQ-Hybrid is now the only key scheme. All machine keys include both classical and post-quantum key material:

1. **Classical-only keys removed**: All machines use PQ-Hybrid keys
2. **PQC required for all identities**: All identity creation and machine enrollment uses PQ-Hybrid keys
3. **No scheme selection**: The `KeyScheme` enum has been removed; PQ-Hybrid is always used

#### Phase 3: Full PQC Migration (Future)

Once ecosystem support matures and classical algorithms are no longer needed for backward compatibility:

1. **Drop classical keys**: Remove Ed25519/X25519 keys to reduce storage
2. **PQC-only signatures**: Use ML-DSA-65 signatures exclusively

#### Implementation Timeline

| Milestone | Status |
|-----------|--------|
| NIST standards finalized (2024) | ✅ Complete |
| PQ-Hybrid key derivation | ✅ Complete |
| ML-DSA-65 signing/verification | ✅ Complete |
| ML-KEM-768 encapsulation/decapsulation | ✅ Complete |
| PQ-Hybrid mandatory (no classical-only) | ✅ Complete |
| Protocol algorithm negotiation | 📋 Pending |
| Storage schema updates | 📋 Pending |
| Full PQC-only migration | 📋 Future |

---

## 6. Integration Considerations

### 6.1 Rust Ecosystem

**Libraries Integrated in zid-crypto**:

| Library | Purpose | Status |
|---------|---------|--------|
| `fips203` | ML-KEM-768 (NIST FIPS 203) | ✅ Production |
| `fips204` | ML-DSA-65 (NIST FIPS 204) | ✅ Production |

These libraries provide NIST-compliant implementations of the standardized post-quantum algorithms.

**zid-crypto Cargo.toml**:

```toml
[dependencies]
# Post-quantum cryptography (NIST FIPS standards)
fips203 = "0.4"  # ML-KEM-768 key encapsulation
fips204 = "0.4"  # ML-DSA-65 digital signatures
```

**Alternative Libraries** (not currently used):

| Library | Purpose | Notes |
|---------|---------|-------|
| `pqcrypto` | Pure Rust PQC implementations | Alternative implementation |
| `oqs-rs` | Bindings to liboqs (Open Quantum Safe) | C library bindings |
| `ml-kem` | RustCrypto ML-KEM implementation | Alternative implementation |
| `ml-dsa` | RustCrypto ML-DSA implementation | Alternative implementation |

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
4. **Key Derivation**: ✅ Domain separation for PQ keys implemented:
   - `cypher:shared:machine:pq-sign:v1` for ML-DSA-65
   - `cypher:shared:machine:pq-kem:v1` for ML-KEM-768

### 6.5 Backward Compatibility

**Strategy**: 
- Classical keys (Ed25519, X25519) remain present in PQ-Hybrid keys for OpenMLS compatibility
- Version all serialized key structures
- Future PQC-only migration will remove classical keys when no longer needed

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

### Implementation Checklist

#### Core Cryptography ✅

| Item | Status | Location |
|------|--------|----------|
| PQ-Hybrid mandatory (no classical-only) | ✅ Complete | `keys/mod.rs` |
| `MlDsaKeyPair` (ML-DSA-65) | ✅ Complete | `keys/pq.rs` |
| `MlKemKeyPair` (ML-KEM-768) | ✅ Complete | `keys/pq.rs` |
| ML-DSA-65 signing | ✅ Complete | `MlDsaKeyPair::sign()` |
| ML-DSA-65 verification | ✅ Complete | `MlDsaKeyPair::verify()` |
| ML-KEM-768 encapsulation | ✅ Complete | `MlKemKeyPair::encapsulate()` |
| ML-KEM-768 decapsulation | ✅ Complete | `MlKemKeyPair::decapsulate()` |
| PQ key derivation functions | ✅ Complete | `derivation/pq.rs` |
| `MachineKeyPair` with PQ support | ✅ Complete | `keys/machine.rs` |
| `derive_machine_keypair_with_scheme()` | ✅ Complete | `derivation/pq.rs` |
| PQ domain separation strings | ✅ Complete | `constants.rs` |
| `fips203`/`fips204` integration | ✅ Complete | `Cargo.toml` |
| PQ-Hybrid always-on (no classical-only mode) | ✅ Complete | - |
| Deterministic key generation | ✅ Complete | `MlDsaKeyPair::from_seed()` |
| Deterministic signing | ✅ Complete | `MlDsaKeyPair::sign_deterministic()` |

#### Integration (Pending)

| Item | Status | Notes |
|------|--------|-------|
| Storage schema updates | 📋 Pending | 60x increase for PQ public keys |
| Protocol algorithm negotiation | 📋 Pending | JWT headers, challenge-response |
| Hybrid signature verification (app-level) | ✅ Complete | Verify both Ed25519 + ML-DSA via `HybridSignature` |
| Migration tooling | 📋 Pending | For existing identities |
| Performance benchmarking | 📋 Pending | Target hardware validation |

### Domain Separation Strings

```rust
// Post-quantum key derivation domains (constants.rs)
DOMAIN_MACHINE_PQ_SIGN = "cypher:shared:machine:pq-sign:v1"   // ML-DSA-65
DOMAIN_MACHINE_PQ_KEM  = "cypher:shared:machine:pq-kem:v1"   // ML-KEM-768
```

### Key Sizes Reference

| Key Type | Classical | PQ-Hybrid |
|----------|-----------|-----------|
| Signing public key | 32 B (Ed25519) | 32 B + 1,952 B (ML-DSA-65) |
| Encryption public key | 32 B (X25519) | 32 B + 1,184 B (ML-KEM-768) |
| Signature | 64 B (Ed25519) | 64 B + 3,309 B (ML-DSA-65) |
| Ciphertext | 32 B (X25519) | 32 B + 1,088 B (ML-KEM-768) |

### Usage

Add `zid-crypto` to your dependencies:

```toml
[dependencies]
zid-crypto = { version = "0.1" }
```

Derive PQ-Hybrid machine keys:

```rust
use zero_id_crypto::{
    derive_machine_keypair,
    MachineKeyCapabilities,
    NeuralKey,
};

// Generate or reconstruct Neural Key
let neural_key = NeuralKey::generate()?;
let identity_id = uuid::Uuid::new_v4();
let machine_id = uuid::Uuid::new_v4();
let epoch = 1u64;

// Derive PQ-Hybrid machine keys
let keypair = derive_machine_keypair(
    &neural_key,
    &identity_id,
    &machine_id,
    epoch,
    MachineKeyCapabilities::FULL_DEVICE,
)?;

// Classical keys (present for OpenMLS compatibility)
let ed25519_pk = keypair.signing_public_key();       // 32 bytes
let x25519_pk = keypair.encryption_public_key();     // 32 bytes

// Post-quantum keys (always present)
let pq_sign_pk = keypair.pq_signing_public_key();       // 1,952 bytes (ML-DSA-65, FIPS 204)
let pq_kem_pk = keypair.pq_encryption_public_key();     // 1,184 bytes (ML-KEM-768, FIPS 203)

// Sign with hybrid signature (Ed25519 + ML-DSA-65)
let signature = keypair.sign(b"message")?;  // HybridSignature, 3,373 bytes
```
