# Cryptographic Mechanisms Comparison

A comprehensive analysis of signature schemes, cryptographic primitives, and encryption strategies across blockchain platforms (Bitcoin, Ethereum, Solana) and messaging applications (Signal, Telegram).

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Signature Schemes](#signature-schemes)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Architecture and Design Philosophy](#architecture-and-design-philosophy)
5. [Security Properties](#security-properties)
6. [Performance Metrics](#performance-metrics)
7. [Post-Quantum Readiness](#post-quantum-readiness)
8. [References](#references)

---

## Executive Summary

This document compares cryptographic mechanisms across two fundamentally different domains:

**Blockchain Platforms** (Bitcoin, Ethereum, Solana) prioritize:
- Transaction integrity and non-repudiation
- Public verifiability of all operations
- Deterministic key derivation for wallet recovery
- Resistance to double-spending attacks

**Messaging Platforms** (Signal, Telegram) prioritize:
- Confidentiality of message contents
- Forward secrecy (past messages stay secure if keys are compromised)
- Post-compromise security (sessions can recover after temporary compromise)
- Deniability of communications

### Key Differentiators

| Aspect | Blockchain | Messaging |
|--------|------------|-----------|
| Primary Goal | Public verification | Private communication |
| Data Model | Permanent, immutable ledger | Ephemeral messages |
| Key Lifetime | Long-lived (years) | Short-lived (per-message/session) |
| Encryption | Rarely used (public data) | Always used (E2EE) |
| Forward Secrecy | Not applicable | Critical requirement |

---

## Signature Schemes

### Overview Comparison

| Platform | Primary Scheme | Curve/Parameters | Signature Size | Public Key Size | Private Key Size |
|----------|---------------|------------------|----------------|-----------------|------------------|
| Bitcoin | ECDSA + Schnorr | secp256k1 | 70-72B (ECDSA), 64B (Schnorr) | 33B (compressed) | 32B |
| Ethereum | ECDSA + BLS | secp256k1, BLS12-381 | 65B (ECDSA), 48B (BLS) | 64B (uncompressed) | 32B |
| Solana | Ed25519 | Curve25519 | 64B | 32B | 32B |
| Signal | Ed25519 + X25519 | Curve25519 | 64B | 32B | 32B |
| Telegram | RSA-2048 + DH | 2048-bit modulus | 256B | 256B | 256B |

### Bitcoin: ECDSA and Schnorr on secp256k1

Bitcoin uses the **secp256k1** elliptic curve defined by the equation:

```
y² = x³ + 7 (mod p)
```

where p = 2²⁵⁶ - 2³² - 977

#### ECDSA (Legacy)

- **Standard**: Implicit in Bitcoin protocol since 2009
- **Signature Format**: DER-encoded (r, s) values, 70-72 bytes variable
- **Security Level**: ~128-bit equivalent
- **Characteristics**:
  - Requires secure random nonce (k) for each signature
  - Nonce reuse leads to private key recovery (fatal vulnerability)
  - Signatures are malleable (third parties can modify valid signatures)

#### Schnorr Signatures (BIP-340, since 2021)

- **Standard**: BIP-340 (activated in Taproot upgrade)
- **Signature Format**: Fixed 64 bytes (32B R-point + 32B s-value)
- **Improvements over ECDSA**:
  - **Linearity**: Enables native multi-signatures (MuSig2) and threshold signatures
  - **Non-malleable**: Signatures cannot be modified by third parties
  - **Batch verification**: Multiple signatures can be verified faster together
  - **Provable security**: Reduces to discrete logarithm problem under random oracle model

```
Signature = (R, s) where:
  R = k·G (nonce point)
  s = k + e·x (mod n)
  e = H(R || P || m) (challenge)
```

### Ethereum: ECDSA and BLS Signatures

#### Execution Layer (ECDSA)

Ethereum uses ECDSA on secp256k1, identical to Bitcoin's curve, but with key differences:

- **Address Derivation**: Keccak-256 hash of public key, truncated to 20 bytes
- **Signature Components**: (r, s, v) where v is the recovery identifier (27 or 28, or EIP-155 chain ID encoded)
- **Recovery Feature**: Public key can be recovered from signature + message, eliminating need to transmit public key

```
Address = Keccak256(PublicKey)[12:32]
```

#### Consensus Layer (BLS12-381)

Ethereum's Proof-of-Stake consensus uses **BLS signatures** for validator attestations:

- **Curve**: BLS12-381 (Barreto-Lynn-Scott curve with embedding degree 12)
- **Signature Size**: 48 bytes (compressed G1 point)
- **Public Key Size**: 48 bytes (compressed G1 point)
- **Key Feature**: **Signature aggregation** - unlimited signatures combine into single 48-byte signature

```
AggregateSignature = σ₁ + σ₂ + ... + σₙ (point addition)
Verification: e(AggSig, G2) = e(H(m), Σ PKᵢ)
```

**Scaling Impact**: With 500,000+ validators, BLS aggregation reduces attestation data from ~32MB to under 100KB per slot.

### Solana: Ed25519

Solana exclusively uses **Ed25519** (Edwards-curve Digital Signature Algorithm):

- **Standard**: RFC 8032
- **Curve**: Twisted Edwards curve equivalent to Curve25519
- **Signature Size**: 64 bytes (fixed)
- **Public Key Size**: 32 bytes
- **Characteristics**:
  - **Deterministic**: No random nonce required (derived from private key + message)
  - **Fast**: Optimized for high-throughput verification
  - **Safe by default**: Resistant to implementation errors

```
Signature = (R, S) where:
  R = r·B (nonce point, r = H(prefix || m))
  S = r + H(R || A || m)·a (mod l)
```

**Implementation Note**: Solana uses a native program for Ed25519 verification, consuming significantly fewer compute units than in-contract implementations.

### Signal: Curve25519 Family

Signal uses the Curve25519 family for different purposes:

| Purpose | Algorithm | Key Type |
|---------|-----------|----------|
| Identity Keys | Ed25519 | Long-term signing |
| Signed Prekeys | Ed25519 | Medium-term signing |
| Key Agreement | X25519 | Ephemeral DH exchange |

The distinction between Ed25519 (signing) and X25519 (key exchange) stems from different curve representations optimized for each operation.

### Telegram: RSA + Diffie-Hellman

Telegram's MTProto 2.0 uses legacy cryptographic primitives:

- **Server Authentication**: RSA-2048 signatures
- **Key Exchange**: 2048-bit Diffie-Hellman (finite field, not elliptic curve)
- **Signature Size**: 256 bytes (RSA-2048)

This represents significantly larger key material compared to elliptic curve alternatives, with RSA-2048 providing roughly equivalent security to a 112-bit symmetric key (compared to 128-bit for 256-bit ECC).

---

## Cryptographic Primitives

### Hash Functions

| Platform | Primary Hash | Usage | Output Size | Standard |
|----------|-------------|-------|-------------|----------|
| Bitcoin | SHA-256 | Block headers, TXID, addresses | 256 bits | FIPS 180-4 |
| Bitcoin | RIPEMD-160 | Address generation (after SHA-256) | 160 bits | ISO/IEC 10118-3 |
| Bitcoin | SHA-256d | Double SHA-256 for PoW | 256 bits | - |
| Ethereum | Keccak-256 | Addresses, state roots, signatures | 256 bits | Pre-FIPS SHA-3 |
| Solana | SHA-256 | Transaction hashes, Merkle trees | 256 bits | FIPS 180-4 |
| Signal | SHA-256 | HKDF, HMAC | 256 bits | FIPS 180-4 |
| Signal | SHA-512 | Ed25519 internal | 512 bits | FIPS 180-4 |
| Telegram | SHA-256 | MTProto 2.0 key derivation | 256 bits | FIPS 180-4 |

**Note**: Ethereum's Keccak-256 is **not** identical to NIST SHA-3 (SHA3-256). Keccak-256 uses different padding, making them incompatible.

### Key Derivation Functions

#### Bitcoin: BIP-32 Hierarchical Deterministic Wallets

```
Master Key Generation:
  seed = PBKDF2(mnemonic, "mnemonic" + passphrase, 2048, 64)
  (master_key, chain_code) = HMAC-SHA512("Bitcoin seed", seed)

Child Key Derivation:
  For normal child:   HMAC-SHA512(chain_code, public_key || index)
  For hardened child: HMAC-SHA512(chain_code, 0x00 || private_key || index)
```

#### Ethereum: Same as Bitcoin (BIP-32/39/44)

Ethereum wallets use identical derivation with different path:
- Bitcoin: `m/44'/0'/0'/0/0`
- Ethereum: `m/44'/60'/0'/0/0`

#### Signal: HKDF (RFC 5869)

Signal uses HKDF-SHA256 extensively for key derivation:

```
HKDF-Expand(prk, info, length):
  T(0) = empty
  T(i) = HMAC(prk, T(i-1) || info || i)
  return first 'length' bytes of T(1) || T(2) || ...
```

#### Telegram: Custom KDF

MTProto 2.0 derives message keys using a custom construction:

```
msg_key = SHA256(auth_key[88:120] || plaintext)[8:24]
aes_key = SHA256(msg_key || auth_key[x:x+36])[:32]
aes_iv  = SHA256(auth_key[y:y+32] || msg_key)[4:20] || SHA256(msg_key || auth_key[z:z+32])[:12]
```

### Symmetric Encryption

| Platform | Algorithm | Mode | Key Size | Nonce/IV | Tag Size |
|----------|-----------|------|----------|----------|----------|
| Signal | AES-256 | GCM | 256 bits | 96 bits | 128 bits |
| Telegram (cloud) | AES-256 | IGE | 256 bits | 256 bits | N/A (no auth) |
| Telegram (secret) | AES-256 | IGE | 256 bits | 256 bits | N/A (SHA-256 MAC) |

**Critical Difference**: Signal uses authenticated encryption (AES-GCM), while Telegram uses AES-IGE which requires a separate MAC for authentication.

### Password Hashing

| Platform | Algorithm | Memory | Iterations | Purpose |
|----------|-----------|--------|------------|---------|
| Signal | Argon2id | 64 MB | 3 | PIN-derived keys |
| Telegram | - | - | - | No client-side password hashing |

---

## Architecture and Design Philosophy

### Bitcoin: UTXO Model with Script

```
┌─────────────────────────────────────────────────────────────┐
│                    Bitcoin Transaction                       │
├─────────────────────────────────────────────────────────────┤
│  Inputs                          │  Outputs                 │
│  ┌───────────────────────────┐   │  ┌────────────────────┐  │
│  │ Previous TXID + Index     │   │  │ Value (satoshis)   │  │
│  │ ScriptSig (signature)     │   │  │ ScriptPubKey       │  │
│  │ Witness (Segwit sigs)     │   │  │ (locking script)   │  │
│  └───────────────────────────┘   │  └────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Key Properties**:
- Signatures commit to specific transaction outputs
- No encryption (all data is public)
- Deterministic verification by all nodes

### Ethereum: Account Model with EVM

```
┌─────────────────────────────────────────────────────────────┐
│                  Ethereum Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Execution Layer (ECDSA)         Consensus Layer (BLS)     │
│   ┌─────────────────────┐        ┌─────────────────────┐    │
│   │ User Transactions   │        │ Validator Votes     │    │
│   │ - secp256k1         │        │ - BLS12-381         │    │
│   │ - 65-byte sigs      │        │ - 48-byte agg sigs  │    │
│   │ - Keccak-256        │        │ - Slot attestations │    │
│   └─────────────────────┘        └─────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Dual Signature System**:
- Users sign transactions with ECDSA (familiar, compatible with existing wallets)
- Validators sign attestations with BLS (enables aggregation for scalability)

### Solana: Parallel Processing Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Solana Transaction                         │
├─────────────────────────────────────────────────────────────┤
│  Header                                                      │
│  ├── Signature Count                                         │
│  ├── Signatures[] (Ed25519, 64 bytes each)                  │
│  └── Message                                                 │
│      ├── Account Keys[] (32 bytes each)                     │
│      └── Instructions[]                                      │
│          ├── Program ID                                      │
│          ├── Account Indices                                 │
│          └── Data (offset-based for sig verification)       │
└─────────────────────────────────────────────────────────────┘
```

**Design Choices**:
- Ed25519 chosen for deterministic signatures and fast batch verification
- Native signature verification program (not in-contract)
- Transaction size limit: 1,232 bytes (constrains multi-sig operations)

### Signal: Triple Ratchet Protocol (2025)

Signal's current architecture combines three key mechanisms:

```
┌─────────────────────────────────────────────────────────────┐
│                Signal Triple Ratchet                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              PQXDH Initial Handshake                 │    │
│  │  ┌─────────────┐         ┌─────────────────────┐    │    │
│  │  │   X25519    │    +    │    ML-KEM-1024      │    │    │
│  │  │ (classical) │         │  (post-quantum)     │    │    │
│  │  └─────────────┘         └─────────────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Double Ratchet (ongoing)                │    │
│  │  ┌─────────────────┐    ┌─────────────────────┐     │    │
│  │  │  DH Ratchet     │    │  Symmetric Ratchet  │     │    │
│  │  │  (X25519)       │    │  (HKDF chain)       │     │    │
│  │  └─────────────────┘    └─────────────────────┘     │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │         Sparse Post-Quantum Ratchet (SPQR)           │    │
│  │  ML-KEM encapsulation every N messages               │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Operations**:

1. **PQXDH** (Post-Quantum Extended Diffie-Hellman):
   ```
   shared_secret = HKDF(X25519_result || ML-KEM_result)
   ```

2. **Double Ratchet**:
   - DH ratchet: New X25519 keys exchanged with each message round-trip
   - Symmetric ratchet: HKDF chain derives per-message keys

3. **SPQR**: Periodic ML-KEM key encapsulation for post-quantum forward secrecy

### Telegram: MTProto 2.0

```
┌─────────────────────────────────────────────────────────────┐
│                    MTProto 2.0                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Cloud Chats (Default)           Secret Chats (Optional)   │
│   ┌─────────────────────┐        ┌─────────────────────┐    │
│   │ Client ←→ Server    │        │ Client ←→ Client    │    │
│   │ encryption          │        │ E2EE                │    │
│   │                     │        │                     │    │
│   │ Keys on server      │        │ Keys only on devices│    │
│   │ Multi-device sync   │        │ Single device only  │    │
│   │ Cloud backup        │        │ No backup           │    │
│   └─────────────────────┘        └─────────────────────┘    │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │              Key Exchange                            │   │
│   │  1. Server sends RSA-encrypted DH parameters        │   │
│   │  2. Client responds with DH public value            │   │
│   │  3. Shared auth_key (2048-bit) established          │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │              Message Encryption                      │   │
│   │  msg_key = SHA256(auth_key[88:120] || plaintext)    │   │
│   │  aes_key, aes_iv = KDF(auth_key, msg_key)           │   │
│   │  ciphertext = AES-256-IGE(plaintext, aes_key, iv)   │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Critical Limitations**:
- Cloud chats: Server has decryption keys
- Secret chats: Must be manually enabled, no group support
- IGE mode: Requires separate integrity check (not AEAD)

---

## Security Properties

### Comparison Matrix

| Property | Bitcoin | Ethereum | Solana | Signal | Telegram (Cloud) | Telegram (Secret) |
|----------|---------|----------|--------|--------|------------------|-------------------|
| Confidentiality | N/A | N/A | N/A | Yes | Server can read | Yes |
| Integrity | Yes | Yes | Yes | Yes | Yes | Yes |
| Authentication | Yes | Yes | Yes | Yes | Yes | Yes |
| Non-repudiation | Yes | Yes | Yes | Optional | No | No |
| Forward Secrecy | N/A | N/A | N/A | Yes | No | Limited |
| Post-Compromise Security | N/A | N/A | N/A | Yes | No | No |
| Deniability | No | No | No | Yes | No | Partial |

### Forward Secrecy Analysis

**Signal**: Achieves forward secrecy through continuous key ratcheting:
- Compromising current keys reveals nothing about past messages
- Each message uses a unique derived key
- DH ratchet ensures even session keys are ephemeral

**Telegram Secret Chats**: Limited forward secrecy:
- Initial DH provides some protection
- No continuous ratcheting within a session
- Rekeying requires explicit user action

**Blockchains**: Forward secrecy is not applicable because:
- All data is intentionally public
- Historical verifiability is a feature, not a bug
- Keys are meant for long-term ownership proof

### Known Vulnerabilities and Mitigations

#### Bitcoin/Ethereum ECDSA

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Nonce reuse | Reusing k in two signatures reveals private key | RFC 6979 deterministic nonces |
| Weak RNG | Poor randomness in k compromises key | Hardware RNG, deterministic derivation |
| Signature malleability | Third parties can modify (r,s) to (r,-s) | Enforce low-S values (BIP-62, EIP-2) |

#### Solana Ed25519

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Offset manipulation | Contract trusts wrong signature data | Explicit structural validation |
| Double public key | Same key used for sign/encrypt | Separate Ed25519/X25519 keys |

#### Signal Protocol

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Key server compromise | Attacker registers fake prekeys | Safety numbers verification |
| Metadata exposure | Server sees who talks to whom | Sealed sender feature |

#### Telegram MTProto 2.0

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Server key access | Cloud chat keys stored on server | Use Secret Chats |
| Timing side channels | AES-IGE timing leaks | Rate limiting (theoretical) |
| Unknown key-share | Rekeying protocol flaw | Protocol updates (2021+) |

---

## Performance Metrics

### Signature Operation Benchmarks

Benchmarks on modern hardware (ARM Cortex-A76, single core):

| Algorithm | Sign (ops/sec) | Verify (ops/sec) | Relative Speed |
|-----------|---------------|------------------|----------------|
| Ed25519 | ~30,775 | ~11,870 | 1.0x (baseline) |
| ECDSA P-256 | ~32,866 | ~10,449 | ~1.1x sign, ~0.9x verify |
| ECDSA secp256k1 | ~28,000 | ~9,500 | ~0.9x sign, ~0.8x verify |
| Schnorr (secp256k1) | ~30,000 | ~11,000 | ~1.0x |
| BLS12-381 | ~1,200 | ~450 | ~0.04x (but aggregates) |
| RSA-2048 | ~900 | ~45,000 | ~0.03x sign, ~3.8x verify |

**Key Observations**:
- Ed25519 and ECDSA are comparable for individual operations
- BLS is slower per-signature but aggregation makes it efficient at scale
- RSA verification is fast but signing is extremely slow

### BLS Aggregation Efficiency

For Ethereum consensus with N validators:

| Validators | Without Aggregation | With BLS Aggregation | Savings |
|------------|--------------------|--------------------|---------|
| 1,000 | 65 KB signatures | 48 bytes | 99.93% |
| 100,000 | 6.5 MB signatures | 48 bytes | 99.9993% |
| 500,000 | 32.5 MB signatures | 48 bytes | 99.99985% |

### Transaction Throughput Impact

| Platform | Signature Scheme | Typical TPS | Signature Overhead |
|----------|-----------------|-------------|-------------------|
| Bitcoin | ECDSA/Schnorr | 7 | ~50% of transaction size |
| Ethereum | ECDSA | 15-30 | ~40% of transaction size |
| Solana | Ed25519 | 65,000 | ~5% due to native verification |

### Message Encryption Overhead

| Platform | Encryption | Key Exchange | Per-Message Overhead |
|----------|------------|--------------|---------------------|
| Signal | AES-256-GCM | PQXDH (~3 KB initial) | ~50 bytes (MAC + headers) |
| Telegram | AES-256-IGE | DH (~512 bytes) | ~32 bytes (msg_key + padding) |

---

## Post-Quantum Readiness

### Threat Model

Quantum computers running **Shor's algorithm** can efficiently solve:
- Integer factorization (breaks RSA)
- Discrete logarithm problem (breaks DH, DSA)
- Elliptic curve discrete logarithm (breaks ECDSA, Ed25519, X25519)

**Grover's algorithm** provides quadratic speedup for:
- Symmetric key search (AES-256 → ~AES-128 security)
- Hash collisions (SHA-256 → ~SHA-128 security)

### Platform Status (as of January 2025)

| Platform | Current Status | Migration Plan | Timeline |
|----------|---------------|----------------|----------|
| **Bitcoin** | Vulnerable (ECDSA/Schnorr) | Research: SPHINCS+, XMSS hash-based signatures | No concrete timeline |
| **Ethereum** | Vulnerable (ECDSA/BLS) | Research: ML-DSA for consensus, account abstraction for users | Long-term research |
| **Solana** | Vulnerable (Ed25519) | Research: NIST PQC standards (ML-DSA, SLH-DSA) | No concrete timeline |
| **Signal** | **Hybrid PQ deployed** | PQXDH + Triple Ratchet with ML-KEM-1024 | Production since 2024 |
| **Telegram** | Vulnerable (RSA/DH) | No announced roadmap | Unknown |

### Signal's Post-Quantum Implementation

Signal is the only platform with deployed post-quantum cryptography:

**PQXDH Protocol**:
```
Classical: X25519 key agreement
    +
Post-Quantum: ML-KEM-1024 (Kyber) encapsulation
    =
Hybrid shared secret (secure if either algorithm holds)
```

**Triple Ratchet Additions**:
- Sparse Post-Quantum Ratchet (SPQR) using Katana (optimized Kyber variant)
- ~37% bandwidth reduction compared to naive ML-KEM integration
- Maintains classical security even if PQ assumptions fail

### NIST Post-Quantum Standards

Standardized algorithms for future blockchain/messaging migration:

| Algorithm | Type | Use Case | Key Size | Signature Size |
|-----------|------|----------|----------|----------------|
| ML-KEM (Kyber) | KEM | Key exchange | 1,568 B (ML-KEM-1024) | N/A |
| ML-DSA (Dilithium) | Signature | Transaction signing | 2,592 B | 4,627 B |
| SLH-DSA (SPHINCS+) | Signature | Hash-based, stateless | 64 B | 49,856 B |

**Challenge for Blockchains**: Post-quantum signatures are 50-100x larger than current ECDSA/Ed25519 signatures, requiring significant protocol changes.

---

## References

### Standards and Specifications

- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)
- **RFC 7748**: Elliptic Curves for Security (X25519, X448)
- **RFC 8439**: ChaCha20 and Poly1305 for IETF Protocols
- **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **RFC 9106**: Argon2 Memory-Hard Function
- **RFC 6238**: TOTP: Time-Based One-Time Password Algorithm
- **FIPS 180-4**: Secure Hash Standard (SHA-2)
- **FIPS 186-5**: Digital Signature Standard (DSS)
- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- **FIPS 204**: Module-Lattice-Based Digital Signature (ML-DSA)

### Bitcoin Improvement Proposals

- **BIP-32**: Hierarchical Deterministic Wallets
- **BIP-39**: Mnemonic code for generating deterministic keys
- **BIP-44**: Multi-Account Hierarchy for Deterministic Wallets
- **BIP-340**: Schnorr Signatures for secp256k1

### Ethereum Specifications

- **Ethereum Yellow Paper**: Formal specification of the Ethereum protocol
- **EIP-2**: Homestead Hard-fork Changes (signature malleability fix)
- **EIP-155**: Simple replay attack protection (chain ID in signatures)
- **Ethereum Consensus Specs**: BLS12-381 signature aggregation

### Protocol Documentation

- **Signal Protocol Specifications**: X3DH, Double Ratchet, PQXDH
- **MTProto 2.0**: Telegram's transport protocol documentation

### Academic Research

- Albrecht et al. (2022): "Four Attacks and a Proof for Telegram" - Journal of Cryptology
- Cohn-Gordon et al. (2020): "A Formal Security Analysis of the Signal Messaging Protocol"
- Stebila & Mosca (2016): "Post-quantum Key Exchange for the Internet" - Selected Areas in Cryptography

### Security Analyses

- Cryptography Engineering Blog (2024): "Is Telegram really an encrypted messaging app?"
- Helius Blog (2025): "What Would Solana Need to Change to Become Quantum Resistant?"
- Cantina Security (2025): "Signature Verification Risks in Solana"
