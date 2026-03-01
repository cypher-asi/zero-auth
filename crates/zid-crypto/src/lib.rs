//! # zid-crypto
//!
//! Cryptographic primitives for the zero-auth identity system.
//!
//! PQ-Hybrid key generation and derivation (Ed25519 + ML-DSA-65 signing,
//! X25519 + ML-KEM-768 encryption) are provided by the `zid` crate and
//! re-exported here. This crate adds server-specific functionality:
//! XChaCha20-Poly1305 encryption, Argon2id password hashing, BLAKE3 hashing,
//! Ed25519 signature utilities, managed identity derivation, and JWT/MFA
//! key derivation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod constants;
pub mod derivation;
pub mod encryption;
pub mod errors;
pub mod hashing;
pub mod keys;
pub mod signatures;
pub mod utils;

pub use constants::*;
pub use derivation::*;
pub use encryption::*;
pub use errors::CryptoError;
pub use hashing::*;
pub use keys::*;
pub use signatures::*;
pub use utils::*;

// Re-export zid DID functions
pub use zid::{did_key_to_ed25519, ed25519_to_did_key, verify_did_ed25519};

// Re-export zid Shamir / identity-generation API
pub use zid::{
    ShamirShare, shamir_split, shamir_combine,
    IdentityBundle, IdentityInfo,
    generate_identity, verify_shares,
    sign_with_shares, derive_machine_keypair_from_shares,
};

// Re-export zid KEM types
pub use zid::{SharedSecret, EncapBundle};

// Re-export zid's full hybrid identity derivation (complements the
// Ed25519-only `derive_identity_signing_keypair` wrapper in `derivation`)
pub use zid::derive_identity_signing_key;
