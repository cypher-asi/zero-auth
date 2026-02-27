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

// Re-export Challenge types for client use
pub use signatures::{canonicalize_challenge, Challenge, EntityType};

// Re-export managed identity derivation
pub use derivation::derive_managed_identity_signing_keypair;

// Re-export zid DID functions
pub use zid::{did_key_to_ed25519, ed25519_to_did_key};

// Re-export zid Shamir API
pub use zid::{ShamirShare, shamir_split, shamir_combine};
