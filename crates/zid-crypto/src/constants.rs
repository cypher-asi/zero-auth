//! Cryptographic constants and domain separation strings.
//!
//! This module implements the specifications from:
//! `docs/requirements/cryptographic-constants.md`
//!
//! All constants are normative and MUST NOT be changed without updating the spec.

/// Size of Ed25519 public keys in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of Ed25519 signatures in bytes
pub const SIGNATURE_SIZE: usize = 64;

/// Size of XChaCha20-Poly1305 nonces in bytes (192 bits)
pub const NONCE_SIZE: usize = 24;

/// Size of XChaCha20-Poly1305 authentication tags in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Size of salt for Argon2id
pub const ARGON2_SALT_SIZE: usize = 32;

/// Size of random challenge nonces in bytes
pub const CHALLENGE_NONCE_SIZE: usize = 32;

/// Challenge expiry time in seconds (60 seconds)
pub const CHALLENGE_EXPIRY_SECONDS: u64 = 60;

/// Session token expiry time in seconds (15 minutes)
pub const SESSION_TOKEN_EXPIRY_SECONDS: u64 = 900;

/// Refresh token expiry time in seconds (30 days)
pub const REFRESH_TOKEN_EXPIRY_SECONDS: u64 = 2_592_000;

/// Approval ceremony expiry time in seconds (15 minutes)
pub const APPROVAL_EXPIRY_SECONDS: u64 = 900;

/// Operation ceremony expiry time in seconds (1 hour)
pub const OPERATION_EXPIRY_SECONDS: u64 = 3600;

/// Shamir secret sharing threshold (3 of 5)
pub const SHAMIR_THRESHOLD: usize = 3;

/// Shamir secret sharing total shares
pub const SHAMIR_TOTAL_SHARES: usize = 5;

// =============================================================================
// Post-Quantum Public Key Sizes
//
// Used by the server for validating PQ public key lengths on enrollment.
// The `zid` crate handles PQ key generation internally but does not export
// these size constants.
// =============================================================================

/// ML-DSA-65 public key size in bytes (NIST FIPS 204)
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;

/// ML-KEM-768 public key size in bytes (NIST FIPS 203)
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;

/// Number of MFA backup codes
pub const MFA_BACKUP_CODES_COUNT: usize = 10;

// =============================================================================
// Domain Separation Strings (as specified in cryptographic-constants.md § 11)
//
// Key derivation domains for NeuralKey → machine/identity keys (machine seed,
// sign, encrypt, pq-sign, pq-encrypt, identity Ed25519, identity pq-sign) are
// handled internally by the `zid` crate and no longer appear here.
//
// The DOMAIN_IDENTITY_SIGNING constant is retained for the Ed25519-only
// `derive_identity_signing_keypair` wrapper used by server code. It matches
// the domain string that `zid` uses internally for the Ed25519 component.
// =============================================================================

/// Domain separation for Identity Signing Key derivation (Ed25519 component).
///
/// Matches `zid`'s internal domain for the Ed25519 ISK path. Used by
/// [`derive_identity_signing_keypair`](crate::derivation::derive_identity_signing_keypair)
/// which returns a plain Ed25519 keypair for server backward-compatibility.
pub const DOMAIN_IDENTITY_SIGNING: &str = "cypher:id:identity:v1";

/// Domain separation for JWT signing key seed derivation
pub const DOMAIN_JWT_SIGNING: &str = "cypher:id:jwt:v1";

/// Domain separation for MFA KEK derivation
pub const DOMAIN_MFA_KEK: &str = "cypher:id:mfa-kek:v1";

/// Domain separation for MFA TOTP AAD
pub const DOMAIN_MFA_TOTP_AAD: &str = "cypher:id:mfa-totp:v1";

/// Domain separation for recovery share backup KEK
pub const DOMAIN_SHARE_BACKUP_KEK: &str = "cypher:share-backup-kek:v1";

/// Domain separation for recovery share backup AAD
pub const DOMAIN_SHARE_BACKUP_AAD: &str = "cypher:share-backup:v1";

/// Domain separation for managed identity signing key derivation
pub const DOMAIN_MANAGED_IDENTITY: &str = "cypher:managed:identity:v1";

/// Domain separation for Shared Vault Key (SVK) derivation (zero-vault)
pub const DOMAIN_VAULT_SVK: &str = "cypher:vault:svk:v1";

/// Domain separation for Vault Data Encryption Key (VDEK) derivation (zero-vault)
pub const DOMAIN_VAULT_VDEK: &str = "cypher:vault:vdek:v1";

/// Domain separation for signing key client share derivation (zero-vault)
pub const DOMAIN_VAULT_SIGNING: &str = "cypher:vault:signing:v1";

/// Argon2id parameters for password hashing
pub mod argon2_params {
    use argon2::{Params, Version};

    /// Memory cost: 64 MiB
    pub const MEMORY_COST: u32 = 64 * 1024;

    /// Time cost: 3 iterations
    pub const TIME_COST: u32 = 3;

    /// Parallelism: 1 thread
    pub const PARALLELISM: u32 = 1;

    /// Output length: 32 bytes
    pub const OUTPUT_LENGTH: usize = 32;

    /// Get Argon2id parameters
    pub fn get_params() -> Params {
        Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LENGTH))
            .expect("valid Argon2id parameters")
    }

    /// Argon2 version
    pub const VERSION: Version = Version::V0x13;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_correct_sizes() {
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(NONCE_SIZE, 24);
        assert_eq!(TAG_SIZE, 16);
    }

    #[test]
    fn test_domain_strings_follow_spec() {
        let domains = [
            DOMAIN_IDENTITY_SIGNING,
            DOMAIN_JWT_SIGNING,
            DOMAIN_MFA_KEK,
            DOMAIN_MFA_TOTP_AAD,
            DOMAIN_MANAGED_IDENTITY,
            DOMAIN_SHARE_BACKUP_KEK,
            DOMAIN_SHARE_BACKUP_AAD,
            DOMAIN_VAULT_SVK,
            DOMAIN_VAULT_VDEK,
            DOMAIN_VAULT_SIGNING,
        ];
        for d in domains {
            assert!(d.starts_with("cypher:"), "{d} missing cypher: prefix");
            assert!(d.contains(":v1"), "{d} missing :v1 version tag");
        }
    }

    #[test]
    fn test_argon2_params_are_valid() {
        let params = argon2_params::get_params();
        assert!(params.m_cost() > 0);
        assert!(params.t_cost() > 0);
    }
}
