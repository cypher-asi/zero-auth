//! OPAQUE password-authenticated key exchange.
//!
//! Provides the cipher suite definition and ServerSetup management for
//! the OPAQUE protocol. The server never sees plaintext passwords.

use crate::errors::{CryptoError, Result};
use opaque_ke::CipherSuite;
use serde::{Deserialize, Serialize};

/// Cipher suite for OPAQUE in this system.
///
/// Uses Ristretto255 for the OPRF and key exchange groups,
/// SHA-512 for hashing, and Argon2id as the key stretching function.
pub struct ZeroAuthOpaque;

impl CipherSuite for ZeroAuthOpaque {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

/// Wrapper for the OPAQUE login state persisted between init and finish.
#[derive(Serialize, Deserialize)]
pub struct OpaqueLoginState {
    /// Serialized `ServerLogin` bytes (opaque-ke format)
    pub server_login_bytes: Vec<u8>,
    /// Email used to initiate this login
    pub email: String,
    /// Creation timestamp (for TTL enforcement)
    pub created_at: u64,
}

/// TTL for ephemeral OPAQUE login state (seconds).
pub const OPAQUE_LOGIN_STATE_TTL_SECS: u64 = 60;

/// Type alias for the OPAQUE ServerSetup parameterised over our cipher suite.
pub type OpaqueServerSetup = opaque_ke::ServerSetup<ZeroAuthOpaque>;

/// Generate a new `ServerSetup` from the OS CSPRNG.
pub fn generate_server_setup() -> opaque_ke::ServerSetup<ZeroAuthOpaque> {
    let mut rng = rand::rngs::OsRng;
    opaque_ke::ServerSetup::new(&mut rng)
}

/// Serialize a `ServerSetup` to bytes (opaque-ke format, not serde).
pub fn serialize_server_setup(
    setup: &opaque_ke::ServerSetup<ZeroAuthOpaque>,
) -> Result<Vec<u8>> {
    serde_json::to_vec(setup).map_err(|e| {
        CryptoError::InvalidInput(format!("ServerSetup serialization failed: {e}"))
    })
}

/// Deserialize a `ServerSetup` from bytes.
pub fn deserialize_server_setup(
    bytes: &[u8],
) -> Result<opaque_ke::ServerSetup<ZeroAuthOpaque>> {
    serde_json::from_slice(bytes).map_err(|e| {
        CryptoError::InvalidInput(format!("ServerSetup deserialization failed: {e}"))
    })
}
