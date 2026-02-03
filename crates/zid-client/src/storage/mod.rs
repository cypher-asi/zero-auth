/*!
 * Local storage helpers for credentials and sessions
 *
 * # Security Model (2+1 Neural Shard Split)
 *
 * The Neural Key is split into 5 Neural Shards (3-of-5 threshold):
 * - 2 shards are stored encrypted on device (below threshold = cryptographically useless alone)
 * - 3 shards are given to the user
 *
 * To reconstruct the Neural Key:
 * - User provides passphrase (decrypts 2 stored shards)
 * - User provides 1 of their 3 shards
 * - 2 + 1 = 3 shards = threshold met
 *
 * Encryption uses:
 * - Argon2id (m=64MiB, t=3, p=4) to derive a 32-byte KEK from the user's passphrase
 * - XChaCha20-Poly1305 for authenticated encryption of each shard
 */

mod credentials;
mod kek;
mod migration;
mod session;

pub use credentials::{
    has_stored_machine_key, load_and_reconstruct_neural_key, load_credentials,
    load_machine_signing_key, save_credentials_with_shards,
};
pub use migration::{is_legacy_credentials, migrate_legacy_credentials};
pub use session::{
    load_session, prompt_neural_shard, prompt_new_passphrase, prompt_passphrase, save_session,
};

use std::path::PathBuf;

/// Domain separation for Neural Shard encryption
pub(crate) const SHARD_ENCRYPTION_DOMAIN: &[u8] = b"zid:client:neural-shard-encryption:v1";

/// Domain separation for machine signing key encryption
pub(crate) const MACHINE_KEY_ENCRYPTION_DOMAIN: &[u8] = b"zid:client:machine-key-encryption:v1";

pub fn get_credentials_path() -> PathBuf {
    PathBuf::from("./.session/credentials.json")
}

pub fn get_session_path() -> PathBuf {
    PathBuf::from("./.session/session.json")
}
