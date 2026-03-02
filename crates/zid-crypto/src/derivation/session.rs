//! Session-related key derivations (JWT).

use crate::{constants::*, errors::*};
use zeroize::Zeroizing;

use super::hkdf_derive_32;

/// Derive JWT signing key seed from service master key
///
/// As specified in cryptographic-constants.md § 9.2
///
/// Formula: jwt_signing_seed = HKDF(service_master_key, "cypher:auth:jwt:v1" || key_epoch)
pub fn derive_jwt_signing_seed(
    service_master_key: &[u8; 32],
    key_epoch: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:auth:jwt:v1" || key_epoch
    let mut info = Vec::with_capacity(DOMAIN_JWT_SIGNING.len() + 8);
    info.extend_from_slice(DOMAIN_JWT_SIGNING.as_bytes());
    info.extend_from_slice(&key_epoch.to_be_bytes());

    let seed = hkdf_derive_32(service_master_key, &info)?;
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_jwt_signing_seed() {
        let service_master_key = [42u8; 32];
        let key_epoch = 1u64;

        let seed = derive_jwt_signing_seed(&service_master_key, key_epoch).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_jwt_seed_different_epochs() {
        let service_master_key = [42u8; 32];

        let seed1 = derive_jwt_signing_seed(&service_master_key, 1).unwrap();
        let seed2 = derive_jwt_signing_seed(&service_master_key, 2).unwrap();

        assert_ne!(*seed1, *seed2);
    }
}
