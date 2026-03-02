//! Identity creation API endpoints for managed identities.
//!
//! Email identity creation uses the OPAQUE protocol (2 round-trips):
//!   init → blinded registration request → response
//!   finish → registration upload → identity created + auto-login
//!
//! OAuth and wallet flows are unchanged.

mod handlers;
mod helpers;
mod types;

pub use handlers::{
    complete_oauth_identity, complete_wallet_identity,
    create_email_identity_init, create_email_identity_finish,
    get_tier_status, initiate_oauth_identity, initiate_wallet_identity, upgrade_identity,
};
