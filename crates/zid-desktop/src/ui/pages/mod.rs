pub mod onboarding;

mod credentials;
mod dashboard;
mod machines;
mod mfa;
mod namespaces;
mod security;
mod sessions;
mod settings;

pub use credentials::render as render_credentials;
pub use dashboard::render as render_dashboard;
pub use machines::render as render_machines;
pub use mfa::render as render_mfa;
pub use namespaces::render as render_namespaces;
pub use security::render as render_security;
pub use sessions::render as render_sessions;
pub use settings::render as render_settings;
