use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum AppError {
    // Network
    ServerUnreachable,
    Timeout,
    RateLimited { retry_after: Duration },

    // Auth
    InvalidCredentials,
    SessionExpired,
    TokenFamilyRevoked,
    MfaRequired,
    IdentityFrozen,

    // Validation
    InvalidInput(String),
    ShardCombineFailed,
    PassphraseIncorrect,

    // Server
    ServerError(u16, String),
    NotFound(String),
    Conflict(String),

    // Local
    StorageError(String),
    CryptoError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerUnreachable => write!(f, "Cannot reach the identity server. Check your connection."),
            Self::Timeout => write!(f, "Request timed out. Please try again."),
            Self::RateLimited { retry_after } => write!(f, "Too many requests. Please wait {} seconds.", retry_after.as_secs()),
            Self::InvalidCredentials => write!(f, "Invalid credentials. Please check and try again."),
            Self::SessionExpired => write!(f, "Your session has expired. Please log in again."),
            Self::TokenFamilyRevoked => write!(f, "Session invalidated — possible unauthorized access detected. Log in again to secure your identity."),
            Self::MfaRequired => write!(f, "Multi-factor authentication is required to continue."),
            Self::IdentityFrozen => write!(f, "Your identity is frozen. Authentication is not available until unfreezing is completed."),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            Self::ShardCombineFailed => write!(f, "Could not reconstruct key. Verify your shards are correct and you have at least 3."),
            Self::PassphraseIncorrect => write!(f, "Incorrect passphrase. Please try again."),
            Self::ServerError(code, msg) => write!(f, "Server error ({code}): {msg}"),
            Self::NotFound(resource) => write!(f, "{resource} not found."),
            Self::Conflict(msg) => write!(f, "Conflict: {msg}"),
            Self::StorageError(msg) => write!(f, "Storage error: {msg}"),
            Self::CryptoError(msg) => write!(f, "Cryptographic operation failed: {msg}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            Self::Timeout
        } else if err.is_connect() {
            Self::ServerUnreachable
        } else if let Some(status) = err.status() {
            match status.as_u16() {
                401 => Self::SessionExpired,
                403 => Self::IdentityFrozen,
                404 => Self::NotFound(err.to_string()),
                409 => Self::Conflict(err.to_string()),
                429 => Self::RateLimited {
                    retry_after: Duration::from_secs(30),
                },
                code => Self::ServerError(code, err.to_string()),
            }
        } else {
            Self::ServerUnreachable
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
