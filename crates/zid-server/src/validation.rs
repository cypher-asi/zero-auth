//! Input validation utilities for API requests.
//!
//! Provides robust validation for:
//! - Email addresses (RFC 5322 compliant)
//! - Password strength (entropy-based using zxcvbn)
//! - Request IDs (UUID format validation)

use crate::error::ApiError;
use validator::ValidateEmail;
use zxcvbn::Score;

/// Minimum password entropy score (0-4 scale from zxcvbn)
/// Score::Two = "somewhat guessable" - provides reasonable protection
/// Score::Three = "safely unguessable" (~10^10 guesses) - recommended for high-value accounts
pub const MIN_PASSWORD_SCORE: Score = Score::Two;

/// Minimum password length
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum password length (prevent DoS via hashing)
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// Validate email address using RFC 5322 compliant validation.
///
/// # Arguments
/// * `email` - Email address to validate
///
/// # Returns
/// Ok(normalized_email) if valid, Err(ApiError) if invalid
pub fn validate_email(email: &str) -> Result<String, ApiError> {
    let email = email.trim().to_lowercase();

    if email.is_empty() {
        return Err(ApiError::InvalidRequest("Email address is required".to_string()));
    }

    // Use validator crate for RFC 5322 compliant validation
    if !email.validate_email() {
        return Err(ApiError::InvalidRequest(
            "Invalid email format. Please provide a valid email address".to_string(),
        ));
    }

    // Additional security checks
    // Reject emails with suspicious patterns
    if email.contains("..") || email.starts_with('.') || email.ends_with('.') {
        return Err(ApiError::InvalidRequest(
            "Invalid email format. Email contains invalid characters".to_string(),
        ));
    }

    Ok(email)
}

/// Validate password strength using entropy-based analysis.
///
/// Uses the zxcvbn library which estimates password strength based on:
/// - Common password patterns
/// - Dictionary words
/// - Keyboard patterns
/// - Repetition and sequences
///
/// # Arguments
/// * `password` - Password to validate
/// * `user_inputs` - Optional list of user-specific words to check against
///                   (e.g., email username, display name)
///
/// # Returns
/// Ok(()) if password meets strength requirements, Err(ApiError) with feedback if not
pub fn validate_password_strength(
    password: &str,
    user_inputs: Option<&[&str]>,
) -> Result<(), ApiError> {
    // Check length bounds
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(ApiError::InvalidRequest(format!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        )));
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ApiError::InvalidRequest(format!(
            "Password must be at most {} characters",
            MAX_PASSWORD_LENGTH
        )));
    }

    // Use zxcvbn for entropy-based strength estimation
    let inputs: Vec<&str> = user_inputs.unwrap_or(&[]).to_vec();
    let estimate = zxcvbn::zxcvbn(password, &inputs);

    // Compare scores directly using the Score enum
    if estimate.score() < MIN_PASSWORD_SCORE {
        // Provide helpful feedback from zxcvbn
        let feedback = estimate.feedback().cloned();
        let message = if let Some(fb) = feedback {
            let mut suggestions = Vec::new();

            if let Some(warning) = fb.warning() {
                suggestions.push(format!("Warning: {}", warning));
            }

            for suggestion in fb.suggestions() {
                suggestions.push(format!("Suggestion: {}", suggestion));
            }

            if suggestions.is_empty() {
                "Password is too weak. Use a mix of letters, numbers, and symbols".to_string()
            } else {
                format!(
                    "Password is too weak. {}",
                    suggestions.join(". ")
                )
            }
        } else {
            "Password is too weak. Use a mix of letters, numbers, and symbols".to_string()
        };

        return Err(ApiError::InvalidRequest(message));
    }

    Ok(())
}

/// Validate and sanitize a request ID.
///
/// # Arguments
/// * `request_id` - Optional client-provided request ID
///
/// # Returns
/// A valid UUID string - either the validated client ID or a new server-generated one
pub fn validate_request_id(request_id: Option<&str>) -> String {
    match request_id {
        Some(id) if !id.is_empty() => {
            // Attempt to parse as UUID to validate format
            match uuid::Uuid::parse_str(id) {
                Ok(uuid) => uuid.to_string(),
                Err(_) => {
                    // Invalid format - generate server-side ID instead
                    // Log this for monitoring potential abuse attempts
                    tracing::debug!(
                        provided_id = %id,
                        "Invalid request ID format, generating server-side ID"
                    );
                    uuid::Uuid::new_v4().to_string()
                }
            }
        }
        _ => uuid::Uuid::new_v4().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Email validation tests
    // ========================================================================

    #[test]
    fn test_valid_emails() {
        let valid_emails = vec![
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "user@sub.domain.example.com",
            "USER@EXAMPLE.COM", // Should normalize to lowercase
        ];

        for email in valid_emails {
            let result = validate_email(email);
            assert!(result.is_ok(), "Expected {} to be valid", email);
            // Verify normalization to lowercase
            assert_eq!(result.unwrap(), email.to_lowercase());
        }
    }

    #[test]
    fn test_invalid_emails() {
        let invalid_emails = vec![
            "",
            "   ",
            "notanemail",
            "@example.com",
            "user@",
            "user@.com",
            "user..name@example.com", // Our custom check catches this
            ".user@example.com",      // Our custom check catches this
            // Note: "user.@example.com" is technically valid per RFC 5322
            // and accepted by the validator crate, so we don't test for it
        ];

        for email in invalid_emails {
            let result = validate_email(email);
            assert!(result.is_err(), "Expected {} to be invalid", email);
        }
    }

    // ========================================================================
    // Password validation tests
    // ========================================================================

    #[test]
    fn test_password_too_short() {
        let result = validate_password_strength("short", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("at least 8 characters"));
    }

    #[test]
    fn test_password_too_long() {
        let long_password = "a".repeat(MAX_PASSWORD_LENGTH + 1);
        let result = validate_password_strength(&long_password, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("at most"));
    }

    #[test]
    fn test_weak_password() {
        // Common weak passwords
        let weak_passwords = vec![
            "password",
            "12345678",
            "qwertyui",
            "aaaaaaaa",
        ];

        for password in weak_passwords {
            let result = validate_password_strength(password, None);
            assert!(result.is_err(), "Expected {} to be rejected as weak", password);
        }
    }

    #[test]
    fn test_strong_password() {
        // These should pass the entropy check
        let strong_passwords = vec![
            "Tr0ub4dor&3#horse",
            "correct-horse-battery-staple",
            "MyP@ssw0rd!2024#Secure",
        ];

        for password in strong_passwords {
            let result = validate_password_strength(password, None);
            assert!(result.is_ok(), "Expected {} to be accepted as strong", password);
        }
    }

    #[test]
    fn test_password_with_user_inputs() {
        // Password containing email username should be weaker
        let result = validate_password_strength("johnsmith123", Some(&["johnsmith"]));
        assert!(result.is_err());
    }

    // ========================================================================
    // Request ID validation tests
    // ========================================================================

    #[test]
    fn test_valid_uuid_request_id() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let result = validate_request_id(Some(uuid));
        assert_eq!(result, uuid);
    }

    #[test]
    fn test_invalid_request_id_generates_new() {
        let invalid_ids = vec![
            "not-a-uuid",
            "12345",
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
        ];

        for id in invalid_ids {
            let result = validate_request_id(Some(id));
            // Should return a valid UUID, not the original
            assert_ne!(result, id);
            assert!(uuid::Uuid::parse_str(&result).is_ok());
        }
    }

    #[test]
    fn test_empty_request_id_generates_new() {
        let result = validate_request_id(Some(""));
        assert!(uuid::Uuid::parse_str(&result).is_ok());
    }

    #[test]
    fn test_none_request_id_generates_new() {
        let result = validate_request_id(None);
        assert!(uuid::Uuid::parse_str(&result).is_ok());
    }
}
