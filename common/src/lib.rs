// Common library for Trust OS - shared types, errors, and traits

pub mod errors;
pub mod models;
pub mod traits;

// Re-export commonly used items
pub use errors::{GrcError, Result};
#[allow(ambiguous_glob_reexports)]
pub use models::*;
#[allow(ambiguous_glob_reexports)]
pub use traits::*;

pub const VERSION: &str = "6.0.0-SOVEREIGN";
pub const APP_NAME: &str = "Trust OS - Governance Intelligence Platform";

// ============================================
// CONSTANTS
// ============================================

pub mod constants {
    // Default timeouts (in seconds)
    pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;
    pub const DEFAULT_LONG_OPERATION_TIMEOUT: u64 = 300;
    pub const DEFAULT_HEALTH_CHECK_TIMEOUT: u64 = 10;

    // Retry configuration
    pub const DEFAULT_MAX_RETRIES: u32 = 3;
    pub const DEFAULT_RETRY_BACKOFF_MS: u64 = 100;

    // Cache configuration
    pub const DEFAULT_CACHE_TTL_SECONDS: u64 = 3600; // 1 hour
    pub const SHORT_CACHE_TTL_SECONDS: u64 = 60;
    pub const LONG_CACHE_TTL_SECONDS: u64 = 86400; // 24 hours

    // Pagination defaults
    pub const DEFAULT_PAGE_SIZE: i32 = 50;
    pub const MAX_PAGE_SIZE: i32 = 1000;

    // Rate limiting
    pub const DEFAULT_RATE_LIMIT_REQUESTS: i32 = 1000;
    pub const DEFAULT_RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

    // Token expiry (in seconds)
    pub const ACCESS_TOKEN_EXPIRY: i64 = 900; // 15 minutes
    pub const REFRESH_TOKEN_EXPIRY: i64 = 604800; // 7 days
    pub const MFA_TOKEN_EXPIRY: i64 = 600; // 10 minutes

    // Evidence retention
    pub const DEFAULT_EVIDENCE_RETENTION_DAYS: i32 = 2555; // 7 years

    // Trust score computation interval (in seconds)
    pub const TRUST_SCORE_COMPUTATION_INTERVAL: i64 = 3600; // 1 hour
    pub const TRUST_SCORE_CACHE_TTL: i64 = 1800; // 30 minutes

    // Framework IDs
    pub const FRAMEWORK_ISO_27001: &str = "iso-27001";
    pub const FRAMEWORK_SOC2: &str = "soc2";
    pub const FRAMEWORK_GDPR: &str = "gdpr";
    pub const FRAMEWORK_HIPAA: &str = "hipaa";
    pub const FRAMEWORK_PCI_DSS: &str = "pci-dss";
    pub const FRAMEWORK_NIST: &str = "nist-800-53";
    pub const FRAMEWORK_CIS: &str = "cis-controls";

    // Deployment regions
    pub const REGION_US_EAST: &str = "us-east-1";
    pub const REGION_EU_WEST: &str = "eu-west-1";
    pub const REGION_APAC: &str = "ap-southeast-1";

    // Consensus regions
    pub const CONSENSUS_REGION_NY: &str = "us-east-1";
    pub const CONSENSUS_REGION_LDN: &str = "eu-west-2";
    pub const CONSENSUS_REGION_SG: &str = "ap-southeast-1";

    // Event topics
    pub const TOPIC_EVIDENCE_INGESTED: &str = "grc.evidence.ingested";
    pub const TOPIC_EVIDENCE_VALIDATED: &str = "grc.evidence.validated";
    pub const TOPIC_CONTROL_EVALUATED: &str = "grc.control.evaluated";
    pub const TOPIC_RISK_SCORED: &str = "grc.risk.scored";
    pub const TOPIC_TRUST_COMPUTED: &str = "grc.trust.computed";
    pub const TOPIC_WORKFLOW_TRIGGERED: &str = "grc.workflow.triggered";
    pub const TOPIC_REMEDIATION_CREATED: &str = "grc.remediation.created";
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

pub mod utils {
    use crate::errors::{GrcError, Result};

    /// Generate a correlation ID for request tracing
    pub fn generate_correlation_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Generate a trace ID for distributed tracing
    pub fn generate_trace_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Validate email format
    pub fn validate_email(email: &str) -> Result<()> {
        let email_regex = regex::Regex::new(
            r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        ).map_err(|e| GrcError::InternalError(format!("Regex error: {}", e)))?;

        if email_regex.is_match(email) {
            Ok(())
        } else {
            Err(GrcError::ValidationFailed("Invalid email format".into()))
        }
    }

    /// Validate username format
    pub fn validate_username(username: &str) -> Result<()> {
        if username.len() < 3 {
            return Err(GrcError::ValidationFailed(
                "Username must be at least 3 characters".into(),
            ));
        }

        if username.len() > 64 {
            return Err(GrcError::ValidationFailed(
                "Username must be at most 64 characters".into(),
            ));
        }

        let username_regex = regex::Regex::new(r"^[a-zA-Z0-9._-]+$")
            .map_err(|e| GrcError::InternalError(format!("Regex error: {}", e)))?;

        if username_regex.is_match(username) {
            Ok(())
        } else {
            Err(GrcError::ValidationFailed(
                "Username can only contain alphanumeric characters, dots, dashes, and underscores"
                    .into(),
            ))
        }
    }

    /// Validate password strength
    pub fn validate_password_strength(password: &str) -> Result<()> {
        if password.len() < 12 {
            return Err(GrcError::ValidationFailed(
                "Password must be at least 12 characters".into(),
            ));
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if has_uppercase && has_lowercase && has_digit && has_special {
            Ok(())
        } else {
            Err(GrcError::ValidationFailed(
                "Password must contain uppercase, lowercase, digit, and special characters".into(),
            ))
        }
    }

    /// Hash a password using Argon2
    pub fn hash_password(password: &str) -> Result<String> {
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};
        use rand::rngs::OsRng;

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| GrcError::CryptoError(format!("Password hashing failed: {}", e)))
            .map(|hash| hash.to_string())
    }

    /// Verify a password hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
        use argon2::{Argon2, PasswordHash, PasswordVerifier};

        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| GrcError::CryptoError(format!("Invalid password hash: {}", e)))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(GrcError::CryptoError(format!(
                "Password verification failed: {}",
                e
            ))),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_email_validation() {
            assert!(validate_email("test@example.com").is_ok());
            assert!(validate_email("invalid-email").is_err());
        }

        #[test]
        fn test_username_validation() {
            assert!(validate_username("validuser").is_ok());
            assert!(validate_username("ab").is_err()); // Too short
            assert!(validate_username("user@invalid").is_err()); // Invalid character
        }

        #[test]
        fn test_password_hashing() {
            let password = "SecurePass123!@#";
            let hash = hash_password(password).unwrap();
            assert!(verify_password(password, &hash).unwrap());
            assert!(!verify_password("WrongPassword", &hash).unwrap());
        }

        #[test]
        fn test_correlation_id_generation() {
            let id1 = generate_correlation_id();
            let id2 = generate_correlation_id();
            assert_ne!(id1, id2);
        }
    }
}

// ============================================
// SECURITY UTILITIES
// ============================================

pub mod security {
    /// Sanitize input for safe use in SQL queries (defense in depth)
    /// Note: Always use parameterized queries in production!
    pub fn sanitize_sql_input(input: &str) -> String {
        input
            .replace('\'', "''")
            .replace(';', "")
            .replace("--", "")
            .replace("/*", "")
            .replace("*/", "")
    }

    /// Sanitize HTML entities to prevent XSS attacks
    pub fn sanitize_html(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('/', "&#x2F;")
    }

    /// Validate and truncate input to max length
    pub fn truncate_input(input: &str, max_len: usize) -> &str {
        if input.len() > max_len {
            &input[..max_len]
        } else {
            input
        }
    }

    /// Check if a string contains potential path traversal
    pub fn contains_path_traversal(input: &str) -> bool {
        input.contains("..") || input.contains("~") || input.contains('\\')
    }

    /// Validate that a string is safe to use as a filename
    pub fn is_safe_filename(filename: &str) -> bool {
        !filename.contains('/')
            && !filename.contains('\\')
            && !filename.contains("..")
            && !filename.starts_with('.')
            && !filename.is_empty()
            && filename.len() <= 255
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_sql_sanitization() {
            assert_eq!(
                sanitize_sql_input("'; DROP TABLE users; --"),
                "'' DROP TABLE users "
            );
            assert_eq!(sanitize_sql_input("1' OR '1'='1"), "1'' OR ''1''=''1");
        }

        #[test]
        fn test_html_sanitization() {
            assert_eq!(
                sanitize_html("<script>alert('xss')</script>"),
                "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;"
            );
        }

        #[test]
        fn test_path_traversal_detection() {
            assert!(contains_path_traversal("../../../etc/passwd"));
            assert!(contains_path_traversal("~/home"));
            assert!(!contains_path_traversal("normal/file.txt"));
        }

        #[test]
        fn test_filename_validation() {
            assert!(is_safe_filename("document.pdf"));
            assert!(!is_safe_filename("../etc/passwd"));
            assert!(!is_safe_filename(".hidden"));
            assert!(!is_safe_filename(""));
        }
    }
}

// ============================================
// MIDDLEWARE TYPES
// ============================================

pub mod middleware {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RequestMetadata {
        pub request_id: String,
        pub correlation_id: String,
        pub trace_id: String,
        pub user_agent: String,
        pub ip_address: String,
        pub method: String,
        pub path: String,
        pub query_string: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct ResponseMetadata {
        pub status_code: u16,
        pub duration_ms: u64,
        pub response_size_bytes: usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION, "6.0.0-SOVEREIGN");
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::DEFAULT_PAGE_SIZE, 50);
        assert!(constants::MAX_PAGE_SIZE > constants::DEFAULT_PAGE_SIZE);
    }
}
