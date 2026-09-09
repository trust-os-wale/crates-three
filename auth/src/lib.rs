// Authentication and authorization module for Trust OS

use chrono::{Duration, Utc};
use common::{
    errors::{GrcError, Result},
    traits::TokenClaims,
    utils,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use totp_rs::{Secret, TOTP};
use uuid::Uuid;

// ============================================
// JWT TOKEN STRUCTURES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // subject (user_id)
    pub tenant_id: String,
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub iat: i64,    // issued at
    pub exp: i64,    // expiration
    pub nbf: i64,    // not before
    pub jti: String, // JWT ID (for revocation)
}

impl JwtClaims {
    pub fn new(
        user_id: String,
        tenant_id: String,
        username: String,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
        expires_in_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(expires_in_seconds);

        Self {
            sub: user_id.clone(),
            tenant_id,
            user_id,
            username,
            email,
            roles,
            permissions,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
        }
    }
}

impl From<JwtClaims> for TokenClaims {
    fn from(jwt: JwtClaims) -> Self {
        TokenClaims {
            user_id: jwt.user_id,
            tenant_id: jwt.tenant_id,
            roles: jwt.roles,
            permissions: jwt.permissions,
            exp: jwt.exp,
        }
    }
}

// ============================================
// TOKEN MANAGER
// ============================================

pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_expiry: i64,
    refresh_token_expiry: i64,
    revocation_list: Arc<TokenRevocationList>,
}

impl TokenManager {
    pub fn new(secret: &str, access_expiry: i64, refresh_expiry: i64) -> Result<Self> {
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        Ok(Self {
            encoding_key,
            decoding_key,
            access_token_expiry: access_expiry,
            refresh_token_expiry: refresh_expiry,
            revocation_list: Arc::new(TokenRevocationList::new()),
        })
    }

    /// Get a reference to the token revocation list
    pub fn revocation_list(&self) -> &Arc<TokenRevocationList> {
        &self.revocation_list
    }

    /// Revoke a token by its JTI
    pub fn revoke_token(&self, jti: &str) {
        self.revocation_list.revoke(jti.to_string());
    }

    /// Check if a token is revoked
    pub fn is_token_revoked(&self, jti: &str) -> bool {
        self.revocation_list.is_revoked(jti)
    }

    /// Create an access token
    pub fn create_access_token(
        &self,
        user_id: String,
        tenant_id: String,
        username: String,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<String> {
        let claims = JwtClaims::new(
            user_id,
            tenant_id,
            username,
            email,
            roles,
            permissions,
            self.access_token_expiry,
        );

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| GrcError::CryptoError(format!("Token creation failed: {}", e)))
    }

    /// Create a refresh token
    pub fn create_refresh_token(&self, user_id: String, tenant_id: String) -> Result<String> {
        let claims = JwtClaims::new(
            user_id,
            tenant_id,
            "refresh".into(),
            None,
            vec![],
            vec![],
            self.refresh_token_expiry,
        );

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| GrcError::CryptoError(format!("Refresh token creation failed: {}", e)))
    }

    /// Verify and decode a token
    pub fn verify_token(&self, token: &str) -> Result<JwtClaims> {
        // SECURITY: Pin algorithm to HS256 to prevent algorithm confusion attacks
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = false; // We don't use audience claim

        let claims = decode::<JwtClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => GrcError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    GrcError::InvalidToken("Invalid token format".into())
                }
                _ => GrcError::InvalidToken(format!("Token verification failed: {}", e)),
            })
            .map(|data| data.claims)?;

        // Check if token has been revoked
        if self.revocation_list.is_revoked(&claims.jti) {
            return Err(GrcError::InvalidToken("Token has been revoked".into()));
        }

        Ok(claims)
    }

    pub fn access_token_expiry(&self) -> i64 {
        self.access_token_expiry
    }

    pub fn refresh_token_expiry(&self) -> i64 {
        self.refresh_token_expiry
    }

    #[cfg(test)]
    /// Extract user ID from token without verification (TESTING ONLY!)
    /// WARNING: This bypasses all security checks. Never use in production.
    pub fn extract_unverified_claims(&self, token: &str) -> Result<JwtClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(GrcError::InvalidToken("Invalid token format".into()));
        }

        let payload = base64_decode(parts[1])?;
        serde_json::from_slice::<JwtClaims>(&payload)
            .map_err(|e| GrcError::InvalidToken(format!("Failed to parse claims: {}", e)))
    }
}

// ============================================
// TOKEN REVOCATION LIST
// ============================================

/// In-memory token revocation list for immediate token invalidation
/// Uses JTI (JWT ID) to track revoked tokens
pub struct TokenRevocationList {
    revoked_jtis: RwLock<HashSet<String>>,
}

impl TokenRevocationList {
    pub fn new() -> Self {
        Self {
            revoked_jtis: RwLock::new(HashSet::new()),
        }
    }

    /// Check if a token has been revoked
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked_jtis
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(jti)
    }

    /// Revoke a token by its JTI
    pub fn revoke(&self, jti: String) {
        self.revoked_jtis
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(jti);
    }

    /// Get the number of revoked tokens (for monitoring)
    pub fn revocation_count(&self) -> usize {
        self.revoked_jtis
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Clean up expired revoked tokens (should be called periodically)
    /// In production, this should be based on token expiry time
    pub fn cleanup(&self, max_revocations: usize) {
        let mut revoked = self.revoked_jtis.write().unwrap_or_else(|e| e.into_inner());
        if revoked.len() > max_revocations {
            // Remove oldest entries (simplified - in production, track expiry times)
            let to_remove: Vec<_> = revoked
                .iter()
                .take(revoked.len() - max_revocations)
                .cloned()
                .collect();
            for jti in to_remove {
                revoked.remove(&jti);
            }
        }
    }
}

impl Default for TokenRevocationList {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================
// MFA/TOTP MANAGER
// ============================================

pub struct MfaManager;

impl MfaManager {
    /// Generate a new TOTP secret
    pub fn generate_secret() -> Result<String> {
        let secret = Secret::generate_secret();
        Ok(secret.to_string())
    }

    /// Get TOTP QR code URL for setup
    pub fn get_totp_uri(secret: &str, email: &str, issuer: &str) -> Result<String> {
        let secret = Secret::Raw(secret.as_bytes().to_vec());
        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| GrcError::CryptoError(format!("Secret conversion failed: {}", e)))?,
            Some(issuer.to_string()),
            email.to_string(),
        )
        .map_err(|e| GrcError::CryptoError(format!("TOTP setup failed: {}", e)))?;

        totp.get_qr_base64()
            .map_err(|e| GrcError::CryptoError(format!("QR code generation failed: {}", e)))
    }

    /// Verify a TOTP code
    pub fn verify_totp(secret: &str, code: &str) -> Result<bool> {
        let secret = Secret::Raw(secret.as_bytes().to_vec());
        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| GrcError::CryptoError(format!("Secret conversion failed: {}", e)))?,
            None,
            "".to_string(),
        )
        .map_err(|e| GrcError::CryptoError(format!("TOTP verification setup failed: {}", e)))?;

        Ok(totp
            .check_current(code)
            .map_err(|_| GrcError::MfaVerificationFailed)
            .unwrap_or(false))
    }
}

// ============================================
// AUTH SERVICE
// ============================================

pub struct AuthService {
    token_manager: Arc<TokenManager>,
}

impl AuthService {
    pub fn new(token_manager: Arc<TokenManager>) -> Self {
        Self { token_manager }
    }

    /// Authenticate user with credentials
    pub async fn authenticate(
        &self,
        _username: &str,
        password: &str,
        stored_password_hash: &str,
    ) -> Result<(String, String)> {
        // Verify password
        let password_valid = utils::verify_password(password, stored_password_hash)?;
        if !password_valid {
            return Err(GrcError::AuthenticationFailed("Invalid credentials".into()));
        }

        // For full implementation, would load user from database
        // This is a stub that should be implemented with actual user lookup
        Err(GrcError::NotImplemented(
            "Full auth service requires database integration".into(),
        ))
    }

    /// Verify if a token is valid
    pub async fn verify_token(&self, token: &str) -> Result<TokenClaims> {
        let jwt_claims = self.token_manager.verify_token(token)?;
        Ok(jwt_claims.into())
    }
}

// ============================================
// HELPER FUNCTIONS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use common::constants::*;

    #[test]
    fn test_jwt_claims_creation() {
        let claims = JwtClaims::new(
            "user-1".into(),
            "tenant-1".into(),
            "testuser".into(),
            Some("test@example.com".into()),
            vec!["admin".into()],
            vec!["read".into(), "write".into()],
            3600,
        );

        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.tenant_id, "tenant-1");
        assert_eq!(claims.roles.len(), 1);
    }

    #[test]
    fn test_token_manager_creation() {
        let manager = TokenManager::new("test-secret", 3600, 86400).unwrap();
        assert_eq!(manager.access_token_expiry, 3600);
    }

    #[test]
    fn test_token_creation_and_verification() {
        let manager = TokenManager::new("test-secret-12345", 3600, 86400).unwrap();

        let token = manager
            .create_access_token(
                "user-1".into(),
                "tenant-1".into(),
                "testuser".into(),
                Some("test@example.com".into()),
                vec!["admin".into()],
                vec!["read".into()],
            )
            .unwrap();

        let claims = manager.verify_token(&token).unwrap();
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.tenant_id, "tenant-1");
    }

    #[test]
    fn test_mfa_secret_generation() {
        let secret = MfaManager::generate_secret().unwrap();
        assert!(!secret.is_empty());
        assert!(secret.len() > 20);
    }

    #[test]
    fn test_mfa_verification() {
        let secret = MfaManager::generate_secret().unwrap();
        // Note: This test is simplified; in reality, you'd need to sync time and get current code
        let result = MfaManager::verify_totp(&secret, "000000");
        // Result may be false, but should not error
        assert!(result.is_ok());
    }
}

pub mod auth;
pub mod identity;

pub use auth::*;
pub use identity::*;
