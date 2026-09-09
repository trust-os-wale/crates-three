use common::errors::{GrcError, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignClaims {
    pub sub: String,
    pub tenant_id: String,
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub auth_method: String,
    pub mfa_verified: bool,
    pub device_id: Option<String>,
    pub session_id: String,
    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,
    pub jti: String,
}

pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_expiry: i64,
    #[allow(dead_code)]
    refresh_expiry: i64,
}

impl TokenManager {
    pub fn new(secret: &str, access_expiry: i64, refresh_expiry: i64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            access_expiry,
            refresh_expiry,
        }
    }

    pub fn create_access_token(
        &self,
        user_id: String,
        tenant_id: String,
        username: String,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
        auth_method: String,
        mfa_verified: bool,
        device_id: Option<String>,
        session_id: String,
    ) -> Result<String> {
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::seconds(self.access_expiry);

        let claims = SovereignClaims {
            sub: user_id.clone(),
            tenant_id,
            user_id,
            username,
            email,
            roles,
            permissions,
            auth_method,
            mfa_verified,
            device_id,
            session_id,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            nbf: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| GrcError::CryptoError(format!("Token creation failed: {}", e)))
    }

    pub fn verify_token(&self, token: &str) -> Result<SovereignClaims> {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_nbf = true;

        decode::<SovereignClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => GrcError::TokenExpired,
                _ => GrcError::InvalidToken(format!("Token verification failed: {}", e)),
            })
            .map(|data| data.claims)
    }
}

pub struct PasswordHasher;

impl PasswordHasher {
    pub fn hash(password: &str) -> Result<String> {
        use argon2::{password_hash::SaltString, Argon2, PasswordHasher as _};
        use rand::rngs::OsRng;

        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| GrcError::CryptoError(format!("Password hashing failed: {}", e)))
            .map(|hash| hash.to_string())
    }

    pub fn verify(password: &str, hash: &str) -> Result<bool> {
        use argon2::{Argon2, PasswordHash, PasswordVerifier};

        let parsed = PasswordHash::new(hash)
            .map_err(|e| GrcError::CryptoError(format!("Invalid hash: {}", e)))?;

        match Argon2::default().verify_password(password.as_bytes(), &parsed) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(GrcError::CryptoError(format!("Verification failed: {}", e))),
        }
    }
}

pub struct SessionHasher;

impl SessionHasher {
    pub fn hash_session(session_id: &str, user_id: &str, tenant_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(b":");
        hasher.update(user_id.as_bytes());
        hasher.update(b":");
        hasher.update(tenant_id.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_flow() {
        let mgr = TokenManager::new("test-secret-12345", 3600, 86400);
        let token = mgr
            .create_access_token(
                "user-1".into(),
                "tenant-1".into(),
                "testuser".into(),
                Some("test@example.com".into()),
                vec!["admin".into()],
                vec!["read".into()],
                "password".into(),
                true,
                None,
                "session-1".into(),
            )
            .unwrap();

        let claims = mgr.verify_token(&token).unwrap();
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.tenant_id, "tenant-1");
        assert!(claims.mfa_verified);
    }
}
