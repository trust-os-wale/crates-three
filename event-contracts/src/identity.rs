use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_USER_AUTHENTICATED: &str = "identity.user.authenticated";
pub const EVENT_USER_REGISTERED: &str = "identity.user.registered";
pub const EVENT_MFA_CHALLENGED: &str = "identity.mfa.challenged";
pub const EVENT_MFA_VERIFIED: &str = "identity.mfa.verified";
pub const EVENT_SESSION_CREATED: &str = "identity.session.created";
pub const EVENT_SESSION_REVOKED: &str = "identity.session.revoked";
pub const EVENT_CREDENTIAL_REGISTERED: &str = "identity.credential.registered";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAuthenticated {
    pub tenant_id: String,
    pub user_id: String,
    pub auth_method: String,
    pub mfa_verified: bool,
    pub device_id: Option<String>,
    pub ip_address: String,
    pub risk_score: f64,
    pub session_id: String,
    pub authenticated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistered {
    pub tenant_id: String,
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub auth_methods: Vec<String>,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenged {
    pub tenant_id: String,
    pub user_id: String,
    pub challenge_type: String,
    pub challenged_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaVerified {
    pub tenant_id: String,
    pub user_id: String,
    pub method: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCreated {
    pub tenant_id: String,
    pub user_id: String,
    pub session_id: String,
    pub device_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRevoked {
    pub tenant_id: String,
    pub user_id: String,
    pub session_id: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRegistered {
    pub tenant_id: String,
    pub user_id: String,
    pub credential_type: String,
    pub credential_id: String,
    pub device_name: String,
    pub registered_at: DateTime<Utc>,
}
