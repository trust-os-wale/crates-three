use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EVENT_TENANT_CREATED: &str = "tenant.created";
pub const EVENT_TENANT_MEMBER_ADDED: &str = "tenant.member_added";
pub const EVENT_TENANT_MEMBER_REMOVED: &str = "tenant.member_removed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCreated {
    pub tenant_id: String,
    pub tenant_name: String,
    pub region: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMemberAdded {
    pub tenant_id: String,
    pub user_id: String,
    pub roles: Vec<String>,
    pub added_by: String,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMemberRemoved {
    pub tenant_id: String,
    pub user_id: String,
    pub removed_by: String,
    pub reason: Option<String>,
    pub removed_at: DateTime<Utc>,
}
