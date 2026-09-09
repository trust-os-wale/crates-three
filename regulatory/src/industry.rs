//! Industry domain types.

use crate::RecordStatus;
use serde::{Deserialize, Serialize};

/// An industry classification (e.g. financial services, healthcare).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Industry {
    pub id: String,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub status: RecordStatus,
}
