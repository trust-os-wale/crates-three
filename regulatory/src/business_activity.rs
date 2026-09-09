//! Business activity domain types.

use crate::RecordStatus;
use serde::{Deserialize, Serialize};

/// A business activity an organization performs (e.g. processing payment
/// card data, providing cloud services, clinical trials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessActivity {
    pub id: String,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub status: RecordStatus,
}
