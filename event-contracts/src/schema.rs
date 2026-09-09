use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSchema {
    pub event_type: String,
    pub current_version: u32,
    pub minimum_version: u32,
    pub description: String,
    pub required_fields: Vec<String>,
    pub optional_fields: Vec<String>,
    pub deprecated: bool,
    pub deprecation_message: Option<String>,
}

pub struct SchemaRegistry {
    schemas: Arc<RwLock<HashMap<String, EventSchema>>>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        let registry = Self {
            schemas: Arc::new(RwLock::new(HashMap::new())),
        };
        registry.register_defaults();
        registry
    }

    fn register_defaults(&self) {
        let default_schemas = vec![
            EventSchema {
                event_type: "governance.score.computed".into(),
                current_version: 1,
                minimum_version: 1,
                description: "Governance score computation result".into(),
                required_fields: vec![
                    "tenant_id".into(),
                    "framework_id".into(),
                    "overall_score".into(),
                ],
                optional_fields: vec!["control_count".into(), "compliant_count".into()],
                deprecated: false,
                deprecation_message: None,
            },
            EventSchema {
                event_type: "compliance.evidence.ingested".into(),
                current_version: 1,
                minimum_version: 1,
                description: "Evidence ingestion event".into(),
                required_fields: vec![
                    "tenant_id".into(),
                    "evidence_id".into(),
                    "control_id".into(),
                ],
                optional_fields: vec![],
                deprecated: false,
                deprecation_message: None,
            },
            EventSchema {
                event_type: "risk.calculated".into(),
                current_version: 1,
                minimum_version: 1,
                description: "Risk calculation result".into(),
                required_fields: vec!["tenant_id".into(), "risk_id".into(), "risk_score".into()],
                optional_fields: vec![],
                deprecated: false,
                deprecation_message: None,
            },
            EventSchema {
                event_type: "trust.score.computed".into(),
                current_version: 1,
                minimum_version: 1,
                description: "Trust score computation".into(),
                required_fields: vec!["tenant_id".into(), "overall_score".into()],
                optional_fields: vec![],
                deprecated: false,
                deprecation_message: None,
            },
            EventSchema {
                event_type: "identity.user.authenticated".into(),
                current_version: 1,
                minimum_version: 1,
                description: "User authentication event".into(),
                required_fields: vec!["tenant_id".into(), "user_id".into(), "auth_method".into()],
                optional_fields: vec![],
                deprecated: false,
                deprecation_message: None,
            },
            EventSchema {
                event_type: "audit.event.recorded".into(),
                current_version: 1,
                minimum_version: 1,
                description: "Audit event record".into(),
                required_fields: vec![
                    "tenant_id".into(),
                    "event_id".into(),
                    "event_type".into(),
                    "actor_id".into(),
                    "action".into(),
                ],
                optional_fields: vec![],
                deprecated: false,
                deprecation_message: None,
            },
        ];

        let mut schemas = self.schemas.blocking_write();
        for schema in default_schemas {
            schemas.insert(schema.event_type.clone(), schema);
        }
    }

    pub async fn register(&self, schema: EventSchema) -> Result<()> {
        let mut schemas = self.schemas.write().await;
        schemas.insert(schema.event_type.clone(), schema);
        Ok(())
    }

    pub async fn get(&self, event_type: &str) -> Result<EventSchema> {
        let schemas = self.schemas.read().await;
        schemas
            .get(event_type)
            .cloned()
            .ok_or_else(|| GrcError::InternalError(format!("Schema not found: {}", event_type)))
    }

    pub async fn validate_event(
        &self,
        event_type: &str,
        event: &serde_json::Value,
        version: u32,
    ) -> Result<()> {
        let schema = self.get(event_type).await?;

        if version < schema.minimum_version {
            return Err(GrcError::ValidationFailed(format!(
                "Event version {} below minimum {}",
                version, schema.minimum_version
            )));
        }

        if schema.deprecated {
            if let Some(ref msg) = schema.deprecation_message {
                tracing::warn!("Deprecated event: {} - {}", event_type, msg);
            }
        }

        for field in &schema.required_fields {
            // Field must exist and must not be null
            let field_valid = event.get(field).map_or(false, |v| !v.is_null());
            if !field_valid {
                return Err(GrcError::ValidationFailed(format!(
                    "Required field '{}' missing or null in {}",
                    field, event_type
                )));
            }
        }

        Ok(())
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}
