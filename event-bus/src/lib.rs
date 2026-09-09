// Event Bus Infrastructure for Trust OS
// Real-time event streaming, publishing, and consumption

use chrono::Utc;
use common::errors::{GrcError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ============================================
// EVENT ENVELOPE
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope<T: Serialize> {
    pub event_id: String,
    pub event_type: String,
    pub event_version: u32,
    pub aggregate_id: String,
    pub tenant_id: String,
    pub occurred_at: chrono::DateTime<Utc>,
    pub published_at: chrono::DateTime<Utc>,
    pub correlation_id: String,
    pub causation_id: String,
    pub signature: String,
    pub data: T,
    pub metadata: std::collections::HashMap<String, String>,
}

impl<T: Serialize> EventEnvelope<T> {
    pub fn new(
        event_type: String,
        aggregate_id: String,
        tenant_id: String,
        correlation_id: String,
        data: T,
    ) -> Self {
        let now = Utc::now();

        Self {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            event_version: 1,
            aggregate_id,
            tenant_id,
            occurred_at: now,
            published_at: now,
            correlation_id,
            causation_id: Uuid::new_v4().to_string(),
            signature: String::new(),
            data,
            metadata: Default::default(),
        }
    }
}

// ============================================
// EVENT PUBLISHER
// ============================================

pub struct EventPublisher {
    signing_key: Option<SigningKey>,
    producer_config: ProducerConfig,
}

#[derive(Debug, Clone)]
pub struct ProducerConfig {
    pub brokers: String,
    pub topic_prefix: String,
    pub compression_type: String,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            brokers: "localhost:9092".into(),
            topic_prefix: "grc".into(),
            compression_type: "snappy".into(),
        }
    }
}

impl EventPublisher {
    pub fn new(config: ProducerConfig, signing_key: Option<SigningKey>) -> Self {
        Self {
            signing_key,
            producer_config: config,
        }
    }

    /// Publish a single event
    pub async fn publish<T: Serialize>(&self, mut envelope: EventEnvelope<T>) -> Result<String> {
        // Sign event if signing key available
        if let Some(ref key) = self.signing_key {
            let payload = serde_json::to_vec(&envelope)
                .map_err(|e| GrcError::EventPublishingFailed(format!("Serialization: {}", e)))?;

            let signature = key.sign(&payload);
            envelope.signature = hex::encode(signature.to_bytes());
        }

        // In production, this would publish to Kafka/Redpanda
        // For now, return the event ID indicating success
        Ok(envelope.event_id)
    }

    /// Publish batch of events
    pub async fn publish_batch<T: Serialize>(
        &self,
        events: Vec<EventEnvelope<T>>,
    ) -> Result<usize> {
        // In production, use batch producer
        Ok(events.len())
    }

    /// Get topic name for an event
    pub fn get_topic(&self, tenant_id: &str, event_type: &str) -> String {
        format!(
            "{}.{}.{}",
            self.producer_config.topic_prefix, tenant_id, event_type
        )
    }

    /// Get partition key (ensures ordering per tenant)
    pub fn get_partition_key<'a>(&self, tenant_id: &'a str) -> &'a str {
        tenant_id
    }
}

// ============================================
// EVENT CONSUMER
// ============================================

pub struct EventConsumer {
    #[allow(dead_code)]
    consumer_config: ConsumerConfig,
    verifying_keys: Arc<std::collections::HashMap<String, VerifyingKey>>,
}

#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    pub brokers: String,
    pub group_id: String,
    pub topics: Vec<String>,
    pub auto_commit: bool,
}

impl EventConsumer {
    pub fn new(config: ConsumerConfig) -> Self {
        Self {
            consumer_config: config,
            verifying_keys: Arc::new(std::collections::HashMap::new()),
        }
    }

    /// Add verifying key for signature validation
    pub fn add_verifying_key(&mut self, key_id: String, key: VerifyingKey) {
        Arc::get_mut(&mut self.verifying_keys).map(|m| m.insert(key_id, key));
    }

    /// Verify event signature
    pub fn verify_signature(
        &self,
        event: &serde_json::Value,
        signature_hex: &str,
        key_id: &str,
    ) -> Result<bool> {
        if let Some(key) = self.verifying_keys.get(key_id) {
            let payload = serde_json::to_vec(event)
                .map_err(|e| GrcError::EventConsumptionFailed(format!("Serialization: {}", e)))?;

            let signature_bytes = hex::decode(signature_hex)
                .map_err(|e| GrcError::EventConsumptionFailed(format!("Hex decode: {}", e)))?;

            let signature = Signature::from_bytes(&signature_bytes.try_into().map_err(|_| {
                GrcError::EventConsumptionFailed("Invalid signature length".into())
            })?);

            key.verify(&payload, &signature)
                .map_err(|_| GrcError::EventConsumptionFailed("Signature invalid".into()))
                .map(|_| true)
        } else {
            Err(GrcError::EventConsumptionFailed(format!(
                "Verifying key not found: {}",
                key_id
            )))
        }
    }
}

// ============================================
// DEAD LETTER QUEUE
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterMessage {
    pub original_message: serde_json::Value,
    pub error: String,
    pub error_timestamp: chrono::DateTime<Utc>,
    pub retry_count: u32,
    pub last_exception: String,
}

pub struct DeadLetterQueue {
    messages: Arc<tokio::sync::RwLock<Vec<DeadLetterMessage>>>,
}

impl DeadLetterQueue {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// Send message to DLQ
    pub async fn send(
        &self,
        message: serde_json::Value,
        error: String,
        last_exception: String,
    ) -> Result<()> {
        let dlq_message = DeadLetterMessage {
            original_message: message,
            error,
            error_timestamp: Utc::now(),
            retry_count: 0,
            last_exception,
        };

        let mut msgs = self.messages.write().await;
        msgs.push(dlq_message);

        Ok(())
    }

    /// Get DLQ messages
    pub async fn get_messages(&self, limit: i32) -> Result<Vec<DeadLetterMessage>> {
        let msgs = self.messages.read().await;
        Ok(msgs.iter().take(limit as usize).cloned().collect())
    }

    /// Clear DLQ
    pub async fn clear(&self) -> Result<()> {
        let mut msgs = self.messages.write().await;
        msgs.clear();
        Ok(())
    }
}

// ============================================
// IDEMPOTENCY STORE
// ============================================

pub struct IdempotencyStore {
    processed_ids: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
}

impl IdempotencyStore {
    pub fn new() -> Self {
        Self {
            processed_ids: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Check if event already processed
    pub async fn has_processed(&self, event_id: &str) -> Result<bool> {
        let ids = self.processed_ids.read().await;
        Ok(ids.contains(event_id))
    }

    /// Mark event as processed
    pub async fn mark_processed(&self, event_id: &str) -> Result<()> {
        let mut ids = self.processed_ids.write().await;
        ids.insert(event_id.into());
        Ok(())
    }

    /// Clear processed IDs (periodic cleanup)
    pub async fn clear(&self) -> Result<()> {
        let mut ids = self.processed_ids.write().await;
        ids.clear();
        Ok(())
    }
}

// ============================================
// EVENT TOPIC REGISTRY
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicSchema {
    pub topic_name: String,
    pub event_type: String,
    pub schema_version: u32,
    pub required_fields: Vec<String>,
}

pub struct TopicRegistry {
    schemas: Arc<tokio::sync::RwLock<std::collections::HashMap<String, TopicSchema>>>,
}

impl TopicRegistry {
    pub fn new() -> Self {
        Self {
            schemas: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a topic schema
    pub async fn register_topic(&self, schema: TopicSchema) -> Result<()> {
        let mut schemas = self.schemas.write().await;
        schemas.insert(schema.topic_name.clone(), schema);
        Ok(())
    }

    /// Get topic schema
    pub async fn get_topic_schema(&self, topic_name: &str) -> Result<TopicSchema> {
        let schemas = self.schemas.read().await;
        schemas.get(topic_name).cloned().ok_or_else(|| {
            GrcError::InternalError(format!("Topic schema not found: {}", topic_name))
        })
    }

    /// Validate event against topic schema
    pub async fn validate_event(&self, topic_name: &str, event: &serde_json::Value) -> Result<()> {
        let schema = self.get_topic_schema(topic_name).await?;

        // Validate required fields
        for field in &schema.required_fields {
            if !event.get(field).is_some() {
                return Err(GrcError::ValidationFailed(format!(
                    "Required field missing: {}",
                    field
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_envelope_creation() {
        let data = serde_json::json!({"test": "data"});
        let envelope = EventEnvelope::new(
            "test.event".into(),
            "agg-1".into(),
            "tenant-1".into(),
            "corr-1".into(),
            data,
        );

        assert_eq!(envelope.event_type, "test.event");
        assert_eq!(envelope.tenant_id, "tenant-1");
        assert!(!envelope.event_id.is_empty());
    }

    #[test]
    fn test_producer_config_default() {
        let config = ProducerConfig::default();
        assert_eq!(config.brokers, "localhost:9092");
        assert_eq!(config.topic_prefix, "grc");
    }

    #[tokio::test]
    async fn test_idempotency_store() {
        let store = IdempotencyStore::new();

        assert!(!store.has_processed("id-1").await.unwrap());

        store.mark_processed("id-1").await.unwrap();

        assert!(store.has_processed("id-1").await.unwrap());
    }

    #[tokio::test]
    async fn test_dead_letter_queue() {
        let dlq = DeadLetterQueue::new();

        let msg = serde_json::json!({"event": "test"});
        dlq.send(msg, "Processing failed".into(), "Timeout".into())
            .await
            .unwrap();

        let messages = dlq.get_messages(10).await.unwrap();
        assert_eq!(messages.len(), 1);
    }
}

pub mod consumer;
pub mod publisher;

pub use consumer::*;
pub use publisher::*;
