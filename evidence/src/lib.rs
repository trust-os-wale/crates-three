// Evidence Storage and Validation Module for Trust OS
// Handles evidence ingestion, validation, deduplication, and storage

use chrono::Utc;
use common::{
    errors::{GrcError, Result},
    models::Evidence,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

// ============================================
// EVIDENCE VALIDATOR
// ============================================

#[derive(Debug, Clone)]
pub struct EvidenceValidationConfig {
    pub max_size_bytes: usize,
    pub allowed_types: Vec<String>,
    pub signature_required: bool,
}

impl Default for EvidenceValidationConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 100 * 1024 * 1024, // 100MB
            allowed_types: vec![
                "log".into(),
                "configuration".into(),
                "audit".into(),
                "vulnerability".into(),
                "compliance".into(),
            ],
            signature_required: true,
        }
    }
}

pub struct EvidenceValidator {
    config: EvidenceValidationConfig,
    verifying_key: Option<VerifyingKey>,
}

impl EvidenceValidator {
    pub fn new(config: EvidenceValidationConfig) -> Self {
        Self {
            config,
            verifying_key: None,
        }
    }

    /// Create validator with Ed25519 verifying key for signature verification
    pub fn with_signature_verification(
        config: EvidenceValidationConfig,
        verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            config,
            verifying_key: Some(verifying_key),
        }
    }

    /// Set the verifying key for signature verification
    pub fn set_verifying_key(&mut self, key: VerifyingKey) {
        self.verifying_key = Some(key);
    }

    /// Validate evidence data
    pub fn validate(&self, data: &[u8], evidence_type: &str) -> Result<EvidenceValidationResult> {
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        // Check size
        if data.len() > self.config.max_size_bytes {
            issues.push(format!(
                "Evidence exceeds maximum size: {} bytes",
                self.config.max_size_bytes
            ));
        }

        // Check type
        if !self.config.allowed_types.contains(&evidence_type.into()) {
            issues.push(format!("Unsupported evidence type: {}", evidence_type));
        }

        // Check not empty
        if data.is_empty() {
            issues.push("Evidence data cannot be empty".into());
        }

        // Try to parse as JSON if applicable
        if evidence_type == "configuration" || evidence_type == "audit" {
            if let Err(e) = serde_json::from_slice::<serde_json::Value>(data) {
                warnings.push(format!("Invalid JSON format: {}", e));
            }
        }

        let valid = issues.is_empty();
        let score = if valid { 100.0 } else { 0.0 };

        Ok(EvidenceValidationResult {
            valid,
            score,
            issues,
            warnings,
        })
    }

    /// Verify Ed25519 signature of evidence data
    pub fn verify_signature(&self, data: &[u8], signature_hex: &str) -> Result<bool> {
        let verifying_key = self.verifying_key.as_ref().ok_or_else(|| {
            GrcError::CryptoError("No verifying key configured for signature verification".into())
        })?;

        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| GrcError::CryptoError(format!("Invalid signature hex: {}", e)))?;

        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| GrcError::CryptoError(format!("Invalid signature format: {}", e)))?;

        verifying_key
            .verify(data, &signature)
            .map_err(|e| GrcError::CryptoError(format!("Signature verification failed: {}", e)))?;

        Ok(true)
    }

    /// Compute hash of evidence
    pub fn compute_hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceValidationResult {
    pub valid: bool,
    pub score: f32,
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
}

// ============================================
// EVIDENCE DEDUPLICATION
// ============================================

#[derive(Debug, Clone)]
pub struct EvidenceHashRecord {
    pub hash: String,
    pub first_evidence_id: String,
    pub occurrence_count: i32,
    pub first_seen: chrono::DateTime<Utc>,
    pub last_seen: chrono::DateTime<Utc>,
}

pub struct EvidenceDeduplicator {
    hash_index: Arc<tokio::sync::RwLock<HashMap<String, EvidenceHashRecord>>>,
}

impl EvidenceDeduplicator {
    pub fn new() -> Self {
        Self {
            hash_index: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Check if evidence hash already exists
    pub async fn check_duplicate(&self, hash: &str) -> Result<Option<EvidenceHashRecord>> {
        let index = self.hash_index.read().await;
        Ok(index.get(hash).cloned())
    }

    /// Record evidence hash
    pub async fn record_hash(&self, hash: String, evidence_id: String) -> Result<()> {
        let mut index = self.hash_index.write().await;

        if let Some(record) = index.get_mut(&hash) {
            record.occurrence_count += 1;
            record.last_seen = Utc::now();
        } else {
            let hash_key = hash.clone();
            index.insert(
                hash_key,
                EvidenceHashRecord {
                    hash,
                    first_evidence_id: evidence_id,
                    occurrence_count: 1,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                },
            );
        }

        Ok(())
    }
}

// ============================================
// EVIDENCE STORAGE (In-Memory)
// ============================================

pub struct InMemoryEvidenceStorage {
    evidence: Arc<tokio::sync::RwLock<HashMap<String, Evidence>>>,
}

impl InMemoryEvidenceStorage {
    pub fn new() -> Self {
        Self {
            evidence: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn store_evidence(&self, evidence: Evidence) -> Result<String> {
        let id = evidence.id.clone();
        let mut store = self.evidence.write().await;
        store.insert(id.clone(), evidence);
        Ok(id)
    }

    pub async fn retrieve_evidence(&self, id: &str) -> Result<Option<Evidence>> {
        let store = self.evidence.read().await;
        Ok(store.get(id).cloned())
    }

    pub async fn list_evidence(&self, tenant_id: &str) -> Result<Vec<Evidence>> {
        let store = self.evidence.read().await;
        let list: Vec<_> = store
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .cloned()
            .collect();
        Ok(list)
    }

    pub async fn delete_evidence(&self, id: &str) -> Result<()> {
        let mut store = self.evidence.write().await;
        store.remove(id);
        Ok(())
    }
}

// ============================================
// EVIDENCE INGESTION SERVICE
// ============================================

pub struct EvidenceIngestionService {
    validator: Arc<EvidenceValidator>,
    deduplicator: Arc<EvidenceDeduplicator>,
    storage: Arc<InMemoryEvidenceStorage>,
}

impl EvidenceIngestionService {
    pub fn new(
        validator: Arc<EvidenceValidator>,
        deduplicator: Arc<EvidenceDeduplicator>,
        storage: Arc<InMemoryEvidenceStorage>,
    ) -> Self {
        Self {
            validator,
            deduplicator,
            storage,
        }
    }

    /// Ingest evidence through complete pipeline
    pub async fn ingest(
        &self,
        tenant_id: String,
        evidence_type: String,
        source: String,
        data: Vec<u8>,
    ) -> Result<String> {
        // 1. Validate
        let validation = self.validator.validate(&data, &evidence_type)?;
        if !validation.valid {
            return Err(GrcError::EvidenceValidationFailed(format!(
                "Validation issues: {:?}",
                validation.issues
            )));
        }

        // 2. Compute hash
        let hash = self.validator.compute_hash(&data);

        // 3. Check for duplicates
        if self.deduplicator.check_duplicate(&hash).await?.is_some() {
            return Err(GrcError::EvidenceDuplicate);
        }

        // 4. Create evidence record
        let evidence = Evidence {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id,
            evidence_type,
            source,
            hash: hash.clone(),
            signature: String::new(),
            validation_status: common::models::ValidationStatus::Valid,
            metadata: Default::default(),
            size_bytes: data.len() as u64,
            ingested_at: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
        };

        let evidence_id = evidence.id.clone();

        // 5. Store
        self.storage.store_evidence(evidence).await?;

        // 6. Record hash
        self.deduplicator
            .record_hash(hash, evidence_id.clone())
            .await?;

        Ok(evidence_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_validator() {
        let validator = EvidenceValidator::new(EvidenceValidationConfig::default());

        let valid_data = b"test evidence data";
        let result = validator.validate(valid_data, "log").unwrap();

        assert!(result.valid);
        assert!(result.score > 0.0);
    }

    #[test]
    fn test_evidence_validator_invalid_type() {
        let validator = EvidenceValidator::new(EvidenceValidationConfig::default());

        let data = b"test";
        let result = validator.validate(data, "invalid_type").unwrap();

        assert!(!result.valid);
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn test_hash_computation() {
        let validator = EvidenceValidator::new(EvidenceValidationConfig::default());

        let data = b"test data";
        let hash1 = validator.compute_hash(data);
        let hash2 = validator.compute_hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex string
    }

    #[tokio::test]
    async fn test_deduplicator() {
        let dedup = EvidenceDeduplicator::new();

        let hash = "abc123".to_string();
        let result = dedup.check_duplicate(&hash).await.unwrap();

        assert!(result.is_none());

        dedup
            .record_hash(hash.clone(), "evidence-1".into())
            .await
            .unwrap();

        let result = dedup.check_duplicate(&hash).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_deduplicator_tracks_multiple_occurrences() {
        let dedup = EvidenceDeduplicator::new();
        let hash = "abc123".to_string();

        dedup
            .record_hash(hash.clone(), "evidence-1".into())
            .await
            .unwrap();
        dedup
            .record_hash(hash.clone(), "evidence-2".into())
            .await
            .unwrap();

        let result = dedup.check_duplicate(&hash).await.unwrap().unwrap();
        assert_eq!(result.occurrence_count, 2);
        assert_eq!(result.first_evidence_id, "evidence-1");
    }

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryEvidenceStorage::new();

        let evidence = Evidence {
            id: "e1".into(),
            tenant_id: "t1".into(),
            evidence_type: "log".into(),
            source: "source1".into(),
            hash: "hash1".into(),
            signature: "sig".into(),
            validation_status: common::models::ValidationStatus::Valid,
            metadata: Default::default(),
            size_bytes: 100,
            ingested_at: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
        };

        storage.store_evidence(evidence.clone()).await.unwrap();

        let retrieved = storage.retrieve_evidence("e1").await.unwrap();
        assert!(retrieved.is_some());
    }
}

pub mod storage;
pub mod validation;

pub use storage::*;
pub use validation::*;
