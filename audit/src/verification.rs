use crate::AuditEvent;
use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityProof {
    pub event_id: String,
    pub hash: String,
    pub previous_hash: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct AuditIntegrityChain {
    proofs: Vec<IntegrityProof>,
}

impl AuditIntegrityChain {
    pub fn new() -> Self {
        Self { proofs: Vec::new() }
    }

    pub fn add_event(&mut self, event: &AuditEvent) -> Result<IntegrityProof> {
        let previous_hash = self.proofs.last().map(|p| p.hash.clone());

        let hash = self.compute_hash(event, &previous_hash);

        let proof = IntegrityProof {
            event_id: event.id.clone(),
            hash,
            previous_hash,
            timestamp: chrono::Utc::now(),
        };

        self.proofs.push(proof.clone());
        Ok(proof)
    }

    pub fn verify_chain(&self) -> Result<bool> {
        for i in 1..self.proofs.len() {
            if self.proofs[i].previous_hash.as_ref() != Some(&self.proofs[i - 1].hash) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn verify_event(&self, event_id: &str, expected_hash: &str) -> Result<bool> {
        let proof = self
            .proofs
            .iter()
            .find(|p| p.event_id == event_id)
            .ok_or_else(|| GrcError::EvidenceNotFound(event_id.to_string()))?;
        Ok(proof.hash == expected_hash)
    }

    fn compute_hash(&self, event: &AuditEvent, previous_hash: &Option<String>) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(event.id.as_bytes());
        hasher.update(event.timestamp.to_rfc3339().as_bytes());
        hasher.update(event.actor.as_bytes());
        hasher.update(event.action.as_bytes());

        if let Some(prev) = previous_hash {
            hasher.update(prev.as_bytes());
        }

        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn chain_length(&self) -> usize {
        self.proofs.len()
    }
}

impl Default for AuditIntegrityChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditCategory, AuditSeverity};

    fn test_event(id: &str) -> AuditEvent {
        AuditEvent::new(
            "t1",
            AuditCategory::Authentication,
            AuditSeverity::Info,
            "user1",
            "login",
            "session",
            id,
        )
    }

    #[test]
    fn test_chain_integrity() {
        let mut chain = AuditIntegrityChain::new();
        chain.add_event(&test_event("e1")).unwrap();
        chain.add_event(&test_event("e2")).unwrap();
        chain.add_event(&test_event("e3")).unwrap();

        assert!(chain.verify_chain().unwrap());
        assert_eq!(chain.chain_length(), 3);
    }

    #[test]
    fn test_verify_event() {
        let mut chain = AuditIntegrityChain::new();
        let proof = chain.add_event(&test_event("e1")).unwrap();

        assert!(chain.verify_event("e1", &proof.hash).unwrap());
        assert!(!chain.verify_event("e1", "wrong_hash").unwrap());
    }
}
