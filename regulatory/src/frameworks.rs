//! Development seed data for frameworks and regulations.
//!
//! NOTE: The PostgreSQL database (migration 005) is the authoritative source
//! of regulatory content. These seeds exist only for local development and
//! integration tests. They intentionally contain NO fabricated requirements:
//! requirements and obligations must be ingested from official sources via
//! the source registry before the platform can assess them.

use crate::{
    Framework, FrameworkStatus, FrameworkVersion, Regulation, RegulationStatus, RegulationVersion,
};

fn utc(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

/// Seed regulations (head records only; requirements come from ingestion).
pub fn seed_regulations() -> Vec<Regulation> {
    vec![Regulation {
        id: "reg-gdpr".to_string(),
        title: "General Data Protection Regulation".to_string(),
        short_title: "GDPR".to_string(),
        regulation_number: "EU 2016/679".to_string(),
        authority_id: "auth-eu-edpb".to_string(),
        jurisdiction_id: "jur-eu".to_string(),
        current_version_id: Some("reg-gdpr-v1".to_string()),
        status: RegulationStatus::InForce,
        created_at: utc("2016-05-04T00:00:00Z"),
    }]
}

/// Seed regulation versions (head records only).
pub fn seed_regulation_versions() -> Vec<RegulationVersion> {
    vec![RegulationVersion {
        id: "reg-gdpr-v1".to_string(),
        regulation_id: "reg-gdpr".to_string(),
        version_number: 1,
        version_label: "EU 2016/679 (original)".to_string(),
        effective_from: Some(utc("2018-05-25T00:00:00Z")),
        effective_to: None,
        status: RegulationStatus::InForce,
        changelog: Some("Initial version".to_string()),
        source_id: Some("src-eu-gazette-gdpr".to_string()),
        supersedes_id: None,
        superseded_by: None,
        published_at: Some(utc("2016-05-04T00:00:00Z")),
    }]
}

/// Seed frameworks (head records only; controls come from ingestion).
pub fn seed_frameworks() -> Vec<Framework> {
    vec![
        Framework {
            id: "fw-soc2".to_string(),
            name: "SOC 2".to_string(),
            description: Some("AICPA SOC 2 Trust Services Criteria".to_string()),
            status: FrameworkStatus::Published,
            created_at: utc("2022-01-01T00:00:00Z"),
        },
        Framework {
            id: "fw-iso27001".to_string(),
            name: "ISO/IEC 27001".to_string(),
            description: Some("Information Security Management Systems".to_string()),
            status: FrameworkStatus::Published,
            created_at: utc("2022-10-25T00:00:00Z"),
        },
        Framework {
            id: "fw-pci-dss".to_string(),
            name: "PCI DSS".to_string(),
            description: Some("Payment Card Industry Data Security Standard".to_string()),
            status: FrameworkStatus::Published,
            created_at: utc("2022-03-31T00:00:00Z"),
        },
        Framework {
            id: "fw-hipaa".to_string(),
            name: "HIPAA".to_string(),
            description: Some("Health Insurance Portability and Accountability Act".to_string()),
            status: FrameworkStatus::Published,
            created_at: utc("2013-01-01T00:00:00Z"),
        },
    ]
}

/// Seed framework versions (head records only).
pub fn seed_framework_versions() -> Vec<FrameworkVersion> {
    vec![
        FrameworkVersion {
            id: "fw-soc2-v1".to_string(),
            framework_id: "fw-soc2".to_string(),
            version_number: 1,
            version_label: "2022 TSC".to_string(),
            effective_from: Some(utc("2022-01-01T00:00:00Z")),
            effective_to: None,
            status: FrameworkStatus::Published,
            changelog: None,
            source_id: None,
        },
        FrameworkVersion {
            id: "fw-iso27001-v1".to_string(),
            framework_id: "fw-iso27001".to_string(),
            version_number: 1,
            version_label: "2022".to_string(),
            effective_from: Some(utc("2022-10-25T00:00:00Z")),
            effective_to: None,
            status: FrameworkStatus::Published,
            changelog: None,
            source_id: None,
        },
        FrameworkVersion {
            id: "fw-pci-dss-v1".to_string(),
            framework_id: "fw-pci-dss".to_string(),
            version_number: 1,
            version_label: "4.0".to_string(),
            effective_from: Some(utc("2022-03-31T00:00:00Z")),
            effective_to: None,
            status: FrameworkStatus::Published,
            changelog: None,
            source_id: None,
        },
        FrameworkVersion {
            id: "fw-hipaa-v1".to_string(),
            framework_id: "fw-hipaa".to_string(),
            version_number: 1,
            version_label: "2013".to_string(),
            effective_from: Some(utc("2013-03-26T00:00:00Z")),
            effective_to: None,
            status: FrameworkStatus::Published,
            changelog: None,
            source_id: None,
        },
    ]
}

/// All seed head records in one call.
pub fn all_seeds() -> (
    Vec<Regulation>,
    Vec<RegulationVersion>,
    Vec<Framework>,
    Vec<FrameworkVersion>,
) {
    (
        seed_regulations(),
        seed_regulation_versions(),
        seed_frameworks(),
        seed_framework_versions(),
    )
}
