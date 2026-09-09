//! Jurisdiction domain types and hierarchy resolution.
//!
//! Jurisdictions form a tree (regional bloc -> nation -> state/province ->
//! local/municipality, plus sector authorities). Hierarchy resolution is
//! used by the applicability engine to compute implied jurisdiction sets.

use crate::RecordStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JurisdictionLevel {
    Nation,
    StateProvince,
    RegionalBloc,
    LocalMunicipality,
    SectorAuthority,
}

/// A legal jurisdiction (EU, Germany, California, GDPR sector authority, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jurisdiction {
    pub id: String,
    pub code: String,
    pub name: String,
    pub level: JurisdictionLevel,
    pub parent_id: Option<String>,
    pub description: Option<String>,
    pub status: RecordStatus,
}

/// Pure hierarchy logic over a jurisdiction tree.
pub struct JurisdictionEngine;

impl JurisdictionEngine {
    /// Full ancestor chain from `jurisdiction_id` up to the root.
    pub fn ancestor_chain<'a>(
        jurisdiction_id: &str,
        all: &'a [Jurisdiction],
    ) -> Vec<&'a Jurisdiction> {
        let mut chain = Vec::new();
        let mut current = all.iter().find(|j| j.id == jurisdiction_id);
        while let Some(node) = current {
            chain.push(node);
            current = node
                .parent_id
                .as_deref()
                .and_then(|p| all.iter().find(|j| j.id == p));
        }
        chain
    }

    /// True when `child` equals or is nested under `ancestor`.
    pub fn is_within(child: &str, ancestor: &str, all: &[Jurisdiction]) -> bool {
        child == ancestor
            || Self::ancestor_chain(child, all)
                .iter()
                .any(|j| j.id == ancestor)
    }

    /// All jurisdictions strictly below `ancestor_id`.
    pub fn descendants<'a>(ancestor_id: &str, all: &'a [Jurisdiction]) -> Vec<&'a Jurisdiction> {
        all.iter()
            .filter(|j| j.id != ancestor_id && Self::is_within(&j.id, ancestor_id, all))
            .collect()
    }

    /// Expand a set of jurisdiction ids to include all implied ancestors.
    ///
    /// Example: an organization operating in "de" (Germany) is implicitly
    /// within "eu" (European Union); rules targeting "eu" must match.
    pub fn implied(ids: &[String], all: &[Jurisdiction]) -> Vec<String> {
        let mut out: Vec<String> = ids.to_vec();
        for id in ids {
            for ancestor in Self::ancestor_chain(id, all) {
                if !out.contains(&ancestor.id) {
                    out.push(ancestor.id.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> Vec<Jurisdiction> {
        vec![
            Jurisdiction {
                id: "eu".into(),
                code: "EU".into(),
                name: "European Union".into(),
                level: JurisdictionLevel::RegionalBloc,
                parent_id: None,
                description: None,
                status: RecordStatus::Active,
            },
            Jurisdiction {
                id: "de".into(),
                code: "DE".into(),
                name: "Germany".into(),
                level: JurisdictionLevel::Nation,
                parent_id: Some("eu".into()),
                description: None,
                status: RecordStatus::Active,
            },
            Jurisdiction {
                id: "de-by".into(),
                code: "DE-BY".into(),
                name: "Bavaria".into(),
                level: JurisdictionLevel::StateProvince,
                parent_id: Some("de".into()),
                description: None,
                status: RecordStatus::Active,
            },
            Jurisdiction {
                id: "us".into(),
                code: "US".into(),
                name: "United States".into(),
                level: JurisdictionLevel::Nation,
                parent_id: None,
                description: None,
                status: RecordStatus::Active,
            },
        ]
    }

    #[test]
    fn test_ancestor_chain() {
        let tree = sample_tree();
        let chain = JurisdictionEngine::ancestor_chain("de-by", &tree);
        let ids: Vec<&str> = chain.iter().map(|j| j.id.as_str()).collect();
        assert_eq!(ids, vec!["de-by", "de", "eu"]);
    }

    #[test]
    fn test_is_within() {
        let tree = sample_tree();
        assert!(JurisdictionEngine::is_within("de-by", "eu", &tree));
        assert!(!JurisdictionEngine::is_within("de-by", "us", &tree));
        assert!(JurisdictionEngine::is_within("eu", "eu", &tree));
    }

    #[test]
    fn test_implied_jurisdictions() {
        let tree = sample_tree();
        let implied = JurisdictionEngine::implied(&["de-by".to_string()], &tree);
        assert!(implied.contains(&"de".to_string()));
        assert!(implied.contains(&"eu".to_string()));
        assert!(!implied.contains(&"us".to_string()));
    }

    #[test]
    fn test_descendants() {
        let tree = sample_tree();
        let children = JurisdictionEngine::descendants("eu", &tree);
        let ids: Vec<&str> = children.iter().map(|j| j.id.as_str()).collect();
        assert!(ids.contains(&"de".to_string().as_str()));
        assert!(ids.contains(&"de-by".to_string().as_str()));
        assert!(!ids.contains(&"us".to_string().as_str()));
    }
}
