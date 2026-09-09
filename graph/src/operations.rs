use crate::{EdgeType, Graph, GraphEdge, GraphNode, NodeId, NodeType};
use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphOperation {
    pub op_type: OperationType,
    pub node_id: Option<NodeId>,
    pub edge_id: Option<String>,
    pub source: Option<NodeId>,
    pub target: Option<NodeId>,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    AddNode,
    RemoveNode,
    AddEdge,
    RemoveEdge,
    UpdateNode,
    Merge,
    Diff,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphDiff {
    pub nodes_added: Vec<NodeId>,
    pub nodes_removed: Vec<NodeId>,
    pub edges_added: Vec<String>,
    pub edges_removed: Vec<String>,
}

pub trait GraphOperations {
    fn apply_operation(&mut self, op: GraphOperation) -> Result<()>;
    fn diff(&self, other: &Graph) -> GraphDiff;
    fn merge(&mut self, other: &Graph) -> Result<()>;
}

impl GraphOperations for Graph {
    fn apply_operation(&mut self, op: GraphOperation) -> Result<()> {
        match op.op_type {
            OperationType::AddNode => {
                let id = op.node_id.ok_or_else(|| {
                    GrcError::InvalidRequest("node_id required for AddNode".into())
                })?;
                let node_type_str = op
                    .properties
                    .get("node_type")
                    .cloned()
                    .unwrap_or_else(|| "Entity".into());
                let node_type = match node_type_str.as_str() {
                    "Policy" => NodeType::Policy,
                    "Control" => NodeType::Control,
                    "Risk" => NodeType::Risk,
                    "Compliance" => NodeType::Compliance,
                    "Evidence" => NodeType::Evidence,
                    "Assessment" => NodeType::Assessment,
                    "Asset" => NodeType::Asset,
                    "Threat" => NodeType::Threat,
                    "Vulnerability" => NodeType::Vulnerability,
                    _ => NodeType::Entity,
                };
                let label = op
                    .properties
                    .get("label")
                    .cloned()
                    .unwrap_or_else(|| id.clone());
                let node = GraphNode {
                    id: id.clone(),
                    node_type,
                    label,
                    properties: op.properties,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                self.add_node(node);
                Ok(())
            }
            OperationType::RemoveNode => {
                let id = op.node_id.ok_or_else(|| {
                    GrcError::InvalidRequest("node_id required for RemoveNode".into())
                })?;
                self.nodes.remove(&id);
                self.adjacency.remove(&id);
                self.reverse_adjacency.remove(&id);
                for neighbors in self.adjacency.values_mut() {
                    neighbors.retain(|n| n != &id);
                }
                for neighbors in self.reverse_adjacency.values_mut() {
                    neighbors.retain(|n| n != &id);
                }
                Ok(())
            }
            OperationType::AddEdge => {
                let edge_id = op
                    .edge_id
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let source = op.source.ok_or_else(|| {
                    GrcError::InvalidRequest("source required for AddEdge".into())
                })?;
                let target = op.target.ok_or_else(|| {
                    GrcError::InvalidRequest("target required for AddEdge".into())
                })?;
                let edge_type_str = op
                    .properties
                    .get("edge_type")
                    .cloned()
                    .unwrap_or_else(|| "DependsOn".into());
                let edge_type = match edge_type_str.as_str() {
                    "Implements" => EdgeType::Implements,
                    "Mitigates" => EdgeType::Mitigates,
                    "Violates" => EdgeType::Violates,
                    "Assesses" => EdgeType::Assesses,
                    "Requires" => EdgeType::Requires,
                    "Triggers" => EdgeType::Triggers,
                    "ConflictsWith" => EdgeType::ConflictsWith,
                    "Supports" => EdgeType::Supports,
                    "GovernedBy" => EdgeType::GovernedBy,
                    _ => EdgeType::DependsOn,
                };
                let weight = op
                    .properties
                    .get("weight")
                    .and_then(|w| w.parse::<f64>().ok())
                    .unwrap_or(1.0);
                let edge = GraphEdge {
                    id: edge_id,
                    source,
                    target,
                    edge_type,
                    weight,
                    properties: op.properties,
                    created_at: chrono::Utc::now(),
                };
                self.add_edge(edge)
            }
            OperationType::RemoveEdge => {
                let edge_id = op.edge_id.ok_or_else(|| {
                    GrcError::InvalidRequest("edge_id required for RemoveEdge".into())
                })?;
                self.edges.remove(&edge_id);
                Ok(())
            }
            OperationType::UpdateNode => {
                let id = op.node_id.ok_or_else(|| {
                    GrcError::InvalidRequest("node_id required for UpdateNode".into())
                })?;
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.properties.extend(op.properties);
                    node.updated_at = chrono::Utc::now();
                }
                Ok(())
            }
            OperationType::Merge | OperationType::Diff => Ok(()),
        }
    }

    fn diff(&self, other: &Graph) -> GraphDiff {
        let self_node_ids: std::collections::HashSet<&NodeId> = self.nodes.keys().collect();
        let other_node_ids: std::collections::HashSet<&NodeId> = other.nodes.keys().collect();

        let nodes_added: Vec<NodeId> = other_node_ids
            .difference(&self_node_ids)
            .map(|id| (*id).clone())
            .collect();
        let nodes_removed: Vec<NodeId> = self_node_ids
            .difference(&other_node_ids)
            .map(|id| (*id).clone())
            .collect();

        let self_edge_ids: std::collections::HashSet<&str> =
            self.edges.keys().map(|s| s.as_str()).collect();
        let other_edge_ids: std::collections::HashSet<&str> =
            other.edges.keys().map(|s| s.as_str()).collect();

        let edges_added: Vec<String> = other_edge_ids
            .difference(&self_edge_ids)
            .map(|id| id.to_string())
            .collect();
        let edges_removed: Vec<String> = self_edge_ids
            .difference(&other_edge_ids)
            .map(|id| id.to_string())
            .collect();

        GraphDiff {
            nodes_added,
            nodes_removed,
            edges_added,
            edges_removed,
        }
    }

    fn merge(&mut self, other: &Graph) -> Result<()> {
        for node in other.nodes.values() {
            self.add_node(node.clone());
        }
        for edge in other.edges.values() {
            if !self.edges.contains_key(&edge.id) {
                self.add_edge(edge.clone())?;
            }
        }
        Ok(())
    }
}
