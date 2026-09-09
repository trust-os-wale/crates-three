//! Graph domain crate for Trust OS.
//!
//! Provides in-memory graph data structures for modeling relationships
//! between entities, policies, controls, risks, and compliance items.

pub mod operations;
pub mod query;

pub use operations::*;
pub use query::*;

use common::errors::{GrcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

pub type NodeId = String;
pub type EdgeId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeType {
    Entity,
    Policy,
    Control,
    Risk,
    Compliance,
    Evidence,
    Assessment,
    Asset,
    Threat,
    Vulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EdgeType {
    DependsOn,
    Implements,
    Mitigates,
    Violates,
    Assesses,
    Requires,
    Triggers,
    ConflictsWith,
    Supports,
    GovernedBy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: NodeId,
    pub node_type: NodeType,
    pub label: String,
    pub properties: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: EdgeId,
    pub source: NodeId,
    pub target: NodeId,
    pub edge_type: EdgeType,
    pub weight: f64,
    pub properties: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graph {
    pub id: String,
    pub tenant_id: String,
    pub nodes: HashMap<NodeId, GraphNode>,
    pub edges: HashMap<EdgeId, GraphEdge>,
    pub adjacency: HashMap<NodeId, Vec<NodeId>>,
    pub reverse_adjacency: HashMap<NodeId, Vec<NodeId>>,
}

impl Graph {
    pub fn new(id: &str, tenant_id: &str) -> Self {
        Self {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            nodes: HashMap::new(),
            edges: HashMap::new(),
            adjacency: HashMap::new(),
            reverse_adjacency: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) {
        self.adjacency.entry(node.id.clone()).or_default();
        self.reverse_adjacency.entry(node.id.clone()).or_default();
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: GraphEdge) -> Result<()> {
        if !self.nodes.contains_key(&edge.source) {
            return Err(GrcError::GraphNodeNotFound(edge.source));
        }
        if !self.nodes.contains_key(&edge.target) {
            return Err(GrcError::GraphNodeNotFound(edge.target));
        }
        self.adjacency
            .entry(edge.source.clone())
            .or_default()
            .push(edge.target.clone());
        self.reverse_adjacency
            .entry(edge.target.clone())
            .or_default()
            .push(edge.source.clone());
        self.edges.insert(edge.id.clone(), edge);
        Ok(())
    }

    pub fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
        self.nodes.get(id)
    }

    pub fn neighbors(&self, id: &NodeId) -> Vec<&GraphNode> {
        self.adjacency
            .get(id)
            .map(|ids| ids.iter().filter_map(|i| self.nodes.get(i)).collect())
            .unwrap_or_default()
    }

    pub fn incoming_neighbors(&self, id: &NodeId) -> Vec<&GraphNode> {
        self.reverse_adjacency
            .get(id)
            .map(|ids| ids.iter().filter_map(|i| self.nodes.get(i)).collect())
            .unwrap_or_default()
    }

    pub fn shortest_path(&self, from: &NodeId, to: &NodeId) -> Option<Vec<NodeId>> {
        if from == to {
            return Some(vec![from.clone()]);
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((from.clone(), vec![from.clone()]));
        visited.insert(from.clone());

        while let Some((current, path)) = queue.pop_front() {
            if let Some(neighbors) = self.adjacency.get(&current) {
                for neighbor in neighbors {
                    if neighbor == to {
                        let mut result = path.clone();
                        result.push(neighbor.clone());
                        return Some(result);
                    }
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        let mut new_path = path.clone();
                        new_path.push(neighbor.clone());
                        queue.push_back((neighbor.clone(), new_path));
                    }
                }
            }
        }
        None
    }

    pub fn blast_radius(&self, node_id: &NodeId, max_depth: usize) -> Vec<NodeId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((node_id.clone(), 0));
        visited.insert(node_id.clone());

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(neighbors) = self.adjacency.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        queue.push_back((neighbor.clone(), depth + 1));
                    }
                }
            }
        }

        visited.into_iter().collect()
    }

    pub fn subgraph(&self, node_ids: &[NodeId]) -> Graph {
        let id_set: HashSet<&NodeId> = node_ids.iter().collect();
        let mut sub = Graph::new(&format!("{}-sub", self.id), &self.tenant_id);

        for nid in node_ids {
            if let Some(node) = self.nodes.get(nid) {
                sub.add_node(node.clone());
            }
        }

        for edge in self.edges.values() {
            if id_set.contains(&edge.source) && id_set.contains(&edge.target) {
                sub.edges.insert(edge.id.clone(), edge.clone());
            }
        }

        sub
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new("default", "default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, node_type: NodeType) -> GraphNode {
        GraphNode {
            id: id.to_string(),
            node_type,
            label: id.to_string(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn make_edge(id: &str, source: &str, target: &str, edge_type: EdgeType) -> GraphEdge {
        GraphEdge {
            id: id.to_string(),
            source: source.to_string(),
            target: target.to_string(),
            edge_type,
            weight: 1.0,
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_graph_add_nodes_and_edges() {
        let mut g = Graph::new("g1", "t1");
        g.add_node(make_node("a", NodeType::Entity));
        g.add_node(make_node("b", NodeType::Policy));
        g.add_edge(make_edge("e1", "a", "b", EdgeType::GovernedBy))
            .unwrap();

        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_shortest_path() {
        let mut g = Graph::new("g1", "t1");
        g.add_node(make_node("a", NodeType::Entity));
        g.add_node(make_node("b", NodeType::Policy));
        g.add_node(make_node("c", NodeType::Control));
        g.add_edge(make_edge("e1", "a", "b", EdgeType::DependsOn))
            .unwrap();
        g.add_edge(make_edge("e2", "b", "c", EdgeType::Implements))
            .unwrap();

        let path = g.shortest_path(&"a".to_string(), &"c".to_string()).unwrap();
        assert_eq!(path, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_blast_radius() {
        let mut g = Graph::new("g1", "t1");
        g.add_node(make_node("a", NodeType::Entity));
        g.add_node(make_node("b", NodeType::Policy));
        g.add_node(make_node("c", NodeType::Control));
        g.add_node(make_node("d", NodeType::Risk));
        g.add_edge(make_edge("e1", "a", "b", EdgeType::DependsOn))
            .unwrap();
        g.add_edge(make_edge("e2", "b", "c", EdgeType::Implements))
            .unwrap();
        g.add_edge(make_edge("e3", "c", "d", EdgeType::Mitigates))
            .unwrap();

        let affected = g.blast_radius(&"a".to_string(), 2);
        assert!(affected.contains(&"a".to_string()));
        assert!(affected.contains(&"b".to_string()));
        assert!(affected.contains(&"c".to_string()));
        assert!(!affected.contains(&"d".to_string()));
    }
}
