//! Graph intelligence crate for Trust OS.
//!
//! Provides graph analytics, path analysis, and blast radius computation
//! for risk and compliance relationships.

pub mod analytics;
pub mod path;

pub use analytics::*;
pub use path::*;

use graph::{Graph, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusResult {
    pub source_node: NodeId,
    pub affected_nodes: Vec<NodeId>,
    pub affected_edges: Vec<String>,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskPropagation {
    pub source_node: NodeId,
    pub propagation_path: Vec<NodeId>,
    pub propagated_risk: f64,
    pub decay_factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalPath {
    pub path: Vec<NodeId>,
    pub total_weight: f64,
    pub risk_score: f64,
}

pub struct GraphIntelligence {
    graph: Graph,
}

impl GraphIntelligence {
    pub fn new(graph: Graph) -> Self {
        Self { graph }
    }

    pub fn blast_radius(&self, node_id: &NodeId, max_depth: usize) -> BlastRadiusResult {
        let affected = self.graph.blast_radius(node_id, max_depth);
        let affected_edges: Vec<String> = self
            .graph
            .edges
            .values()
            .filter(|e| affected.contains(&e.source) && affected.contains(&e.target))
            .map(|e| e.id.clone())
            .collect();

        BlastRadiusResult {
            source_node: node_id.clone(),
            affected_nodes: affected,
            affected_edges,
            depth: max_depth,
        }
    }

    pub fn propagate_risk(
        &self,
        source: &NodeId,
        initial_risk: f64,
        decay: f64,
        max_depth: usize,
    ) -> Vec<RiskPropagation> {
        let mut propagations = Vec::new();
        let paths = self.all_paths_from(source, max_depth);

        for path in paths {
            let mut risk = initial_risk;
            for (i, _node) in path.iter().enumerate() {
                if i > 0 {
                    risk *= decay;
                }
                propagations.push(RiskPropagation {
                    source_node: source.clone(),
                    propagation_path: path[..=i].to_vec(),
                    propagated_risk: risk,
                    decay_factor: decay,
                });
            }
        }

        propagations
    }

    pub fn find_critical_paths(&self, from: &NodeId, to: &NodeId) -> Vec<CriticalPath> {
        let paths = self.all_paths(from, to);
        let mut critical_paths: Vec<CriticalPath> = paths
            .into_iter()
            .filter_map(|path| {
                let total_weight: f64 = path
                    .windows(2)
                    .filter_map(|w| {
                        self.graph
                            .edges
                            .values()
                            .find(|e| e.source == w[0] && e.target == w[1])
                            .map(|e| e.weight)
                    })
                    .sum();

                let risk_score = total_weight / path.len() as f64;

                Some(CriticalPath {
                    path,
                    total_weight,
                    risk_score,
                })
            })
            .collect();

        critical_paths.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
        critical_paths
    }

    pub fn centrality_scores(&self) -> HashMap<NodeId, f64> {
        let mut scores = HashMap::new();
        let node_count = self.graph.node_count() as f64;

        for node_id in self.graph.nodes.keys() {
            let out_degree = self
                .graph
                .adjacency
                .get(node_id)
                .map(|n| n.len() as f64)
                .unwrap_or(0.0);
            let in_degree = self
                .graph
                .reverse_adjacency
                .get(node_id)
                .map(|n| n.len() as f64)
                .unwrap_or(0.0);

            let score = if node_count > 0.0 {
                (out_degree + in_degree) / (2.0 * (node_count - 1.0))
            } else {
                0.0
            };

            scores.insert(node_id.clone(), score);
        }

        scores
    }

    fn all_paths_from(&self, start: &NodeId, max_depth: usize) -> Vec<Vec<NodeId>> {
        let mut paths = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.dfs_paths(
            start,
            &mut visited,
            &mut paths,
            vec![start.clone()],
            max_depth,
            0,
        );
        paths
    }

    fn all_paths(&self, from: &NodeId, to: &NodeId) -> Vec<Vec<NodeId>> {
        let mut paths = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.dfs_to_target(from, to, &mut visited, &mut paths, vec![from.clone()]);
        paths
    }

    fn dfs_paths(
        &self,
        current: &NodeId,
        visited: &mut std::collections::HashSet<NodeId>,
        paths: &mut Vec<Vec<NodeId>>,
        current_path: Vec<NodeId>,
        max_depth: usize,
        depth: usize,
    ) {
        if depth >= max_depth {
            return;
        }

        visited.insert(current.clone());

        if let Some(neighbors) = self.graph.adjacency.get(current) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    let mut new_path = current_path.clone();
                    new_path.push(neighbor.clone());
                    paths.push(new_path.clone());
                    self.dfs_paths(neighbor, visited, paths, new_path, max_depth, depth + 1);
                }
            }
        }

        visited.remove(current);
    }

    fn dfs_to_target(
        &self,
        current: &NodeId,
        target: &NodeId,
        visited: &mut std::collections::HashSet<NodeId>,
        paths: &mut Vec<Vec<NodeId>>,
        current_path: Vec<NodeId>,
    ) {
        if current == target {
            paths.push(current_path);
            return;
        }

        visited.insert(current.clone());

        if let Some(neighbors) = self.graph.adjacency.get(current) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    let mut new_path = current_path.clone();
                    new_path.push(neighbor.clone());
                    self.dfs_to_target(neighbor, target, visited, paths, new_path);
                }
            }
        }

        visited.remove(current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph::{GraphEdge, GraphNode};

    fn make_test_graph() -> Graph {
        let mut g = Graph::new("g1", "t1");
        g.add_node(GraphNode {
            id: "a".into(),
            node_type: NodeType::Risk,
            label: "Risk A".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_node(GraphNode {
            id: "b".into(),
            node_type: NodeType::Control,
            label: "Control B".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_node(GraphNode {
            id: "c".into(),
            node_type: NodeType::Asset,
            label: "Asset C".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_edge(GraphEdge {
            id: "e1".into(),
            source: "a".into(),
            target: "b".into(),
            edge_type: EdgeType::Mitigates,
            weight: 0.8,
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
        })
        .unwrap();
        g.add_edge(GraphEdge {
            id: "e2".into(),
            source: "b".into(),
            target: "c".into(),
            edge_type: EdgeType::Supports,
            weight: 0.5,
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
        })
        .unwrap();
        g
    }

    #[test]
    fn test_blast_radius() {
        let gi = GraphIntelligence::new(make_test_graph());
        let result = gi.blast_radius(&"a".into(), 2);
        assert!(result.affected_nodes.contains(&"a".to_string()));
        assert!(result.affected_nodes.contains(&"b".to_string()));
        assert!(result.affected_nodes.contains(&"c".to_string()));
    }

    #[test]
    fn test_centrality() {
        let gi = GraphIntelligence::new(make_test_graph());
        let scores = gi.centrality_scores();
        assert!(scores.get("b").unwrap() > scores.get("a").unwrap());
    }
}
