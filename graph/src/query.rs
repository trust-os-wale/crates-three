use crate::{EdgeType, Graph, NodeId, NodeType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQuery {
    pub node_type_filter: Option<NodeType>,
    pub edge_type_filter: Option<EdgeType>,
    pub property_filters: HashMap<String, String>,
    pub max_depth: Option<usize>,
    pub start_node: Option<NodeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub nodes: Vec<NodeId>,
    pub edges: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl Graph {
    pub fn query(&self, query: &GraphQuery) -> QueryResult {
        let mut matching_nodes: Vec<NodeId> = Vec::new();
        let mut matching_edges: Vec<String> = Vec::new();

        for (id, node) in &self.nodes {
            let mut matches = true;

            if let Some(ref node_type) = query.node_type_filter {
                if &node.node_type != node_type {
                    matches = false;
                }
            }

            for (key, value) in &query.property_filters {
                if node.properties.get(key).map(|v| v.as_str()) != Some(value.as_str()) {
                    matches = false;
                }
            }

            if matches {
                matching_nodes.push(id.clone());
            }
        }

        for (id, edge) in &self.edges {
            let mut matches = true;

            if let Some(ref edge_type) = query.edge_type_filter {
                if &edge.edge_type != edge_type {
                    matches = false;
                }
            }

            if matching_nodes.contains(&edge.source) || matching_nodes.contains(&edge.target) {
                if matches {
                    matching_edges.push(id.clone());
                }
            }
        }

        let mut metadata = HashMap::new();
        metadata.insert("total_nodes".into(), matching_nodes.len().to_string());
        metadata.insert("total_edges".into(), matching_edges.len().to_string());

        QueryResult {
            nodes: matching_nodes,
            edges: matching_edges,
            metadata,
        }
    }

    pub fn find_nodes_by_type(&self, node_type: &NodeType) -> Vec<&crate::GraphNode> {
        self.nodes
            .values()
            .filter(|n| &n.node_type == node_type)
            .collect()
    }

    pub fn find_edges_between(&self, source: &NodeId, target: &NodeId) -> Vec<&crate::GraphEdge> {
        self.edges
            .values()
            .filter(|e| &e.source == source && &e.target == target)
            .collect()
    }

    pub fn incoming_edges(&self, node_id: &NodeId) -> Vec<&crate::GraphEdge> {
        self.edges
            .values()
            .filter(|e| &e.target == node_id)
            .collect()
    }

    pub fn outgoing_edges(&self, node_id: &NodeId) -> Vec<&crate::GraphEdge> {
        self.edges
            .values()
            .filter(|e| &e.source == node_id)
            .collect()
    }

    pub fn connected_components(&self) -> Vec<Vec<NodeId>> {
        let mut visited = HashSet::new();
        let mut components = Vec::new();

        for node_id in self.nodes.keys() {
            if visited.contains(node_id) {
                continue;
            }
            let mut component = Vec::new();
            let mut stack = vec![node_id.clone()];
            while let Some(current) = stack.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current.clone());
                component.push(current.clone());

                if let Some(neighbors) = self.adjacency.get(&current) {
                    for n in neighbors {
                        if !visited.contains(n) {
                            stack.push(n.clone());
                        }
                    }
                }
                if let Some(neighbors) = self.reverse_adjacency.get(&current) {
                    for n in neighbors {
                        if !visited.contains(n) {
                            stack.push(n.clone());
                        }
                    }
                }
            }
            components.push(component);
        }
        components
    }

    pub fn cycle_detection(&self) -> bool {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        fn dfs(
            graph: &Graph,
            node: &NodeId,
            visited: &mut HashSet<NodeId>,
            rec_stack: &mut HashSet<NodeId>,
        ) -> bool {
            visited.insert(node.clone());
            rec_stack.insert(node.clone());

            if let Some(neighbors) = graph.adjacency.get(node) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        if dfs(graph, neighbor, visited, rec_stack) {
                            return true;
                        }
                    } else if rec_stack.contains(neighbor) {
                        return true;
                    }
                }
            }

            rec_stack.remove(node);
            false
        }

        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) {
                if dfs(self, node_id, &mut visited, &mut rec_stack) {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GraphEdge, GraphNode};

    fn make_test_graph() -> Graph {
        let mut g = Graph::new("q1", "t1");
        g.add_node(GraphNode {
            id: "a".into(),
            node_type: NodeType::Entity,
            label: "Entity A".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_node(GraphNode {
            id: "b".into(),
            node_type: NodeType::Policy,
            label: "Policy B".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_node(GraphNode {
            id: "c".into(),
            node_type: NodeType::Control,
            label: "Control C".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_edge(GraphEdge {
            id: "e1".into(),
            source: "a".into(),
            target: "b".into(),
            edge_type: EdgeType::GovernedBy,
            weight: 1.0,
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
        })
        .unwrap();
        g.add_edge(GraphEdge {
            id: "e2".into(),
            source: "b".into(),
            target: "c".into(),
            edge_type: EdgeType::Implements,
            weight: 1.0,
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
        })
        .unwrap();
        g
    }

    #[test]
    fn test_query_by_type() {
        let g = make_test_graph();
        let query = GraphQuery {
            node_type_filter: Some(NodeType::Policy),
            edge_type_filter: None,
            property_filters: HashMap::new(),
            max_depth: None,
            start_node: None,
        };
        let result = g.query(&query);
        assert_eq!(result.nodes.len(), 1);
        assert!(result.nodes.contains(&"b".to_string()));
    }

    #[test]
    fn test_connected_components() {
        let g = make_test_graph();
        let components = g.connected_components();
        assert_eq!(components.len(), 1);
    }

    #[test]
    fn test_no_cycle() {
        let g = make_test_graph();
        assert!(!g.cycle_detection());
    }
}
