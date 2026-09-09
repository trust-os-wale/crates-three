use graph::{Graph, NodeId};

pub struct GraphAnalyzer<'a> {
    graph: &'a Graph,
}

impl<'a> GraphAnalyzer<'a> {
    pub fn new(graph: &'a Graph) -> Self {
        Self { graph }
    }

    pub fn density(&self) -> f64 {
        let n = self.graph.node_count() as f64;
        if n <= 1.0 {
            return 0.0;
        }
        let max_edges = n * (n - 1.0);
        self.graph.edge_count() as f64 / max_edges
    }

    pub fn average_degree(&self) -> f64 {
        let n = self.graph.node_count() as f64;
        if n == 0.0 {
            return 0.0;
        }
        self.graph.edge_count() as f64 / n
    }

    pub fn isolated_nodes(&self) -> Vec<NodeId> {
        self.graph
            .nodes
            .keys()
            .filter(|id| {
                let out = self.graph.adjacency.get(*id).map(|n| n.len()).unwrap_or(0);
                let in_ = self
                    .graph
                    .reverse_adjacency
                    .get(*id)
                    .map(|n| n.len())
                    .unwrap_or(0);
                out == 0 && in_ == 0
            })
            .cloned()
            .collect()
    }

    pub fn strongly_connected_components(&self) -> Vec<Vec<NodeId>> {
        self.graph.connected_components()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph::{GraphEdge, GraphNode, NodeType};

    #[test]
    fn test_density() {
        let mut g = Graph::new("g1", "t1");
        g.add_node(GraphNode {
            id: "a".into(),
            node_type: NodeType::Entity,
            label: "A".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_node(GraphNode {
            id: "b".into(),
            node_type: NodeType::Entity,
            label: "B".into(),
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        g.add_edge(GraphEdge {
            id: "e1".into(),
            source: "a".into(),
            target: "b".into(),
            edge_type: graph::EdgeType::DependsOn,
            weight: 1.0,
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
        })
        .unwrap();

        let analyzer = GraphAnalyzer::new(&g);
        assert!((analyzer.density() - 0.5).abs() < 0.01);
        assert_eq!(analyzer.average_degree(), 1.0);
    }
}
