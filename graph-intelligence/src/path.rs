use crate::CriticalPath;
use graph::{Graph, NodeId};
use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap, HashSet};

#[derive(Clone, Copy, PartialEq)]
struct OrderedFloat(f64);

impl Eq for OrderedFloat {}

impl PartialOrd for OrderedFloat {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for OrderedFloat {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

pub struct PathFinder<'a> {
    graph: &'a Graph,
}

impl<'a> PathFinder<'a> {
    pub fn new(graph: &'a Graph) -> Self {
        Self { graph }
    }

    pub fn shortest_path_weighted(&self, from: &NodeId, to: &NodeId) -> Option<CriticalPath> {
        let mut distances: HashMap<NodeId, f64> = HashMap::new();
        let mut predecessors: HashMap<NodeId, NodeId> = HashMap::new();
        let mut heap = BinaryHeap::new();

        distances.insert(from.clone(), 0.0);
        heap.push(Reverse((OrderedFloat(0.0), from.clone())));

        while let Some(Reverse((OrderedFloat(dist), current))) = heap.pop() {
            if current == *to {
                let mut path = Vec::new();
                let mut node = to.clone();
                path.push(node.clone());
                while let Some(prev) = predecessors.get(&node) {
                    path.push(prev.clone());
                    node = prev.clone();
                }
                path.reverse();
                return Some(CriticalPath {
                    path,
                    total_weight: dist,
                    risk_score: dist,
                });
            }

            if dist > *distances.get(&current).unwrap_or(&f64::INFINITY) {
                continue;
            }

            if let Some(neighbors) = self.graph.adjacency.get(&current) {
                for neighbor in neighbors {
                    let edge_weight = self
                        .graph
                        .edges
                        .values()
                        .find(|e| e.source == current && e.target == *neighbor)
                        .map(|e| e.weight)
                        .unwrap_or(1.0);

                    let new_dist = dist + edge_weight;
                    if new_dist < *distances.get(neighbor).unwrap_or(&f64::INFINITY) {
                        distances.insert(neighbor.clone(), new_dist);
                        predecessors.insert(neighbor.clone(), current.clone());
                        heap.push(Reverse((OrderedFloat(new_dist), neighbor.clone())));
                    }
                }
            }
        }

        None
    }

    pub fn all_paths(&self, from: &NodeId, to: &NodeId, max_depth: usize) -> Vec<CriticalPath> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        self.dfs(
            from,
            to,
            &mut visited,
            &mut paths,
            vec![from.clone()],
            max_depth,
            0,
        );
        paths
    }

    fn dfs(
        &self,
        current: &NodeId,
        target: &NodeId,
        visited: &mut HashSet<NodeId>,
        paths: &mut Vec<CriticalPath>,
        current_path: Vec<NodeId>,
        max_depth: usize,
        depth: usize,
    ) {
        if current == target {
            let total_weight: f64 = current_path
                .windows(2)
                .filter_map(|w| {
                    self.graph
                        .edges
                        .values()
                        .find(|e| e.source == w[0] && e.target == w[1])
                        .map(|e| e.weight)
                })
                .sum();
            paths.push(CriticalPath {
                path: current_path,
                total_weight,
                risk_score: total_weight,
            });
            return;
        }

        if depth >= max_depth {
            return;
        }

        visited.insert(current.clone());

        if let Some(neighbors) = self.graph.adjacency.get(current) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    let mut new_path = current_path.clone();
                    new_path.push(neighbor.clone());
                    self.dfs(
                        neighbor,
                        target,
                        visited,
                        paths,
                        new_path,
                        max_depth,
                        depth + 1,
                    );
                }
            }
        }

        visited.remove(current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph::{GraphEdge, GraphNode, NodeType};

    fn test_graph() -> Graph {
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
        g.add_node(GraphNode {
            id: "c".into(),
            node_type: NodeType::Entity,
            label: "C".into(),
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
        g.add_edge(GraphEdge {
            id: "e2".into(),
            source: "b".into(),
            target: "c".into(),
            edge_type: graph::EdgeType::DependsOn,
            weight: 2.0,
            properties: HashMap::new(),
            created_at: chrono::Utc::now(),
        })
        .unwrap();
        g
    }

    #[test]
    fn test_shortest_path() {
        let g = test_graph();
        let finder = PathFinder::new(&g);
        let path = finder
            .shortest_path_weighted(&"a".into(), &"c".into())
            .unwrap();
        assert_eq!(path.path, vec!["a", "b", "c"]);
        assert!((path.total_weight - 3.0).abs() < 0.01);
    }
}
