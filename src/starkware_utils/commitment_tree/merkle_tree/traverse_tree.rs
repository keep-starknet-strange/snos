use std::collections::VecDeque;

use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::storage::storage::{HashFunctionType, Storage};

pub trait TreeTraverser<'trav, S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    type NodeType;

    async fn get_children(&mut self, node: &Self::NodeType) -> Result<Vec<Self::NodeType>, TreeError>;
}

/// Traverses a tree as follows:
/// 1. Starts by calling get_children_callback(root). This function should return the children of
/// root in the tree that you want to visit.
/// 2. Call get_children_callback() on each of the children to get more nodes, and repeat.
///
/// The order of execution is not guaranteed, except that it is more similar to DFS than BFS in
/// terms of memory consumption.
pub async fn traverse_tree<'tree, S, H, LF, N, TT>(traverser: &mut TT, root: N) -> Result<(), TreeError>
where
    S: Storage + Sync,
    H: HashFunctionType + Sync,
    LF: LeafFact<S, H>,
    N: Sync,
    TT: TreeTraverser<'tree, S, H, LF, NodeType = N> + Send,
{
    // The Python implementation (https://github.com/starkware-libs/cairo-lang/blob/4e233516f52477ad158bc81a86ec2760471c1b65/src/starkware/starkware_utils/commitment_tree/merkle_tree/traverse_tree.py#L16)
    // uses an async priority queue that ultimately should look like depth-first search (DFS).
    // For now, we implement it as a single-thread DFS out of simplicity.

    let mut queue = VecDeque::new();
    queue.push_back(root);

    while let Some(node) = queue.pop_front() {
        let children = traverser.get_children(&node).await?;
        for child in children {
            queue.push_back(child);
        }
    }

    Ok(())
}
