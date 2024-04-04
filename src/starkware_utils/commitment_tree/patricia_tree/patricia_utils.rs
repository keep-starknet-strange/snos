//! Starkware's Merkle-Patricia tree is based on this representation:
//! Each node can be one of these:
//! 1. Empty, with value of 0.
//! 2. Edge node, with value of hash(bottom_node, edge_path) + edge_length.
//! 3. Binary node, with value of hash(left, right).
//!
//! An edge node represents a path in a maximal subtree with a single non-empty node.
//! for example, the following is encoded
//! #    0
//! #  0   0
//! # 0 h 0 0
//! as
//! (2, 1, h)
//!
//! If that maximal subtree is trivial, it is encoded as (0, 0, h) where h is the value of
//! the leaf or the hash corresponding to that subtree.
#![cfg(test)]

use std::collections::HashMap;

use cairo_vm::Felt252;
use num_traits::ToPrimitive;

use crate::storage::storage::HashFunctionType;

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    bottom: Felt252,
    path: Felt252,
    length: Felt252,
}

impl Node {
    fn empty() -> Self {
        Self { bottom: Felt252::ZERO, path: Felt252::ZERO, length: Felt252::ZERO }
    }

    fn is_empty(&self) -> bool {
        self == &Self::empty()
    }
}

fn hash_node<H: HashFunctionType>(node: Node, preimage: &mut HashMap<Felt252, Node>) -> Felt252 {
    if node.length == Felt252::ZERO {
        return node.bottom;
    }

    let result = H::hash_felts(node.bottom, node.path) + node.length;
    preimage.insert(result, node);
    result
}

/// Computes the root of a Merkle-Patricia tree from the list of all the leaves.
/// This function is not efficient, and should only be used for tests.
/// Returns:
/// * The hash of the root.
/// * A preimage dict from hash to either (left, right) for binary nodes, or (edge_length,
///   edge_path, bottom_node) for edge nodes.
/// * node_at_path - a dictionary from height, path to a node encoding triplet.
pub fn compute_patricia_from_leaves_for_test<H: HashFunctionType>(
    leaves: &[Felt252],
) -> (Felt252, HashMap<Felt252, Node>, HashMap<(Felt252, Felt252), Node>)
where
{
    assert!(leaves.len().is_power_of_two());

    let mut preimage: HashMap<Felt252, Node> = HashMap::new();
    let mut node_at_path: HashMap<(Felt252, Felt252), Node> = HashMap::new();

    // All the nodes are stored as edge nodes representation of non-negative length:
    // (length, path, hash of bottom node).
    let mut layer: Vec<Node> =
        leaves.iter().copied().map(|leaf| Node { bottom: leaf, path: Felt252::ZERO, length: Felt252::ZERO }).collect();
    let mut height = Felt252::ZERO;

    while layer.len() > 1 {
        let values: Vec<_> = layer.iter().map(|node| node.bottom.to_biguint()).collect();
        println!("{:?}", values);
        for (i, x) in layer.iter().enumerate() {
            node_at_path.insert((height, Felt252::from(i)), x.clone());
        }

        let mut next_layer = vec![];
        for chunk in layer.chunks_exact(2) {
            let left = &chunk[0];
            let right = &chunk[1];

            let next_node = if left.is_empty() && right.is_empty() {
                Node::empty()
            } else if left.is_empty() {
                Node {
                    bottom: right.bottom,
                    path: right.path + Felt252::from(1 << right.length.to_u64().unwrap()),
                    length: right.length + 1,
                }
            } else if right.is_empty() {
                Node { bottom: left.bottom, path: left.path, length: left.length + 1 }
            } else {
                Node {
                    bottom: H::hash_felts(
                        hash_node::<H>(left.clone(), &mut preimage),
                        hash_node::<H>(right.clone(), &mut preimage),
                    ),
                    path: Felt252::ZERO,
                    length: Felt252::ZERO,
                }
            };
            next_layer.push(next_node);
        }
        layer = next_layer;
        height = height + 1;
    }

    let root = layer[0].clone();
    node_at_path.insert((height, Felt252::ZERO), root.clone());
    let root_hash = hash_node::<H>(root, &mut preimage);

    (root_hash, preimage, node_at_path)
}

#[cfg(test)]
mod tests {
    // Sanity tests comparing results generated with the Python implementation.
    use super::*;
    use crate::crypto::pedersen::PedersenHash;

    #[test]
    fn test_hash_node() {
        let expected_hash =
            Felt252::from_dec_str("1321142004022994845681377299801403567378503530250467610343381590909832171181")
                .unwrap();

        let mut preimage = HashMap::new();
        let node = Node { bottom: Felt252::ONE, path: Felt252::ONE, length: Felt252::ONE };
        let hash = hash_node::<PedersenHash>(node, &mut preimage);

        assert_eq!(hash, expected_hash);
        println!("{}", hash);
    }

    #[test]
    fn test_compute_root_two_leaves() {
        let expected_root_hash =
            Felt252::from_dec_str("2592987851775965742543459319508348457290966253241455514226127639100457844774")
                .unwrap();

        let (root_hash, _, _) = compute_patricia_from_leaves_for_test::<PedersenHash>(&[Felt252::ONE, Felt252::TWO]);
        assert_eq!(root_hash, expected_root_hash);
    }

    #[test]
    fn test_compute_root_eight_leaves() {
        let expected_root_hash =
            Felt252::from_dec_str("3206463776576638577137066366647706846226995569381452684870955234387294439611")
                .unwrap();

        let leaves = vec![
            Felt252::ZERO,
            Felt252::from(12),
            Felt252::ZERO,
            Felt252::ZERO,
            Felt252::from(1000),
            Felt252::ZERO,
            Felt252::from(30),
            Felt252::ZERO,
        ];
        let (root_hash, _, _) = compute_patricia_from_leaves_for_test::<PedersenHash>(&leaves);
        println!("{}", root_hash);

        assert_eq!(root_hash, expected_root_hash);
    }
}
