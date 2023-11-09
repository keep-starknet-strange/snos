use std::collections::HashMap;

use anyhow::Context;
use bitvec::prelude::{BitSlice, BitVec, Msb0};
use starknet_api::hash::StarkFelt;

use super::trie::{MerkleTrie, StarkHasher};
use crate::utils::felt_from_bits_api;

/// Read-only storage used by the [Trie](crate::trie::Trie).
pub trait Storage {
    /// Returns the node stored at the given index.
    fn get(&self, index: u64) -> anyhow::Result<Option<StoredNode>>;
    /// Returns the hash of the node at the given index.
    fn hash(&self, index: u64) -> anyhow::Result<Option<StarkFelt>>;
    /// Returns the value of the leaf at the given path.
    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<StarkFelt>>;
}

#[derive(Clone, Debug)]
pub enum Node {
    Binary { left: Child, right: Child },
    Edge { child: Child, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

#[derive(Clone, Debug)]
pub enum Child {
    Id(u64),
    Hash(StarkFelt),
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoredNode {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

#[derive(Default, Debug, Clone)]
pub struct TrieStorage {
    nodes: HashMap<u64, (StarkFelt, StoredNode)>,
    leaves: HashMap<StarkFelt, StarkFelt>,
    pub root_map: HashMap<StarkFelt, (StarkFelt, u64)>,
}

impl Storage for TrieStorage {
    fn get(&self, node: u64) -> anyhow::Result<Option<StoredNode>> {
        Ok(self.nodes.get(&node).map(|x| x.1.clone()))
    }

    fn hash(&self, node: u64) -> anyhow::Result<Option<StarkFelt>> {
        Ok(self.nodes.get(&node).map(|x| x.0))
    }

    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<StarkFelt>> {
        assert!(path.len() == 251);

        let key = felt_from_bits_api(path).context("Mapping path to felt")?;

        Ok(self.leaves.get(&key).cloned())
    }
}

impl TrieStorage {
    pub fn commit_and_persist<H: StarkHasher, const HEIGHT: usize>(
        &mut self,
        tree: MerkleTrie<H, HEIGHT>,
        root_key: StarkFelt,
    ) -> (StarkFelt, u64) {
        for (key, value) in &tree.leaves {
            let key = felt_from_bits_api(key).unwrap();
            self.leaves.insert(key, *value);
        }

        let update = tree.commit(self).unwrap();

        let mut indices = HashMap::new();
        let mut idx = self.nodes.len();
        for hash in update.nodes.keys() {
            indices.insert(*hash, idx as u64);
            idx += 1;
        }

        for (hash, node) in update.nodes {
            let node = match node {
                Node::Binary { left, right } => {
                    let left = match left {
                        Child::Id(idx) => idx,
                        Child::Hash(hash) => *indices.get(&hash).expect("Left child should have an index"),
                    };

                    let right = match right {
                        Child::Id(idx) => idx,
                        Child::Hash(hash) => *indices.get(&hash).expect("Right child should have an index"),
                    };

                    StoredNode::Binary { left, right }
                }
                Node::Edge { child, path } => {
                    let child = match child {
                        Child::Id(idx) => idx,
                        Child::Hash(hash) => *indices.get(&hash).expect("Child should have an index"),
                    };

                    StoredNode::Edge { child, path }
                }
                Node::LeafBinary => StoredNode::LeafBinary,
                Node::LeafEdge { path } => StoredNode::LeafEdge { path },
            };

            self.nodes.insert(*indices.get(&hash).unwrap(), (hash, node));
        }

        let index = *indices.get(&update.root).unwrap();

        self.root_map.insert(root_key, (update.root, index));

        (update.root, index)
    }
}
