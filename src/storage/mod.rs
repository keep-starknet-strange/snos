pub mod starknet;

use anyhow::Context;
use bitvec::{prelude::BitSlice, prelude::BitVec, prelude::Msb0};
use starknet_api::hash::StarkFelt;

use std::collections::HashMap;

use crate::utils::felt_from_bits;

/// Read-only storage used by the [Trie](crate::trie::Trie).
pub trait Storage {
    /// Returns the node stored at the given index.
    fn get(&self, index: u32) -> anyhow::Result<Option<StoredNode>>;
    /// Returns the hash of the node at the given index.
    fn hash(&self, index: u32) -> anyhow::Result<Option<StarkFelt>>;
    /// Returns the value of the leaf at the given path.
    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<StarkFelt>>;
}

#[derive(Clone, Debug)]
pub enum Node {
    Binary {
        left: Child,
        right: Child,
    },
    Edge {
        child: Child,
        path: BitVec<u8, Msb0>,
    },
    LeafBinary,
    LeafEdge {
        path: BitVec<u8, Msb0>,
    },
}

#[derive(Clone, Debug)]
pub enum Child {
    Id(u32),
    Hash(StarkFelt),
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoredNode {
    Binary { left: u32, right: u32 },
    Edge { child: u32, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

#[derive(Default, Debug)]
pub struct DefaultTrieStorage {
    nodes: HashMap<u32, (StarkFelt, StoredNode)>,
    leaves: HashMap<StarkFelt, StarkFelt>,
}

impl Storage for DefaultTrieStorage {
    fn get(&self, node: u32) -> anyhow::Result<Option<StoredNode>> {
        Ok(self.nodes.get(&node).map(|x| x.1.clone()))
    }

    fn hash(&self, node: u32) -> anyhow::Result<Option<StarkFelt>> {
        Ok(self.nodes.get(&node).map(|x| x.0))
    }

    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<StarkFelt>> {
        assert!(path.len() == 251);

        let key = felt_from_bits(path).context("Mapping path to felt")?;

        Ok(self.leaves.get(&key).cloned())
    }
}
