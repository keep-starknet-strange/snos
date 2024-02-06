//! pathfinder/crates/merkle-tree
use std::cell::RefCell;
use std::rc::Rc;

use bitvec::order::Msb0;
use bitvec::prelude::BitVec;
use bitvec::slice::BitSlice;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_crypto::FieldElement;

use super::trie::StarkHasher;
use crate::utils::felt_from_bits_api;

#[derive(Debug, Clone, PartialEq)]
pub enum TrieNode {
    Binary { left: StarkFelt, right: StarkFelt },
    Edge { child: StarkFelt, path: BitVec<u8, Msb0> },
}

impl TrieNode {
    pub fn hash<H: StarkHasher>(&self) -> StarkFelt {
        match self {
            TrieNode::Binary { left, right } => H::hash(left, right),
            TrieNode::Edge { child, path } => {
                let mut length = [0; 32];
                // Safe as len() is guaranteed to be <= 251
                length[31] = path.len() as u8;
                let path = felt_from_bits_api(path).unwrap();

                let length = FieldElement::from_bytes_be(&length).unwrap();
                let hash = FieldElement::from(H::hash(child, &path));
                StarkFelt::from(hash + length)
            }
        }
    }
}

/// A node in a Binary Merkle-Patricia Tree graph.
#[derive(Clone, Debug, PartialEq)]
pub enum InternalNode {
    /// A node that has not been fetched from storage yet.
    ///
    /// As such, all we know is its hash.
    Unresolved(u64),
    /// A branch node with exactly two children.
    Binary(BinaryNode),
    /// Describes a path connecting two other nodes.
    Edge(EdgeNode),
    /// A leaf node.
    Leaf,
}

/// Describes the [InternalNode::Binary] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryNode {
    /// The height of this node in the tree.
    pub height: usize,
    /// [Left](Direction::Left) child.
    pub left: Rc<RefCell<InternalNode>>,
    /// [Right](Direction::Right) child.
    pub right: Rc<RefCell<InternalNode>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EdgeNode {
    /// The starting height of this node in the tree.
    pub height: usize,
    /// The path this edge takes.
    pub path: BitVec<u8, Msb0>,
    /// The child of this node.
    pub child: Rc<RefCell<InternalNode>>,
}

/// Describes the direction a child of a [BinaryNode] may have.
///
/// Binary nodes have two children, one left and one right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

impl Direction {
    /// Inverts the [Direction].
    ///
    /// [Left] becomes [Right], and [Right] becomes [Left].
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn invert(self) -> Direction {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

impl From<bool> for Direction {
    fn from(tf: bool) -> Self {
        match tf {
            true => Direction::Right,
            false => Direction::Left,
        }
    }
}

impl From<Direction> for bool {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::Left => false,
            Direction::Right => true,
        }
    }
}

impl BinaryNode {
    /// Maps the key's bit at the binary node's height to a [Direction].
    ///
    /// This can be used to check which direction the key descibes in the context
    /// of this binary node i.e. which direction the child along the key's path would
    /// take.
    pub fn direction(&self, key: &BitSlice<u8, Msb0>) -> Direction {
        key[self.height].into()
    }

    /// Returns the [Left] or [Right] child.
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn get_child(&self, direction: Direction) -> Rc<RefCell<InternalNode>> {
        match direction {
            Direction::Left => self.left.clone(),
            Direction::Right => self.right.clone(),
        }
    }

    pub fn calculate_hash<H: StarkHasher>(left: &StarkFelt, right: &StarkFelt) -> StarkHash {
        H::hash(left, right)
    }
}

impl InternalNode {
    pub fn is_binary(&self) -> bool {
        matches!(self, InternalNode::Binary(..))
    }

    pub fn as_binary(&self) -> Option<&BinaryNode> {
        match self {
            InternalNode::Binary(binary) => Some(binary),
            _ => None,
        }
    }

    pub fn as_edge(&self) -> Option<&EdgeNode> {
        match self {
            InternalNode::Edge(edge) => Some(edge),
            _ => None,
        }
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, InternalNode::Leaf)
    }
}

impl EdgeNode {
    /// Returns true if the edge node's path matches the same path given by the key.
    pub fn path_matches(&self, key: &BitSlice<u8, Msb0>) -> bool {
        self.path == key[self.height..self.height + self.path.len()]
    }

    /// Returns the common bit prefix between the edge node's path and the given key.
    ///
    /// This is calculated with the edge's height taken into account.
    pub fn common_path(&self, key: &BitSlice<u8, Msb0>) -> &BitSlice<u8, Msb0> {
        let key_path = key.iter().skip(self.height);
        let common_length = key_path.zip(self.path.iter()).take_while(|(a, b)| a == b).count();

        &self.path[..common_length]
    }

    pub fn calculate_hash<H: StarkHasher>(child: &StarkFelt, path: &BitSlice<u8, Msb0>) -> StarkHash {
        let mut length = [0; 32];
        // Safe as len() is guaranteed to be <= 251
        length[31] = path.len() as u8;
        let length = FieldElement::from_bytes_be(&length).unwrap();
        let path = felt_from_bits_api(path).unwrap();

        StarkFelt::from(FieldElement::from(H::hash(child, &path)) + length)
    }
}
