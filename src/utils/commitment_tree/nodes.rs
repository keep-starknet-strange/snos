use bitvec::{prelude::Msb0, vec::BitVec};
use starknet::core::types::FieldElement;

use crate::{
    storage::{DBObject, Fact, HASH_BYTES},
    utils::hasher::{pedersen::PedersenHasher, HasherT},
};

use serde::{Deserialize, Serialize};

pub const EMPTY_NODE_HASH: [u8; 4] = HASH_BYTES;

pub const EMPTY_NODE_PREIMAGE_LENGTH: FieldElement = FieldElement::ZERO;

/// A node in a Binary Merkle-Patricia Tree graph.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum InnerNodeFact {
    /// A node that has not been fetched from storage yet.
    ///
    /// As such, all we know is its hash.
    Empty(EmptyNode),
    /// A branch node with exactly two children.
    Binary(BinaryNode),
    /// Describes a path connecting two other nodes.
    Edge(EdgeNode),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmptyNode {}

impl Fact for EmptyNode {
    fn _hash<H: HasherT>(&self) -> Vec<u8> {
        HASH_BYTES.to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BinaryNode {
    left: FieldElement,
    right: FieldElement,
}

impl BinaryNode {
    #[allow(unused)]
    pub(crate) fn preimage_length() -> FieldElement {
        FieldElement::TWO * FieldElement::from_byte_slice_be(HASH_BYTES.as_slice()).unwrap()
    }
}

impl Fact for BinaryNode {
    fn _hash<H: HasherT>(&self) -> Vec<u8> {
        EMPTY_NODE_HASH.to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EdgeNode {
    /// The root of the subtree containing data with value != 0.
    bottom_node: Box<InnerNodeFact>,
    /// The binary representation of the leaf index in the subtree that this node is root of.
    edge_path: BitVec<u8, Msb0>,
    /// The height of the edge node (the length of the path to the leaf).
    edge_length: usize,
}

impl EdgeNode {
    #[allow(unused)]
    pub(crate) fn preimage_length() -> FieldElement {
        FieldElement::TWO * FieldElement::from_byte_slice_be(HASH_BYTES.as_slice()).unwrap()
            + FieldElement::ONE
    }
}

impl Fact for EdgeNode {
    fn _hash<H: HasherT>(&self) -> Vec<u8> {
        // https://github.com/ferrilab/bitvec/issues/27
        let mut bv = self.edge_path.to_owned();
        bv.force_align();
        let bvec = bv.into_vec();

        let bottom_path_hash = H::hash_elements(
            self.bottom_node.hash().unwrap(),
            FieldElement::from_byte_slice_be(bvec.as_slice()).unwrap(),
        );

        // Add the edge length.
        [
            bottom_path_hash.to_bytes_be().as_slice(),
            self.edge_length.to_string().as_bytes(),
        ]
        .concat()
    }
}

impl InnerNodeFact {
    /// Returns true if the node represents an empty node -- this is defined as a node
    /// with the [FieldElement::ZERO].
    ///
    /// This can occur for the root node in an empty graph.
    pub fn is_empty(&self) -> bool {
        match self {
            InnerNodeFact::Empty(hash) => hash._hash::<PedersenHasher>() == HASH_BYTES,
            _ => false,
        }
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, InnerNodeFact::Binary(..))
    }

    /// Get the hash of an inner node fact.
    pub fn hash(&self) -> Option<FieldElement> {
        match self {
            InnerNodeFact::Empty(empty) => Some(
                FieldElement::from_byte_slice_be(empty._hash::<PedersenHasher>().as_slice())
                    .unwrap(),
            ),
            InnerNodeFact::Binary(binary) => Some(
                FieldElement::from_byte_slice_be(binary._hash::<PedersenHasher>().as_slice())
                    .unwrap(),
            ),
            InnerNodeFact::Edge(edge) => Some(
                FieldElement::from_byte_slice_be(edge._hash::<PedersenHasher>().as_slice())
                    .unwrap(),
            ),
        }
    }
}

/// DBObject implementations
/// Required for DBObject trait
/// Prefixes the key with the type of the object

impl DBObject for EmptyNode {
    fn db_key(suffix: Vec<u8>) -> Vec<u8> {
        patricia_node_db_key(suffix)
    }
}

impl DBObject for BinaryNode {
    fn db_key(suffix: Vec<u8>) -> Vec<u8> {
        patricia_node_db_key(suffix)
    }
}

impl DBObject for EdgeNode {
    fn db_key(suffix: Vec<u8>) -> Vec<u8> {
        patricia_node_db_key(suffix)
    }
}

fn patricia_node_db_key(suffix: Vec<u8>) -> Vec<u8> {
    let prefix: &[u8] = "patricia_node".as_bytes();
    let sep: &[u8] = ":".as_bytes();

    [prefix, sep, suffix.as_slice()].concat()
}
