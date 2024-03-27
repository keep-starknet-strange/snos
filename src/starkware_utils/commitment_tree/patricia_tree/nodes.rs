use cairo_vm::Felt252;
use num_bigint::BigUint;

use crate::starkware_utils::commitment_tree::base_types::{Length, NodePath};
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::inner_node_fact::InnerNodeFact;
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::EMPTY_NODE_HASH;
use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};
use crate::storage::storage::{DbObject, Fact, HashFunctionType, Storage, HASH_BYTES};

const PATRICIA_NODE_PREFIX: &[u8] = "patricia_node".as_bytes();

/// Represents the root of an empty (all leaves are 0) full binary tree.
pub struct EmptyNodeFact;

impl EmptyNodeFact {
    const PREIMAGE_LENGTH: usize = 0;
}

impl<S, H> InnerNodeFact<S, H> for EmptyNodeFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn to_tuple(&self) -> Vec<BigUint> {
        vec![]
    }
}

impl<S, H> Fact<S, H> for EmptyNodeFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn hash(&self) -> Vec<u8> {
        EMPTY_NODE_HASH.to_vec()
    }
}

impl DbObject for EmptyNodeFact {}

impl Serializable for EmptyNodeFact {
    fn prefix() -> Vec<u8> {
        PATRICIA_NODE_PREFIX.to_vec()
    }
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        Ok("".as_bytes().to_vec())
    }

    fn deserialize(_data: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self {})
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BinaryNodeError {
    #[allow(unused)]
    #[error("Left node hash is empty hash")]
    LeftNodeIsEmpty,
    #[allow(unused)]
    #[error("Right node hash is empty hash")]
    RightNodeIsEmpty,
}

/// A binary node in a Patricia-Merkle tree; this is a regular Merkle node.
pub struct BinaryNodeFact {
    pub left_node: Vec<u8>,
    pub right_node: Vec<u8>,
}

impl BinaryNodeFact {
    const PREIMAGE_LENGTH: usize = 2 * HASH_BYTES;

    #[allow(unused)]
    pub fn new(left_node: Vec<u8>, right_node: Vec<u8>) -> Result<Self, BinaryNodeError> {
        if left_node == EMPTY_NODE_HASH {
            return Err(BinaryNodeError::LeftNodeIsEmpty);
        }
        if right_node == EMPTY_NODE_HASH {
            return Err(BinaryNodeError::RightNodeIsEmpty);
        }

        Ok(Self { left_node, right_node })
    }
}

impl<S, H> InnerNodeFact<S, H> for BinaryNodeFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn to_tuple(&self) -> Vec<BigUint> {
        vec![BigUint::from_bytes_be(&self.left_node), BigUint::from_bytes_be(&self.right_node)]
    }
}

impl<S, H> Fact<S, H> for BinaryNodeFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn hash(&self) -> Vec<u8> {
        H::hash(&self.left_node, &self.right_node)
    }
}

impl DbObject for BinaryNodeFact {}

impl Serializable for BinaryNodeFact {
    fn prefix() -> Vec<u8> {
        PATRICIA_NODE_PREFIX.to_vec()
    }
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let serialized = self.left_node.iter().cloned().chain(self.right_node.iter().cloned()).collect();
        Ok(serialized)
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let expected_len = 2 * HASH_BYTES;
        if data.len() != 2 * HASH_BYTES {
            return Err(DeserializeError::LengthMismatch(expected_len, data.len()));
        }

        let mut hashes = data.chunks(HASH_BYTES);
        // Unwrapping is safe thanks to the length check above
        let left_node = hashes.next().unwrap().to_vec();
        let right_node = hashes.next().unwrap().to_vec();
        Ok(Self { left_node, right_node })
    }
}

/// A node in a Patricia-Merkle tree that represents the edge to a subtree that contains data
/// with value != 0.
/// Represented by three values embedding this information (elaborated below).
/// Note that the bottom_node cannot be an edge node itself (otherwise, they would have both been
/// fused to a bigger edge node).
pub struct EdgeNodeFact {
    /// The root of the subtree containing data with value != 0.
    pub bottom_node: Vec<u8>,
    /// The binary representation of the leaf index in the subtree that this node is root of.
    pub edge_path: NodePath,
    /// The height of the edge node (the length of the path to the leaf).
    pub edge_length: Length,
}

impl EdgeNodeFact {
    const PREIMAGE_LENGTH: usize = 2 * HASH_BYTES + 1;

    pub fn new(bottom_node: Vec<u8>, path: NodePath, length: Length) -> Result<Self, TreeError> {
        verify_path_value(&path, length)?;
        Ok(Self { bottom_node, edge_path: path, edge_length: length })
    }

    pub fn new_unchecked(bottom_node: Vec<u8>, path: NodePath, length: Length) -> Self {
        debug_assert!(verify_path_value(&path, length).is_ok());
        Self { bottom_node, edge_path: path, edge_length: length }
    }
}

impl<S, H> InnerNodeFact<S, H> for EdgeNodeFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn to_tuple(&self) -> Vec<BigUint> {
        vec![BigUint::from(self.edge_length.0), self.edge_path.0.clone(), BigUint::from_bytes_be(&self.bottom_node)]
    }
}

impl<S, H> Fact<S, H> for EdgeNodeFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn hash(&self) -> Vec<u8> {
        hash_edge::<H>(&self.bottom_node, self.edge_path.clone(), self.edge_length)
    }
}

impl DbObject for EdgeNodeFact {}

impl Serializable for EdgeNodeFact {
    fn prefix() -> Vec<u8> {
        PATRICIA_NODE_PREFIX.to_vec()
    }

    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        serialize_edge(&self.bottom_node, self.edge_path.clone(), self.edge_length)
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let expected_len = 2 * HASH_BYTES + 1;
        if data.len() != expected_len {
            return Err(DeserializeError::LengthMismatch(expected_len, data.len()));
        }

        // Unwrapping is safe thanks to the length check above
        let mut data_iter = data.chunks(HASH_BYTES);
        let bottom = data_iter.next().unwrap();
        let path = NodePath::deserialize(data_iter.next().unwrap())?;
        let length = Length::deserialize(data_iter.next().unwrap())?;

        Ok(Self::new_unchecked(bottom.to_vec(), path, length))
    }
}

pub fn verify_path_value(path: &NodePath, length: Length) -> Result<(), TreeError> {
    // TODO: NodePath probably needs to be defined as BigUint
    if path.0 >= (BigUint::from(1u64) << length.0) {
        return Err(TreeError::InvalidEdgePath(path.clone(), length));
    }
    Ok(())
}

fn serialize_edge(bottom: &[u8], path: NodePath, length: Length) -> Result<Vec<u8>, SerializeError> {
    let path_bytes = path.serialize()?;
    let length_bytes = length.serialize()?;

    let serialized = [bottom, &path_bytes, &length_bytes].iter().flat_map(|v| v.iter().cloned()).collect();
    Ok(serialized)
}

fn hash_edge<H: HashFunctionType>(bottom: &[u8], path: NodePath, length: Length) -> Vec<u8> {
    let bottom_path_hash = H::hash(bottom, path.0.to_bytes_be().as_ref());

    // Warning: this may be too small?
    let hash_value = Felt252::from_bytes_be_slice(&bottom_path_hash) + length.0;
    hash_value.to_bytes_be().to_vec()
}

pub enum PatriciaNodeFact {
    Empty(EmptyNodeFact),
    Binary(BinaryNodeFact),
    Edge(EdgeNodeFact),
}

impl Serializable for PatriciaNodeFact {
    fn prefix() -> Vec<u8> {
        PATRICIA_NODE_PREFIX.to_vec()
    }

    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        match self {
            Self::Empty(empty) => empty.serialize(),
            Self::Binary(binary) => binary.serialize(),
            Self::Edge(edge) => edge.serialize(),
        }
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let node = match data.len() {
            EmptyNodeFact::PREIMAGE_LENGTH => Self::Empty(EmptyNodeFact::deserialize(data)?),
            BinaryNodeFact::PREIMAGE_LENGTH => Self::Binary(BinaryNodeFact::deserialize(data)?),
            EdgeNodeFact::PREIMAGE_LENGTH => Self::Edge(EdgeNodeFact::deserialize(data)?),
            other => {
                return Err(DeserializeError::NoVariantWithLength(other));
            }
        };
        Ok(node)
    }
}

impl<S, H> Fact<S, H> for PatriciaNodeFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn hash(&self) -> Vec<u8> {
        match self {
            Self::Empty(empty) => <EmptyNodeFact as Fact<S, H>>::hash(empty),
            Self::Binary(binary) => <BinaryNodeFact as Fact<S, H>>::hash(binary),
            Self::Edge(edge) => <EdgeNodeFact as Fact<S, H>>::hash(edge),
        }
    }
}

impl DbObject for PatriciaNodeFact {}

impl<S, H> InnerNodeFact<S, H> for PatriciaNodeFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn to_tuple(&self) -> Vec<BigUint> {
        match self {
            Self::Empty(empty) => <EmptyNodeFact as InnerNodeFact<S, H>>::to_tuple(empty),
            Self::Binary(binary) => <BinaryNodeFact as InnerNodeFact<S, H>>::to_tuple(binary),
            Self::Edge(edge) => <EdgeNodeFact as InnerNodeFact<S, H>>::to_tuple(edge),
        }
    }
}
