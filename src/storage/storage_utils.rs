use cairo_vm::Felt252;

use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};
use crate::storage::storage::{DbObject, Fact, HashFunctionType, Storage};

#[derive(Clone, Debug, PartialEq)]
pub struct SimpleLeafFact {
    pub value: Felt252,
}

impl SimpleLeafFact {
    pub fn new(value: Felt252) -> Self {
        Self { value }
    }

    pub fn empty() -> Self {
        Self::new(Felt252::ZERO)
    }
}

impl<S, H> Fact<S, H> for SimpleLeafFact
where
    H: HashFunctionType,
    S: Storage,
{
    fn hash(&self) -> Vec<u8> {
        self.serialize().unwrap()
    }
}

impl DbObject for SimpleLeafFact {}

impl Serializable for SimpleLeafFact {
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        Ok(self.value.to_bytes_be().to_vec())
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let value = Felt252::from_bytes_be_slice(data);
        Ok(Self { value })
    }
}

impl<S, H> LeafFact<S, H> for SimpleLeafFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn is_empty(&self) -> bool {
        self.value == Felt252::ZERO
    }
}
