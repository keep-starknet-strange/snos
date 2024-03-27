use std::fmt::{Display, Formatter};
use std::ops::Sub;

use num_bigint::BigUint;

use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};
use crate::storage::storage::HASH_BYTES;

pub type TreeIndex = BigUint;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct NodePath(pub BigUint);

impl Display for NodePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serializable for NodePath {
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let bytes = self.0.to_bytes_be();
        let mut serialized = vec![0; HASH_BYTES - bytes.len()];
        serialized.extend(bytes);
        Ok(serialized)
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self(BigUint::from_bytes_be(data)))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub struct Length(pub u64);

impl Sub<u64> for Length {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl Display for Length {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serializable for Length {
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        if self.0 > u8::MAX as u64 {
            return Err(SerializeError::ValueTooLong(1));
        }
        Ok(vec![self.0 as u8])
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self(data[0] as u64))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub struct Height(pub u64);

impl Sub<u64> for Height {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl Display for Height {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
