use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::ops::Sub;

use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};
use crate::storage::storage::HASH_BYTES;

pub type TreeIndex = BigUint;

#[derive(Debug, Clone, PartialEq, Default, Eq, Hash)]
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

#[derive(Debug, Copy, Clone, PartialEq, Default, Eq)]
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

#[derive(Debug, Copy, Clone, PartialEq, Default, Eq, Hash)]
pub struct Height(pub u64);

impl TryFrom<Felt252> for Height {
    type Error = MathError;

    fn try_from(value: Felt252) -> Result<Self, Self::Error> {
        let height = value.to_u64().ok_or(MathError::Felt252ToU64Conversion(Box::new(value)))?;
        Ok(Self(height))
    }
}

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

#[derive(Debug, Clone, PartialEq, Default, Eq, Hash)]
pub struct DescentStart(pub Height, pub NodePath);
#[derive(Debug, Clone, PartialEq, Default, Eq)]
pub struct DescentPath(pub Length, pub NodePath);
pub type DescentMap = HashMap<DescentStart, DescentPath>;
