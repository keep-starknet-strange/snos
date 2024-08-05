use std::ops::Deref;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet_api::core::{ClassHash, CompiledClassHash};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::StarknetApiError;
use starknet_types_core::felt::Felt;

const EMPTY_HASH: [u8; 32] = [0; 32];

/// Starknet hash type.
/// Encapsulates the result of hash functions and provides conversion functions to Cairo VM
/// and Starknet API types for convenience.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn empty() -> Self {
        Self::from_bytes_be(EMPTY_HASH)
    }

    pub fn from_bytes_be(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Builds a `Hash` from a bytes slice.
    /// The slice length must be <= 32.
    pub fn from_bytes_be_slice(bytes: &[u8]) -> Self {
        let mut array = [0u8; 32];
        let start = 32 - bytes.len();

        for (i, &byte) in bytes.iter().enumerate() {
            array[start + i] = byte;
        }

        Hash(array)
    }
}

impl PartialEq<[u8; 32]> for Hash {
    fn eq(&self, other: &[u8; 32]) -> bool {
        &self.0 == other
    }
}

impl Deref for Hash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Hash> for Felt {
    fn from(hash: Hash) -> Self {
        Felt::from_bytes_be(&hash.0)
    }
}

impl From<&Hash> for BigUint {
    fn from(hash: &Hash) -> Self {
        BigUint::from_bytes_be(&hash.0)
    }
}

impl From<&BigUint> for Hash {
    fn from(value: &BigUint) -> Self {
        // `BigUint.to_bytes_be()` only returns the minimum amount of bytes, so we need to use
        // `from_bytes_be_slice` for this conversion.
        Self::from_bytes_be_slice(&value.to_bytes_be())
    }
}

impl From<Felt> for Hash {
    fn from(value: Felt) -> Self {
        // This conversion is safe, BigUint is 32 bytes so this will always work.
        Self::from_bytes_be(value.to_bytes_be())
    }
}

impl TryFrom<Hash> for StarkFelt {
    type Error = StarknetApiError;

    fn try_from(hash: Hash) -> Result<Self, Self::Error> {
        Self::new(hash.0)
    }
}

impl TryFrom<Hash> for CompiledClassHash {
    type Error = StarknetApiError;

    fn try_from(hash: Hash) -> Result<Self, Self::Error> {
        Ok(Self(hash.try_into()?))
    }
}

impl TryFrom<Hash> for ClassHash {
    type Error = StarknetApiError;

    fn try_from(hash: Hash) -> Result<Self, Self::Error> {
        Ok(Self(hash.try_into()?))
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenericClassHash(Hash);

impl GenericClassHash {
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    pub fn from_bytes_be(bytes: [u8; 32]) -> Self {
        Self(Hash(bytes))
    }
}

impl From<ClassHash> for GenericClassHash {
    fn from(class_hash: ClassHash) -> Self {
        let hash = Hash::from_bytes_be_slice(class_hash.0.bytes());
        Self(hash)
    }
}

impl From<GenericClassHash> for ClassHash {
    fn from(class_hash: GenericClassHash) -> Self {
        let stark_hash = StarkHash::new_unchecked(class_hash.0.0);
        ClassHash(stark_hash)
    }
}

impl From<GenericClassHash> for CompiledClassHash {
    fn from(class_hash: GenericClassHash) -> Self {
        let stark_hash = StarkHash::new_unchecked(class_hash.0.0);
        CompiledClassHash(stark_hash)
    }
}

impl From<GenericClassHash> for Felt {
    fn from(class_hash: GenericClassHash) -> Self {
        Felt::from_bytes_be(&class_hash.0.0)
    }
}

impl Deref for GenericClassHash {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
