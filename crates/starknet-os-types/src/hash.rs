use std::ops::Deref;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet_api::core::{ClassHash, CompiledClassHash};
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

impl From<Hash> for CompiledClassHash {
    fn from(hash: Hash) -> Self {
        Self(hash.into())
    }
}

impl From<Hash> for ClassHash {
    fn from(hash: Hash) -> Self {
        Self(hash.into())
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
        let hash = Hash(class_hash.0.to_bytes_be());
        Self(hash)
    }
}

impl From<GenericClassHash> for ClassHash {
    fn from(class_hash: GenericClassHash) -> Self {
        class_hash.0.into()
    }
}

impl From<GenericClassHash> for CompiledClassHash {
    fn from(class_hash: GenericClassHash) -> Self {
        class_hash.0.into()
    }
}

impl From<GenericClassHash> for Felt {
    fn from(class_hash: GenericClassHash) -> Self {
        Felt::from_bytes_be(&class_hash.0 .0)
    }
}

impl Deref for GenericClassHash {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
