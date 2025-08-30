//! Hash types and utilities for Starknet.

use std::ops::Deref;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet_api::core::{ClassHash, CompiledClassHash};
use starknet_types_core::felt::Felt;

/// The size of a hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Empty hash value (all zeros).
const EMPTY_HASH: [u8; HASH_SIZE] = [0; HASH_SIZE];

/// A 32-byte hash value used throughout the Starknet ecosystem.
///
/// This type encapsulates the result of hash functions and provides conversion
/// functions to various Starknet types for convenience. The hash is stored
/// internally as a 32-byte array in big-endian format.
///
/// # Examples
///
/// ```rust
/// use starknet_os_types::hash::Hash;
///
/// // Create an empty hash
/// let empty_hash = Hash::empty();
///
/// // Create from bytes
/// let bytes = [1u8; 32];
/// let hash = Hash::from_bytes_be(bytes);
///
/// // Create from a slice
/// let slice = &[1u8, 2u8, 3u8];
/// let hash = Hash::from_bytes_be_slice(slice);
/// ```
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    /// Creates an empty hash (all zeros).
    ///
    /// # Returns
    ///
    /// A hash with all bytes set to zero.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_bytes_be(EMPTY_HASH)
    }

    /// Creates a hash from a 32-byte array in big-endian format.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32 bytes representing the hash
    ///
    /// # Returns
    ///
    /// A new `Hash` instance.
    #[must_use]
    pub fn from_bytes_be(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a hash from a byte slice.
    ///
    /// The slice is padded with leading zeros if it's shorter than 32 bytes.
    /// If the slice is longer than 32 bytes, only the last 32 bytes are used.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice to convert to a hash
    ///
    /// # Returns
    ///
    /// A new `Hash` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::hash::Hash;
    ///
    /// let short_slice = &[1u8, 2u8, 3u8];
    /// let hash = Hash::from_bytes_be_slice(short_slice);
    /// // The hash will be padded with leading zeros
    /// ```
    #[must_use]
    pub fn from_bytes_be_slice(bytes: &[u8]) -> Self {
        let mut array = [0u8; HASH_SIZE];
        let start = HASH_SIZE.saturating_sub(bytes.len());
        let copy_len = bytes.len().min(HASH_SIZE);

        array[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
        Hash(array)
    }

    /// Returns the hash as a byte array.
    ///
    /// # Returns
    ///
    /// The 32-byte array representing this hash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    /// Returns the hash as a byte slice.
    ///
    /// # Returns
    ///
    /// A slice containing the hash bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<[u8; HASH_SIZE]> for Hash {
    fn eq(&self, other: &[u8; HASH_SIZE]) -> bool {
        self.0 == *other
    }
}

impl PartialEq<[u8]> for Hash {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.as_slice() == other
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
        // `BigUint.to_bytes_be()` only returns the minimum number of bytes, so we need to use
        // `from_bytes_be_slice` for this conversion.
        Self::from_bytes_be_slice(&value.to_bytes_be())
    }
}

impl From<Felt> for Hash {
    fn from(value: Felt) -> Self {
        // This conversion is safe, Felt is 32 bytes, so this will always work.
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

/// A generic class hash that can be used across different contract class types.
///
/// This type wraps a `Hash` and provides conversion methods to various Starknet
/// class hash types. It serves as a unified representation for class hashes
/// regardless of the underlying contract class format.
///
/// # Examples
///
/// ```rust
/// use starknet_os_types::hash::{Hash, GenericClassHash};
/// use starknet_api::core::ClassHash;
///
/// let hash = Hash::from_bytes_be([1u8; 32]);
/// let class_hash = GenericClassHash::new(hash);
///
/// // Convert to Starknet API types
/// let starknet_class_hash: ClassHash = class_hash.into();
/// ```
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenericClassHash(Hash);

impl GenericClassHash {
    /// Creates a new generic class hash from a `Hash`.
    ///
    /// # Arguments
    ///
    /// * `hash` - The underlying hash value
    ///
    /// # Returns
    ///
    /// A new `GenericClassHash` instance.
    #[must_use]
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Creates a generic class hash from a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32 bytes representing the class hash
    ///
    /// # Returns
    ///
    /// A new `GenericClassHash` instance.
    #[must_use]
    pub fn from_bytes_be(bytes: [u8; HASH_SIZE]) -> Self {
        Self(Hash::from_bytes_be(bytes))
    }

    /// Returns the underlying hash value.
    ///
    /// # Returns
    ///
    /// A reference to the underlying `Hash`.
    #[must_use]
    pub fn as_hash(&self) -> &Hash {
        &self.0
    }
}

impl From<ClassHash> for GenericClassHash {
    fn from(class_hash: ClassHash) -> Self {
        let hash = Hash::from_bytes_be(class_hash.0.to_bytes_be());
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
        Felt::from_bytes_be(&class_hash.0.0)
    }
}

impl Deref for GenericClassHash {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_creation() {
        let empty = Hash::empty();
        assert_eq!(empty.as_bytes(), &[0u8; 32]);

        let bytes = [1u8; 32];
        let hash = Hash::from_bytes_be(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash_from_slice() {
        let short_slice = &[1u8, 2u8, 3u8];
        let hash = Hash::from_bytes_be_slice(short_slice);

        let expected = {
            let mut arr = [0u8; 32];
            arr[29..32].copy_from_slice(short_slice);
            arr
        };
        assert_eq!(hash.as_bytes(), &expected);
    }

    #[test]
    fn test_hash_equality() {
        let hash1 = Hash::from_bytes_be([1u8; 32]);
        let hash2 = Hash::from_bytes_be([1u8; 32]);
        let hash3 = Hash::from_bytes_be([2u8; 32]);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1, [1u8; 32]);
    }

    #[test]
    fn test_generic_class_hash() {
        let hash = Hash::from_bytes_be([1u8; 32]);
        let class_hash = GenericClassHash::new(hash);

        assert_eq!(class_hash.as_hash(), &hash);

        let bytes = [2u8; 32];
        let class_hash2 = GenericClassHash::from_bytes_be(bytes);
        assert_eq!(class_hash2.as_hash().as_bytes(), &bytes);
    }
}
