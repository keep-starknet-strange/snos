use cairo_vm::types::errors::math_errors::MathError;
use starknet_crypto::{poseidon_hash, poseidon_hash_many, FieldElement};
use starknet_os_types::hash::Hash;

use crate::storage::storage::HashFunctionType;

#[derive(Clone, Debug, PartialEq)]
pub struct PoseidonHash;

impl HashFunctionType for PoseidonHash {
    fn hash(x: &[u8], y: &[u8]) -> Hash {
        let x_felt = FieldElement::from_byte_slice_be(x).unwrap();
        let y_felt = FieldElement::from_byte_slice_be(y).unwrap();

        Hash::from_bytes_be(poseidon_hash(x_felt, y_felt).to_bytes_be())
    }
}

/// A wrapper around `poseidon_hash_many` that takes and returns bytes.
pub fn poseidon_hash_many_bytes(msgs: &[&[u8]]) -> Result<Hash, MathError> {
    let field_elements: Result<Vec<_>, _> = msgs.iter().map(|elem| FieldElement::from_byte_slice_be(elem)).collect();
    let field_elements = field_elements.map_err(|_| MathError::ByteConversionError)?;
    let result = poseidon_hash_many(&field_elements);

    Ok(Hash::from_bytes_be(result.to_bytes_be()))
}
