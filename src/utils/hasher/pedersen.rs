use super::HasherT;
use cairo_felt::Felt252;
/// The Pedersen hasher.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PedersenHasher;

/// The Pedersen hasher implementation.
impl HasherT for PedersenHasher {
    /// The Pedersen hash function.
    /// # Arguments
    /// * `data` - The data to hash.
    /// # Returns
    /// The hash of the data.
    fn hash_bytes(data: &[u8]) -> Felt252 {
        // Calculate the number of 31-byte chunks we'll need, rounding up.
        // (1 byte is used padding to prevent the value of field from being greater than the field's
        // modulus) TODO: It is need a way to truncate bytes to fit into values smaller than modular
        // (for optimization)
        const CHUNK_SIZE: usize = 31;
        let mut hash_value = Felt252::new(0);

        for chunk in data.chunks(CHUNK_SIZE) {
            // We know that the chunk size is 31 and the value can not
            // overflow than the field's modulus value. In more detail, the Felt252 Maximum value is 2^251
            // + 17 * 2^192. So the chunk (31 bytes is 248 bits) is smaller than the maximum value (== 2^248 - 1
            // < 2^251 + 17 * 2^192).
            let _field_element = Felt252::from_bytes_be(chunk);
            // TODO: use lambdaworks
            // hash_value = pedersen_hash(&hash_value, &field_element);
            hash_value = Felt252::new(0);
        }

        hash_value
    }

    #[inline(always)]
    fn hash_elements(_a: Felt252, _b: Felt252) -> Felt252 {
        // TODO: use impl from lambdaworks pedersen_hash(&a, &b)
        Felt252::new(0)
    }

    /// Compute hash on elements, taken from [starknet-rs](https://github.com/xJonathanLEI/starknet-rs/blob/master/starknet-core/src/crypto.rs#L25) pending a no_std support.
    ///
    /// # Arguments
    ///
    /// * `elements` - The elements to hash.
    ///
    /// # Returns
    ///
    /// h(h(h(h(0, data\[0\]), data\[1\]), ...), data\[n-1\]), n).
    #[inline]
    fn compute_hash_on_elements(_elements: &[Felt252]) -> Felt252 {
        // TODO: use impl from lambdaworks compute_hash_on_elements(elements)
        Felt252::new(0)
    }
}
