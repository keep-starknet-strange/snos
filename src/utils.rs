use anyhow::anyhow;
use bitvec::{prelude::BitSlice, prelude::BitVec, prelude::Msb0, view::BitView};

use starknet_api::core::{ClassHash, Nonce, PatriciaKey};
use starknet_api::hash::{pedersen_hash, StarkFelt, StarkHash};

/// Calculates the contract state hash from its preimage.
pub fn calculate_contract_state_hash(
    class_hash: ClassHash,
    contract_root: PatriciaKey,
    nonce: Nonce,
) -> StarkHash {
    const CONTRACT_STATE_HASH_VERSION: StarkFelt = StarkFelt::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), nonce), CONTRACT_STATE_HASH_VERSION)
    let hash = pedersen_hash(&class_hash.0, &contract_root.key());
    let hash = pedersen_hash(&hash, &nonce.0);
    pedersen_hash(&hash, &CONTRACT_STATE_HASH_VERSION)
}

pub fn felt_from_bits(bits: &BitSlice<u8, Msb0>) -> anyhow::Result<StarkFelt> {
    if bits.len() > 251 {
        return Err(anyhow!("overflow: > 251 bits"));
    }

    let mut bytes = [0u8; 32];
    bytes.view_bits_mut::<Msb0>()[256 - bits.len()..].copy_from_bitslice(bits);

    StarkFelt::new(bytes).map_err(|e| anyhow!(format!("{e}")))
}

pub fn bits_from_felt(felt: StarkFelt) -> BitVec<u8, Msb0> {
    felt.bytes().view_bits::<Msb0>()[5..].to_bitvec()
}
