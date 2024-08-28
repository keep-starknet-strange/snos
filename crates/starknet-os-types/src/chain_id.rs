use starknet_api::core::ChainId;
use starknet_types_core::felt::Felt;

/// Converts a ChainId object into a felt.
pub fn chain_id_to_felt(chain_id: &ChainId) -> Felt {
    Felt::from_bytes_be_slice(chain_id.to_string().as_bytes())
}
