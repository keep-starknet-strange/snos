use starknet_api::core::ChainId;
use starknet_types_core::felt::Felt;

/// Converts a ChainId object into a felt.
pub fn chain_id_to_felt(chain_id: &ChainId) -> Felt {
    Felt::from_bytes_be_slice(chain_id.to_string().as_bytes())
}

/// Builds a ChainId from a felt.
/// This function reads the felt as ASCII bytes. Leading zeroes are skipped.
pub fn chain_id_from_felt(felt: Felt) -> ChainId {
    // Skip leading zeroes
    let chain_id_bytes: Vec<_> = felt.to_bytes_be().into_iter().skip_while(|byte| *byte == 0u8).collect();
    let chain_id_str = String::from_utf8_lossy(&chain_id_bytes);
    ChainId::from(chain_id_str.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id_from_felt() {
        let chain_id_felt = Felt::from_dec_str("393402133025997798000961").unwrap();
        let chain_id = chain_id_from_felt(chain_id_felt);
        assert_eq!(chain_id, ChainId::Sepolia);
    }
}
