//! Chain ID conversion utilities for Starknet.

use starknet_api::core::ChainId;
use starknet_types_core::felt::Felt;

/// Converts a `ChainId` object into a `Felt`.
///
/// This function serializes the chain ID as a string and converts it to a felt
/// using big-endian byte representation.
///
/// # Arguments
///
/// * `chain_id` - The chain ID to convert
///
/// # Returns
///
/// A `Felt` representing the chain ID
///
/// # Example
///
/// ```rust
/// use starknet_os_types::chain_id::chain_id_to_felt;
/// use starknet_api::core::ChainId;
///
/// let chain_id = ChainId::Sepolia;
/// let felt = chain_id_to_felt(&chain_id);
/// ```
pub fn chain_id_to_felt(chain_id: &ChainId) -> Felt {
    Felt::from_bytes_be_slice(chain_id.to_string().as_bytes())
}

/// Builds a `ChainId` from a `Felt`.
///
/// This function reads the felt as ASCII bytes, skipping leading zeroes.
/// The felt is interpreted as a UTF-8 string representation of the chain ID.
///
/// # Arguments
///
/// * `felt` - The felt to convert to a chain ID
///
/// # Returns
///
/// A `ChainId` parsed from the felt
///
/// # Example
///
/// ```rust
/// use starknet_os_types::chain_id::chain_id_from_felt;
/// use starknet_api::core::ChainId;
/// use starknet_types_core::felt::Felt;
///
/// let felt = Felt::from_dec_str("393402133025997798000961").unwrap();
/// let chain_id = chain_id_from_felt(felt);
/// assert_eq!(chain_id, ChainId::Sepolia);
/// ```
pub fn chain_id_from_felt(felt: Felt) -> ChainId {
    // Skip leading zeroes to get the actual chain ID bytes
    let chain_id_bytes: Vec<u8> = felt.to_bytes_be().into_iter().skip_while(|&byte| byte == 0u8).collect();

    // Convert bytes to string and parse as chain ID
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

    #[test]
    fn test_chain_id_to_felt_roundtrip() {
        let original_chain_id = ChainId::Sepolia;
        let felt = chain_id_to_felt(&original_chain_id);
        let roundtrip_chain_id = chain_id_from_felt(felt);
        assert_eq!(original_chain_id, roundtrip_chain_id);
    }

    #[test]
    fn test_mainnet_chain_id() {
        let chain_id_felt = Felt::from_dec_str("23448594291968334").unwrap();
        let chain_id = chain_id_from_felt(chain_id_felt);
        assert_eq!(chain_id, ChainId::Mainnet);
    }
}
