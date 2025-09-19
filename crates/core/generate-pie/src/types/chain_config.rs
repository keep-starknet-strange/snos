use crate::constants::DEFAULT_SEPOLIA_STRK_FEE_TOKEN;
use crate::error::PieGenerationError;
use starknet_api::core::{ChainId, ContractAddress};
use starknet_types_core::felt::Felt;

/// Configuration for chain-specific settings.
///
/// This struct contains all the chain-specific configuration needed for PIE generation,
/// including the chain ID, fee token addresses, and whether the chain is an L3.
///
/// # Examples
///
/// ```rust
/// use generate_pie::ChainConfig;
/// use starknet_api::core::ChainId;
///
/// // Use default Sepolia configuration
/// let config = ChainConfig::default();
///
/// // Create custom configuration
/// let custom_config = ChainConfig {
///     chain_id: ChainId::Mainnet,
///     strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked("0x123...")).unwrap(),
///     is_l3: true,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ChainConfig {
    /// The chain ID for the target Starknet network.
    pub chain_id: ChainId,
    /// The address of the STRK fee token contract.
    pub strk_fee_token_address: ContractAddress,
    /// Whether this is an L3 chain (true) or L2 chain (false).
    pub is_l3: bool,
}

impl Default for ChainConfig {
    /// Creates a default configuration for Sepolia testnet.
    ///
    /// # Returns
    ///
    /// A `ChainConfig` instance with Sepolia defaults:
    /// - Chain ID: Sepolia
    /// - STRK fee token: Sepolia STRK token address
    /// - L3: false (L2 chain)
    fn default() -> Self {
        Self {
            chain_id: ChainId::Sepolia,
            strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked(DEFAULT_SEPOLIA_STRK_FEE_TOKEN))
                .expect("Valid Sepolia STRK fee token address"),
            is_l3: false,
        }
    }
}

impl ChainConfig {
    /// Validates the chain configuration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the configuration is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns a `PieGenerationError::InvalidConfig` if the configuration is invalid.
    pub fn validate(&self) -> Result<(), PieGenerationError> {
        // Validate that the STRK fee token address is not zero
        if self.strk_fee_token_address == ContractAddress::default() {
            return Err(PieGenerationError::InvalidConfig("STRK fee token address cannot be zero".to_string()));
        }

        Ok(())
    }
}
