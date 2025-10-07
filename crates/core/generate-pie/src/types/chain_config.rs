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
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
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
    /// Creates a new ChainConfig with default values.
    ///
    /// # Returns
    ///
    /// A new `ChainConfig` instance with Sepolia defaults:
    /// - Chain ID: Sepolia
    /// - STRK fee token: Sepolia STRK token address
    /// - L3: false (L2 chain)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use generate_pie::ChainConfig;
    /// use starknet_api::core::ChainId;
    ///
    /// let config = ChainConfig::new()
    ///     .with_chain_id(ChainId::Mainnet)
    ///     .with_is_l3(true);
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the STRK fee token address.
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address of the STRK fee token
    ///
    /// # Returns
    ///
    /// The modified `ChainConfig` instance for method chaining
    ///
    /// # Examples
    ///
    /// ```rust
    /// use generate_pie::ChainConfig;
    /// use starknet_api::core::{ChainId, ContractAddress};
    /// use starknet_types_core::felt::Felt;
    ///
    /// let address = ContractAddress::try_from(Felt::from_hex_unchecked("0x123...")).unwrap();
    /// let config = ChainConfig::new()
    ///     .with_strk_fee_token_address(address);
    /// ```
    pub fn with_strk_fee_token_address(mut self, address: ContractAddress) -> Self {
        self.strk_fee_token_address = address;
        self
    }

    /// Sets the STRK fee token address from a hex string.
    ///
    /// This method parses the hex string and converts it to a ContractAddress.
    /// If the string is invalid, it returns an error.
    ///
    /// # Arguments
    ///
    /// * `address_hex` - The hex string representation of the STRK fee token address
    ///
    /// # Returns
    ///
    /// `Result<Self, PieGenerationError>` - The modified `ChainConfig` instance or an error
    ///
    /// # Errors
    ///
    /// Returns `PieGenerationError::InvalidConfig` if the hex string is invalid or cannot be converted to a ContractAddress.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use generate_pie::ChainConfig;
    ///
    /// let config = ChainConfig::new()
    ///     .with_strk_fee_token_address_str("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d")
    ///     .unwrap();
    /// ```
    pub fn with_strk_fee_token_address_str(mut self, address_hex: &str) -> Result<Self, PieGenerationError> {
        let felt = Felt::from_hex(address_hex)
            .map_err(|e| PieGenerationError::InvalidConfig(format!("Invalid STRK fee token address hex: {}", e)))?;

        let address = ContractAddress::try_from(felt)
            .map_err(|e| PieGenerationError::InvalidConfig(format!("Failed to convert to ContractAddress: {}", e)))?;

        self.strk_fee_token_address = address;
        Ok(self)
    }

    /// Sets the chain ID from a string.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain name as a string (e.g., "sepolia", "mainnet", or custom chain name)
    ///
    /// # Returns
    ///
    /// The modified `ChainConfig` instance for method chaining
    ///
    /// # Examples
    ///
    /// ```rust
    /// use generate_pie::ChainConfig;
    ///
    /// let config = ChainConfig::new()
    ///     .with_chain_id("mainnet");
    /// ```
    pub fn with_chain_id(mut self, chain: &str) -> Self {
        self.chain_id = match chain {
            "sepolia" => ChainId::Sepolia,
            "mainnet" => ChainId::Mainnet,
            _ => ChainId::Other(chain.to_string()),
        };
        self
    }

    /// Sets whether this is an L3 chain.
    ///
    /// # Arguments
    ///
    /// * `is_l3` - true if this is an L3 chain, false for L2
    ///
    /// # Returns
    ///
    /// The modified `ChainConfig` instance for method chaining
    ///
    /// # Examples
    ///
    /// ```rust
    /// use generate_pie::ChainConfig;
    /// use starknet_api::core::ChainId;
    ///
    /// let config = ChainConfig::new(ChainId::Sepolia)
    ///     .with_is_l3(true);
    /// ```
    pub fn with_is_l3(mut self, is_l3: bool) -> Self {
        self.is_l3 = is_l3;
        self
    }

    pub fn default_with_chain(chain: &str) -> Self {
        match chain {
            "sepolia" => Self::default(),
            "mainnet" => Self { chain_id: ChainId::Mainnet, ..Default::default() },
            _ => Self { chain_id: ChainId::Other(chain.to_string()), ..Default::default() },
        }
    }

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
