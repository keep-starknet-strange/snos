use cairo_vm::types::layout_name::LayoutName;
use starknet_os::io::os_output::StarknetOsRunnerOutput;

use crate::error::PieGenerationError;
use crate::types::{ChainConfig, OsHintsConfiguration};

/// Input configuration for PIE generation.
///
/// This struct contains all the necessary configuration and parameters needed to
/// generate a Cairo PIE file from Starknet blocks.
///
/// # Examples
///
/// ```rust
/// use generate_pie::{PieGenerationInput, ChainConfig, OsHintsConfiguration};
///
/// let input = PieGenerationInput {
///     rpc_url: "https://your-starknet-node.com".to_string(),
///     blocks: vec![12345, 12346],
///     chain_config: ChainConfig::default(),
///     os_hints_config: OsHintsConfiguration::default(),
///     output_path: Some("output.pie".to_string()),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct PieGenerationInput {
    /// The RPC URL of the Starknet node to connect to.
    pub rpc_url: String,
    /// The list of block numbers to process for PIE generation.
    pub blocks: Vec<u64>,
    /// Layout to be used for SNOS
    pub layout: LayoutName,
    /// Chain-specific configuration settings.
    pub chain_config: ChainConfig,
    /// OS hints and execution configuration.
    pub os_hints_config: OsHintsConfiguration,
    /// Optional output file path for the generated PIE file.
    pub output_path: Option<String>,
}

impl PieGenerationInput {
    /// Validates the PIE generation input configuration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the input is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns a `PieGenerationError::InvalidConfig` if the input is invalid.
    pub fn validate(&self) -> Result<(), PieGenerationError> {
        // Validate RPC URL
        if self.rpc_url.trim().is_empty() {
            return Err(PieGenerationError::InvalidConfig("RPC URL cannot be empty".to_string()));
        }

        // Validate blocks
        if self.blocks.is_empty() {
            return Err(PieGenerationError::InvalidConfig("At least one block must be specified".to_string()));
        }

        // Validate that blocks are in ascending order
        let mut sorted_blocks = self.blocks.clone();
        sorted_blocks.sort();
        if sorted_blocks != self.blocks {
            return Err(PieGenerationError::InvalidConfig("Blocks must be specified in ascending order".to_string()));
        }

        // Validate chain configuration
        self.chain_config.validate()?;

        Ok(())
    }
}

/// Result containing the generated PIE and metadata.
///
/// This struct contains the output of the PIE generation process, including
/// the generated Cairo PIE, information about processed blocks, and the output path.
pub struct PieGenerationResult {
    /// The output from the Starknet OS execution containing the Cairo PIE.
    pub output: StarknetOsRunnerOutput,
    /// The list of block numbers that were successfully processed.
    pub blocks_processed: Vec<u64>,
    /// The output file path where the PIE was saved (if specified).
    pub output_path: Option<String>,
}
