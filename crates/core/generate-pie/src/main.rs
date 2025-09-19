//! Main entry point for the generate-pie application.
//!
//! This binary demonstrates how to use the generate-pie library to generate
//! Cairo PIE files from Starknet blocks.

use log::{error, info};

use generate_pie::generate_pie;
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
/// Main entry point for the generate-pie application.
///
/// This function demonstrates the usage of the generate-pie library by:
/// 1. Initializing logging
/// 2. Creating a configuration for PIE generation
/// 3. Calling the core PIE generation function
/// 4. Handling the results and errors appropriately
///
/// # Returns
///
/// Returns `Ok(())` if the PIE generation completes successfully, or an error
/// if any step of the process fails.
///
/// # Errors
///
/// This function can return various errors including
/// - Configuration validation errors
/// - RPC client connection errors
/// - Block processing errors
/// - OS execution errors
/// - File I/O errors
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    env_logger::init();
    info!("Starting SNOS PIE generation application");

    // Build the input configuration
    // TODO: take the RPC from env or command line
    let input = PieGenerationInput {
        rpc_url: "https://pathfinder-snos.d.karnot.xyz".to_string(),
        blocks: vec![924072],
        chain_config: ChainConfig::default(),             // Uses Sepolia defaults
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: None,
    };

    // Display configuration information
    info!("Configuration:");
    info!("  RPC URL: {}", input.rpc_url);
    info!("  Blocks: {:?}", input.blocks);
    info!("  Chain ID: {:?}", input.chain_config.chain_id);
    info!("  Is L3: {}", input.chain_config.is_l3);
    info!("  Debug mode: {}", input.os_hints_config.debug_mode);
    info!("  Use KZG DA: {}", input.os_hints_config.use_kzg_da);
    info!("  Output path: {:?}", input.output_path);

    // Call the core PIE generation function
    match generate_pie(input).await {
        Ok(result) => {
            info!("PIE generation completed successfully!");
            info!("  Blocks processed: {:?}", result.blocks_processed);
            if let Some(output_path) = result.output_path {
                info!("  Output written to: {}", output_path);
            }
        }
        Err(e) => {
            error!("PIE generation failed: {}", e);
            error!("\n❌ PIE generation failed: {}", e);
            return Err(e.into());
        }
    }

    info!("SNOS execution completed successfully!");
    info!("\n✅ SNOS execution completed successfully!");
    Ok(())
}
