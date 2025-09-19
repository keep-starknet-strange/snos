//! Main entry point for the generate-pie application.
//!
//! This binary demonstrates how to use the generate-pie library to generate
//! Cairo PIE files from Starknet blocks.

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
    log::info!("Starting SNOS PIE generation application");

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: "https://pathfinder-snos.d.karnot.xyz".to_string(),
        blocks: vec![924072],
        chain_config: ChainConfig::default(),             // Uses Sepolia defaults
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: None,
    };

    // Display configuration information
    log::info!("Configuration:");
    log::info!("  RPC URL: {}", input.rpc_url);
    log::info!("  Blocks: {:?}", input.blocks);
    log::info!("  Chain ID: {:?}", input.chain_config.chain_id);
    log::info!("  Is L3: {}", input.chain_config.is_l3);
    log::info!("  Debug mode: {}", input.os_hints_config.debug_mode);
    log::info!("  Use KZG DA: {}", input.os_hints_config.use_kzg_da);
    log::info!("  Output path: {:?}", input.output_path);

    // Call the core PIE generation function
    match generate_pie(input).await {
        Ok(result) => {
            log::info!("PIE generation completed successfully!");
            log::info!("  Blocks processed: {:?}", result.blocks_processed);
            if let Some(output_path) = result.output_path {
                log::info!("  Output written to: {}", output_path);
            }
        }
        Err(e) => {
            log::error!("PIE generation failed: {}", e);
            eprintln!("\n❌ PIE generation failed: {}", e);
            return Err(e.into());
        }
    }

    log::info!("SNOS execution completed successfully!");
    println!("\n✅ SNOS execution completed successfully!");
    Ok(())
}
