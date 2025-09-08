use generate_pie::{generate_pie, ChainConfig, OsHintsConfiguration, PieGenerationInput};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    println!("Starting SNOS PoC application with clean architecture");

    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: "https://pathfinder-snos.d.karnot.xyz".to_string(),
        blocks: vec![924072],
        chain_config: ChainConfig::default(),             // Uses Sepolia defaults
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: None,
    };

    println!("Configuration:");
    println!("  RPC URL: {}", input.rpc_url);
    println!("  Blocks: {:?}", input.blocks);
    println!("  Chain ID: {:?}", input.chain_config.chain_id);
    println!("  Output: {:?}", input.output_path);

    // Call the core PIE generation function
    match generate_pie(input).await {
        Ok(result) => {
            println!("\n🎉 PIE generation completed successfully!");
            println!("  Blocks processed: {:?}", result.blocks_processed);
            if let Some(output_path) = result.output_path {
                println!("  Output written to: {}", output_path);
            }
        }
        Err(e) => {
            eprintln!("\n❌ PIE generation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("\n✅ SNOS execution completed successfully!");
    Ok(())
}
