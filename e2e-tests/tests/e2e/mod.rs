//! Simple end-to-end tests for PIE generation
//!
//! These tests provide straightforward validation of the PIE generation workflow
//! using parameterized test cases.
//!
use cairo_vm::types::layout_name::LayoutName;
use generate_pie::generate_pie;
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use generate_pie::utils::load_versioned_constants;
use rstest::rstest;
use std::env;
use std::time::Duration;
use tokio::time::timeout;

pub const SNOS_RPC_URL_ENV_MAINNET: &str = "SNOS_RPC_URL";
pub const SNOS_RPC_URL_ENV_SEPOLIA: &str = "SNOS_RPC_URL_SEPOLIA";

pub const TEST_TIMEOUT_SECS: u64 = 30 * 60; // 30 minutes

/// Get RPC URL from environment
/// Falls back to default RPC URLs if environment variables are not set
fn get_rpc_url(chain: &str) -> String {
    match chain {
        "sepolia" => {
            env::var(SNOS_RPC_URL_ENV_SEPOLIA).unwrap_or_else(|_| panic!("{} env is needed", SNOS_RPC_URL_ENV_SEPOLIA))
        }
        "mainnet" => {
            env::var(SNOS_RPC_URL_ENV_MAINNET).unwrap_or_else(|_| panic!("{} env is needed", SNOS_RPC_URL_ENV_MAINNET))
        }
        _ => panic!("Unsupported chain: {}", chain),
    }
}

/// Simple PIE generation test with parameterized block numbers
#[rstest]
// sepolia blocks (0.14.2)
#[case("sepolia", vec![7984520])] // first 0.14.2 block
#[case("sepolia", vec![7984521])] // second 0.14.2 block, empty and contiguous with first block
#[case("sepolia", vec![7984520, 7984521])] // first contiguous 0.14.2 multi-block pair
#[case("sepolia", vec![7984528])] // first non-empty invoke-v3 block
#[case("sepolia", vec![7984545])] // l1 handler-heavy block
#[case("sepolia", vec![7984561])] // declare-v3 block
#[case("sepolia", vec![8002289])] // boundary get_block_hash regression block
#[case("sepolia", vec![8002288, 8002289])] // original failing replay window for the boundary block-hash read
#[tokio::test(flavor = "multi_thread")]
async fn test_pie_generation(#[case] chain: &str, #[case] block_numbers: Vec<u64>) {
    println!("🧪 Testing PIE generation for blocks on {}", chain);

    let input = PieGenerationInput {
        rpc_url: get_rpc_url(chain),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default_with_chain(chain),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
        layout: LayoutName::all_cairo,
        versioned_constants: None,
        public_keys: None,
    };

    println!("📡 Using RPC: {}", input.rpc_url);
    println!("📦 Processing blocks");

    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => match pie_result {
            Ok(pie_result) => {
                println!("✅  PIE generation succeeded for blocks on {}", chain);
                assert_eq!(pie_result.blocks_processed, block_numbers);
                assert_eq!(pie_result.output_path, None);
                println!("🎉 Blocks processed successfully on {}!", chain);
            }
            Err(e) => {
                panic!("❌ PIE generation failed for blocks on {}: {}", chain, e);
            }
        },
        Err(_) => {
            panic!("❌ PIE generation timed out for blocks on {} after {} seconds", chain, TEST_TIMEOUT_SECS);
        }
    }
}

/// Test PIE generation with custom versioned constants
///
/// This test demonstrates how to use custom versioned constants from a file.
/// It uses the `resources/custom_version_constants.json` file directly.
#[tokio::test(flavor = "multi_thread")]
async fn test_pie_generation_with_custom_versioned_constants() {
    // Construct path to the custom versioned constants file relative to workspace root
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let constants_path = workspace_root.join("resources").join("custom_version_constants.json");
    let constants_path_str = constants_path.to_str().expect("Invalid path");

    // Test the loading function
    let versioned_constants = match load_versioned_constants(Some(constants_path_str)) {
        Ok(Some(constants)) => {
            println!("✅ Successfully loaded versioned constants from file: {}", constants_path_str);
            Some(constants)
        }
        Ok(None) => {
            panic!("❌ Expected to load versioned constants from file, but got None");
        }
        Err(e) => {
            panic!("❌ Failed to load versioned constants from {}: {}", constants_path_str, e);
        }
    };

    // Use a simple block for testing (0.14.2 empty block)
    let chain = "sepolia";
    let block_numbers = vec![7984521]; // empty block, second block of 0.14.2

    println!("🧪 Testing PIE generation with custom versioned constants for blocks on {}", chain);

    let input = PieGenerationInput {
        rpc_url: get_rpc_url(chain),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default_with_chain(chain),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
        layout: LayoutName::all_cairo,
        versioned_constants,
        public_keys: None,
    };

    println!("📡 Using RPC: {}", input.rpc_url);
    println!("📦 Processing blocks");
    if input.versioned_constants.is_some() {
        println!("📋 Using custom versioned constants from file");
    } else {
        println!("📋 Using auto-detected versioned constants");
    }

    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => match pie_result {
            Ok(pie_result) => {
                println!("✅  PIE generation succeeded for blocks on {}", chain);
                assert_eq!(pie_result.blocks_processed, block_numbers);
                assert_eq!(pie_result.output_path, None);
                println!("🎉 Blocks processed successfully on {}!", chain);
            }
            Err(e) => {
                panic!("❌ PIE generation failed for blocks on {}: {}", chain, e);
            }
        },
        Err(_) => {
            panic!("❌ PIE generation timed out for blocks on {} after {} seconds", chain, TEST_TIMEOUT_SECS);
        }
    }
}
