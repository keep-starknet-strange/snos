//! Simple end-to-end tests for PIE generation
//!
//! These tests provide straightforward validation of the PIE generation workflow
//! using parameterized test cases.
//!
//! There's a special case for pathfinder for blocks in range [1943743,1952704] on Mainnet.
//!
//! Official Statement from Starknet:
//!
//! ---
//! Due to the Cairo0 bug we had in regard to some of the deprecated contract hashes not being
//! recognized by the Class Manager component following the upgrade - some txs that should've passed,
//! failed. The issue this created is that re-execution of these tx will work as these classes do
//! exist. Therefore, we ask you to rely on the feeder gateway for re-execution requests between
//! blocks 1943704-1952704. Unfortunately, Starkscan rely on this fix to be fully functioning again.
//! ---
//!
//! One such txn where re-execution leads to a different result is:
//! `0x1b63eae2bd1b55f06b76d7b32c60f21a0d3d09d34d89587e01a7185d37c274e`

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
// mainnet not on 0.14.1 yet
// #[case("mainnet", vec![1943728])] // slow
// #[case("mainnet", vec![1943731])] // slow
// #[case("mainnet", vec![1952705])] // slow
// #[case("mainnet", vec![1944976])] // slow
// #[case("mainnet", vec![2403992])] // slow
// sepolia blocks (0.14.1)
#[case("sepolia", vec![2934726])] // first 0.14.1 block
#[case("sepolia", vec![2934727])] // empty block, second block of 0.14.1
#[case("sepolia", vec![3023829])] // has declare txn
#[case("sepolia", vec![3028228])] // deploy account ready multisig
#[case("sepolia", vec![3028244])] // deploy account ready simple
#[case("sepolia", vec![3030489])] // l1 handler reverted txn
#[case("sepolia", vec![3042980])] // l1 handler eth bridge txn
#[case("sepolia", vec![3048281])] // l1 handler strk bridge txn
#[case("sepolia", vec![3030480])] // l1 handler random
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

    // Use a simple block for testing (0.14.1 empty block)
    let chain = "sepolia";
    let block_numbers = vec![2934727]; // empty block, second block of 0.14.1

    println!("🧪 Testing PIE generation with custom versioned constants for blocks on {}", chain);

    let input = PieGenerationInput {
        rpc_url: get_rpc_url(chain),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default_with_chain(chain),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
        layout: LayoutName::all_cairo,
        versioned_constants,
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
