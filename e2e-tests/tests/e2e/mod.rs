//! Simple end-to-end tests for PIE generation
//!
//! These tests provide straightforward validation of the PIE generation workflow
//! using parameterized test cases.

use cairo_vm::types::layout_name::LayoutName;
use generate_pie::constants::{DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN};
use generate_pie::generate_pie;
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use rstest::rstest;
use std::env;
use std::time::Duration;
use tokio::time::timeout;

pub const SNOS_RPC_URL_ENV_MAINNET: &str = "SNOS_RPC_URL";
pub const SNOS_RPC_URL_ENV_SEPOLIA: &str = "SNOS_RPC_URL_SEPOLIA";

pub const TEST_TIMEOUT_SECS: u64 = 30 * 60; // 30 minutes

/// Get RPC URL from environment
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
// mainnet blocks
#[case("mainnet", vec![1943728])] // very slow
#[case("mainnet", vec![1943731])] // slow
#[case("mainnet", vec![1943743])] // very slow
#[case("mainnet", vec![1944976])] // slow
#[case("mainnet", vec![2403992])] // slow
// sepolia blocks
#[case("sepolia", vec![2325530, 2325531])] // very slow
#[case("sepolia", vec![994169])] // very slow
#[case("sepolia", vec![926808])] // fast
#[case("sepolia", vec![927143])] // fast
#[case("sepolia", vec![1041119])] // fast
#[case("sepolia", vec![1004270])] // fast
#[case("sepolia", vec![2244464])] // fast
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
        strk_fee_token_address: DEFAULT_SEPOLIA_STRK_FEE_TOKEN.to_string(),
        eth_fee_token_address: DEFAULT_SEPOLIA_ETH_FEE_TOKEN.to_string(),
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
