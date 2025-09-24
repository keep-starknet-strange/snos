//! Simple end-to-end tests for PIE generation
//!
//! These tests provide straightforward validation of the PIE generation workflow
//! using parameterized test cases.

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
#[case("mainnet", 2403992)]
#[case("mainnet", 1943728)]
#[case("mainnet", 1943731)]
#[case("mainnet", 1943743)]
#[case("mainnet", 1944976)]
#[case("sepolia", 994169)]
#[case("sepolia", 926808)]
#[case("sepolia", 1004270)]
#[case("sepolia", 1041119)]
#[case("sepolia", 927143)]
#[tokio::test(flavor = "multi_thread")]
async fn test_pie_generation(#[case] chain: &str, #[case] block_number: u64) {
    println!("🧪 Testing PIE generation for block {}", block_number);

    let input = PieGenerationInput {
        rpc_url: get_rpc_url(chain),
        blocks: vec![block_number],
        chain_config: ChainConfig::default_with_chain(chain),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    println!("📡 Using RPC: {}", input.rpc_url);
    println!("📦 Processing block: {}", block_number);

    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => match pie_result {
            Ok(pie_result) => {
                println!("✅  PIE generation succeeded for block {}", block_number);
                assert_eq!(pie_result.blocks_processed, vec![block_number]);
                assert_eq!(pie_result.output_path, None);
                println!("🎉 Block {} processed successfully!", block_number);
            }
            Err(e) => {
                panic!("❌ PIE generation failed for block {}: {}", block_number, e);
            }
        },
        Err(_) => {
            panic!("❌ PIE generation timed out after {} seconds", TEST_TIMEOUT_SECS);
        }
    }
}
