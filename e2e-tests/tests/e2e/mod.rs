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

pub const SNOS_RPC_URL_ENV: &str = "SNOS_RPC_URL";
pub const TEST_TIMEOUT_SECS: u64 = 30 * 60; // 30 minutes

/// Get RPC URL from environment
fn get_rpc_url() -> String {
    env::var(SNOS_RPC_URL_ENV).expect(&format!("{} env is needed", SNOS_RPC_URL_ENV))
}

/// Simple PIE generation test with parameterized block numbers
#[rstest]
#[case(2403992)]
#[tokio::test(flavor = "multi_thread")]
async fn test_pie_generation(#[case] block_number: u64) {
    println!("🧪 Testing PIE generation for block {}", block_number);

    let input = PieGenerationInput {
        rpc_url: get_rpc_url(),
        blocks: vec![block_number],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    println!("📡 Using RPC: {}", input.rpc_url);
    println!("📦 Processing block: {}", block_number);

    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => match pie_result {
            Ok(pie_result) => {
                println!("✅ PIE generation succeeded for block {}", block_number);
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
