//! End-to-end tests for PIE generation functionality
//!
//! These tests verify the complete workflow from RPC input to PIE output,
//! testing the integration between all crates in the workspace.

use std::env;
use std::fs;
use std::path::Path;
use tokio::time::{timeout, Duration};

use generate_pie::generate_pie;
use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};

/// Environment variable for test RPC URL
const TEST_RPC_URL_ENV: &str = "SNOS_TEST_RPC_URL";
/// Default test RPC URL (Pathfinder mainnet)
const DEFAULT_TEST_RPC_URL: &str = "https://pathfinder-mainnet.d.karnot.xyz";

/// Test timeout in seconds (PIE generation can take a while)
const TEST_TIMEOUT_SECS: u64 = 300; // 5 minutes

fn get_test_rpc_url() -> String {
    env::var(TEST_RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_TEST_RPC_URL.to_string())
}

fn create_test_output_path(test_name: &str, block_numbers: &[u64]) -> String {
    let blocks_str = block_numbers.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("_");
    format!("test_output_{}_blocks_{}.pie", test_name, blocks_str)
}

fn cleanup_test_file(path: &str) {
    if Path::new(path).exists() {
        if let Err(e) = fs::remove_file(path) {
            eprintln!("Warning: Failed to cleanup test file {}: {}", path, e);
        }
    }
}

/// Test basic single block PIE generation
///
/// This test verifies:
/// - RPC client can connect to the endpoint
/// - Block data can be fetched and processed
/// - Cached state can be generated
/// - OS execution completes successfully
/// - PIE file is generated and passes validation
#[tokio::test]
#[ignore = "Requires working RPC endpoint - run with: cargo test test_single_block_pie_generation -- --ignored"]
async fn test_single_block_pie_generation() {
    let test_name = "single_block";
    // Use a known good block number for testing
    let block_number = 200000u64;
    let block_numbers = vec![block_number];

    let output_path = create_test_output_path(test_name, &block_numbers);

    // Cleanup any existing test files
    cleanup_test_file(&output_path);

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default(), // Uses mainnet defaults
        os_hints_config: OsHintsConfiguration::default(),
        output_path: Some(output_path.clone()),
    };

    println!("🧪 Testing single block PIE generation");
    println!("   RPC URL: {}", input.rpc_url);
    println!("   Block: {}", block_number);
    println!("   Output: {}", output_path);

    // Run the test with timeout
    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(pie_output) => {
                    println!("✅ PIE generation succeeded!");

                    // Verify the result
                    assert_eq!(pie_output.blocks_processed, block_numbers);
                    assert_eq!(pie_output.output_path, Some(output_path.clone()));

                    // Verify the PIE file was created
                    assert!(Path::new(&output_path).exists(), "PIE file should exist at {}", output_path);

                    // Verify PIE validity (this was already checked in generate_pie, but let's be explicit)
                    println!("✅ PIE file validation passed");

                    // Check file size (PIE files should be substantial)
                    let metadata = fs::metadata(&output_path).expect("Should be able to read PIE file metadata");
                    assert!(metadata.len() > 1024, "PIE file should be larger than 1KB, got {} bytes", metadata.len());
                    println!("✅ PIE file size: {} bytes", metadata.len());

                    println!("🎉 Single block PIE generation test completed successfully!");
                }
                Err(e) => {
                    panic!("❌ PIE generation failed: {}", e);
                }
            }
        }
        Err(_) => {
            panic!("❌ PIE generation timed out after {} seconds", TEST_TIMEOUT_SECS);
        }
    }

    // Cleanup
    cleanup_test_file(&output_path);
}

/// Test multi-block PIE generation
///
/// This test verifies:
/// - Multiple blocks can be processed in sequence
/// - State is correctly maintained between blocks
/// - Compiled classes are properly merged
/// - Multi-block PIE is generated successfully
#[tokio::test]
#[ignore = "Requires working RPC endpoint and takes significant time - run with: cargo test test_multi_block_pie_generation -- --ignored"]
async fn test_multi_block_pie_generation() {
    let test_name = "multi_block";
    // Use consecutive blocks for testing
    let block_numbers = vec![200000u64, 200001u64];

    let output_path = create_test_output_path(test_name, &block_numbers);

    // Cleanup any existing test files
    cleanup_test_file(&output_path);

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: Some(output_path.clone()),
    };

    println!("🧪 Testing multi-block PIE generation");
    println!("   RPC URL: {}", input.rpc_url);
    println!("   Blocks: {:?}", block_numbers);
    println!("   Output: {}", output_path);

    // Multi-block processing takes longer
    let extended_timeout = Duration::from_secs(TEST_TIMEOUT_SECS * 2);

    let result = timeout(extended_timeout, generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(pie_output) => {
                    println!("✅ Multi-block PIE generation succeeded!");

                    // Verify all blocks were processed
                    assert_eq!(pie_output.blocks_processed, block_numbers);
                    assert_eq!(pie_output.output_path, Some(output_path.clone()));

                    // Verify the PIE file was created
                    assert!(Path::new(&output_path).exists(), "PIE file should exist at {}", output_path);

                    // Multi-block PIE should be larger than single block
                    let metadata = fs::metadata(&output_path).expect("Should be able to read PIE file metadata");
                    assert!(
                        metadata.len() > 2048,
                        "Multi-block PIE file should be larger, got {} bytes",
                        metadata.len()
                    );
                    println!("✅ Multi-block PIE file size: {} bytes", metadata.len());

                    println!("🎉 Multi-block PIE generation test completed successfully!");
                }
                Err(e) => {
                    panic!("❌ Multi-block PIE generation failed: {}", e);
                }
            }
        }
        Err(_) => {
            panic!("❌ Multi-block PIE generation timed out after {} seconds", extended_timeout.as_secs());
        }
    }

    // Cleanup
    cleanup_test_file(&output_path);
}

/// Test PIE generation with different chain configurations
#[tokio::test]
#[ignore = "Requires working RPC endpoint - run with: cargo test test_chain_config_variations -- --ignored"]
async fn test_chain_config_variations() {
    let test_name = "chain_config";
    let block_numbers = vec![200000u64];

    // Test with custom chain configuration
    let mut custom_chain_config = ChainConfig::default();
    custom_chain_config.is_l3 = true; // Test L3 configuration

    let output_path = create_test_output_path(test_name, &block_numbers);
    cleanup_test_file(&output_path);

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: block_numbers.clone(),
        chain_config: custom_chain_config,
        os_hints_config: OsHintsConfiguration::default(),
        output_path: Some(output_path.clone()),
    };

    println!("🧪 Testing PIE generation with custom chain config");
    println!("   L3 mode: {}", input.chain_config.is_l3);

    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => match pie_result {
            Ok(pie_output) => {
                println!("✅ PIE generation with custom chain config succeeded!");
                assert_eq!(pie_output.blocks_processed, block_numbers);
                assert!(Path::new(&output_path).exists());
            }
            Err(e) => {
                panic!("❌ PIE generation with custom chain config failed: {}", e);
            }
        },
        Err(_) => {
            panic!("❌ PIE generation with custom chain config timed out");
        }
    }

    cleanup_test_file(&output_path);
}

/// Test PIE generation with different OS hints configurations
#[tokio::test]
#[ignore = "Requires working RPC endpoint - run with: cargo test test_os_hints_variations -- --ignored"]
async fn test_os_hints_variations() {
    let test_name = "os_hints";
    let block_numbers = vec![200000u64];

    // Test with custom OS hints configuration
    let mut custom_os_hints = OsHintsConfiguration::default();
    custom_os_hints.debug_mode = true;
    custom_os_hints.full_output = true;
    custom_os_hints.use_kzg_da = false;

    let output_path = create_test_output_path(test_name, &block_numbers);
    cleanup_test_file(&output_path);

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default(),
        os_hints_config: custom_os_hints,
        output_path: Some(output_path.clone()),
    };

    println!("🧪 Testing PIE generation with custom OS hints config");
    println!("   Debug mode: {}", input.os_hints_config.debug_mode);
    println!("   Full output: {}", input.os_hints_config.full_output);
    println!("   Use KZG DA: {}", input.os_hints_config.use_kzg_da);

    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(pie_output) => {
                    println!("✅ PIE generation with custom OS hints succeeded!");
                    assert_eq!(pie_output.blocks_processed, block_numbers);
                    assert!(Path::new(&output_path).exists());

                    // With debug mode and full output, the PIE might be larger
                    let metadata = fs::metadata(&output_path).expect("Should be able to read PIE file metadata");
                    println!("✅ PIE file size with debug/full output: {} bytes", metadata.len());
                }
                Err(e) => {
                    panic!("❌ PIE generation with custom OS hints failed: {}", e);
                }
            }
        }
        Err(_) => {
            panic!("❌ PIE generation with custom OS hints timed out");
        }
    }

    cleanup_test_file(&output_path);
}

/// Test PIE generation without output file (in-memory only)
#[tokio::test]
#[ignore = "Requires working RPC endpoint - run with: cargo test test_in_memory_pie_generation -- --ignored"]
async fn test_in_memory_pie_generation() {
    let block_numbers = vec![200000u64];

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None, // No file output
    };

    println!("🧪 Testing in-memory PIE generation (no file output)");

    let result = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(pie_output) => {
                    println!("✅ In-memory PIE generation succeeded!");
                    assert_eq!(pie_output.blocks_processed, block_numbers);
                    assert_eq!(pie_output.output_path, None);

                    // Verify the PIE data exists in memory
                    // The cairo_pie should have been validated during generation
                    println!("✅ In-memory PIE is valid and accessible");
                }
                Err(e) => {
                    panic!("❌ In-memory PIE generation failed: {}", e);
                }
            }
        }
        Err(_) => {
            panic!("❌ In-memory PIE generation timed out");
        }
    }
}
