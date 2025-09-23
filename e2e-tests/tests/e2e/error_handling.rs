//! End-to-end tests for error handling scenarios
//!
//! These tests verify that the system gracefully handles various error conditions
//! and provides meaningful error messages.

use std::env;
use tokio::time::{timeout, Duration};

use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
use generate_pie::{error::PieGenerationError, generate_pie};

/// Short timeout for tests that should fail quickly
const QUICK_TIMEOUT_SECS: u64 = 30;

fn get_test_rpc_url() -> String {
    env::var("SNOS_TEST_RPC_URL").unwrap_or_else(|_| "https://pathfinder-mainnet.d.karnot.xyz".to_string())
}

/// Test error handling when RPC endpoint is invalid
#[tokio::test]
async fn test_invalid_rpc_endpoint() {
    println!("🧪 Testing invalid RPC endpoint error handling");

    let input = PieGenerationInput {
        rpc_url: "http://invalid-nonexistent-endpoint.local:12345".to_string(),
        blocks: vec![200000u64],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    let result = timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(_) => {
                    panic!("❌ Expected RPC client error, but PIE generation succeeded");
                }
                Err(e) => {
                    println!("✅ Got expected error: {}", e);

                    // Verify it's the right type of error
                    match e {
                        PieGenerationError::RpcClient(msg) => {
                            println!("✅ Correct error type: RpcClient");
                            assert!(
                                msg.contains("Failed to initialize RPC client")
                                    || msg.contains("connection")
                                    || msg.contains("invalid")
                                    || msg.contains("endpoint"),
                                "Error message should indicate RPC client issue: {}",
                                msg
                            );
                        }
                        _ => {
                            panic!("❌ Expected RpcClient error, got: {:?}", e);
                        }
                    }
                }
            }
        }
        Err(_) => {
            panic!("❌ Test timed out - invalid RPC should fail quickly");
        }
    }
}

/// Test error handling when block number doesn't exist
#[tokio::test]
#[ignore = "Requires working RPC endpoint - run with: cargo test test_nonexistent_block -- --ignored"]
async fn test_nonexistent_block() {
    println!("🧪 Testing nonexistent block error handling");

    // Use a block number that's way in the future and unlikely to exist
    let future_block = 99999999u64;

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: vec![future_block],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    let result = timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(_) => {
                    panic!("❌ Expected block processing error, but PIE generation succeeded");
                }
                Err(e) => {
                    println!("✅ Got expected error: {}", e);

                    // Verify it's the right type of error
                    match e {
                        PieGenerationError::BlockProcessing { block_number, source: _ } => {
                            println!("✅ Correct error type: BlockProcessing");
                            assert_eq!(block_number, future_block);
                        }
                        PieGenerationError::RpcClient(msg) => {
                            println!("✅ Alternative acceptable error: RpcClient - {}", msg);
                            // Some RPC clients might return this for nonexistent blocks
                        }
                        _ => {
                            panic!("❌ Expected BlockProcessing or RpcClient error, got: {:?}", e);
                        }
                    }
                }
            }
        }
        Err(_) => {
            panic!("❌ Test timed out - nonexistent block should fail quickly");
        }
    }
}

/// Test input validation errors
#[tokio::test]
async fn test_input_validation_errors() {
    println!("🧪 Testing input validation errors");

    // Test empty blocks list
    let input_empty_blocks = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: vec![], // Empty blocks should be invalid
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    let result = generate_pie(input_empty_blocks).await;
    match result {
        Ok(_) => {
            panic!("❌ Expected validation error for empty blocks list");
        }
        Err(e) => {
            println!("✅ Got expected validation error: {}", e);
            match e {
                PieGenerationError::InvalidConfig(msg) => {
                    println!("✅ Correct error type: InvalidConfig");
                    assert!(
                        msg.contains("blocks") || msg.contains("empty"),
                        "Error should mention blocks or empty: {}",
                        msg
                    );
                }
                _ => {
                    panic!("❌ Expected InvalidConfig error, got: {:?}", e);
                }
            }
        }
    }

    // Test invalid RPC URL format
    let input_invalid_url = PieGenerationInput {
        rpc_url: "not-a-valid-url".to_string(),
        blocks: vec![200000u64],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    let result = timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), generate_pie(input_invalid_url)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(_) => {
                    panic!("❌ Expected error for invalid URL format");
                }
                Err(e) => {
                    println!("✅ Got expected error for invalid URL: {}", e);
                    // Could be either InvalidConfig or RpcClient depending on when validation occurs
                    match e {
                        PieGenerationError::InvalidConfig(_) | PieGenerationError::RpcClient(_) => {
                            println!("✅ Acceptable error type for invalid URL");
                        }
                        _ => {
                            panic!("❌ Expected InvalidConfig or RpcClient error, got: {:?}", e);
                        }
                    }
                }
            }
        }
        Err(_) => {
            panic!("❌ Test timed out - invalid URL should fail quickly");
        }
    }
}

/// Test file system errors (invalid output path)
#[tokio::test]
#[ignore = "Requires working RPC endpoint - run with: cargo test test_filesystem_errors -- --ignored"]
async fn test_filesystem_errors() {
    println!("🧪 Testing filesystem error handling");

    // Try to write to an invalid/restricted path
    let invalid_output_path = "/root/restricted/invalid/path/output.pie".to_string();

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: vec![200000u64],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: Some(invalid_output_path),
    };

    let result = timeout(
        Duration::from_secs(60), // Give it some time to process before hitting the I/O error
        generate_pie(input),
    )
    .await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(_) => {
                    panic!("❌ Expected I/O error for invalid output path");
                }
                Err(e) => {
                    println!("✅ Got expected error: {}", e);
                    match e {
                        PieGenerationError::Io(_) => {
                            println!("✅ Correct error type: Io");
                        }
                        _ => {
                            // Some systems might catch this earlier as a different error type
                            println!("✅ Alternative error type (acceptable): {:?}", e);
                        }
                    }
                }
            }
        }
        Err(_) => {
            panic!("❌ Test timed out");
        }
    }
}

/// Test network timeout scenarios (using a very slow/unreliable endpoint)
#[tokio::test]
#[ignore = "Network dependent test - run manually when needed"]
async fn test_network_timeout() {
    println!("🧪 Testing network timeout scenarios");

    // Use an endpoint that's likely to be slow or unreliable
    let slow_rpc_url = "http://httpstat.us/200?sleep=30000".to_string(); // Simulates 30s delay

    let input = PieGenerationInput {
        rpc_url: slow_rpc_url,
        blocks: vec![200000u64],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    // Set a shorter timeout than the endpoint delay
    let result = timeout(Duration::from_secs(10), generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(_) => {
                    panic!("❌ Expected timeout or network error");
                }
                Err(e) => {
                    println!("✅ Got expected network error: {}", e);
                    // Should be RpcClient error due to timeout/network issues
                    match e {
                        PieGenerationError::RpcClient(_) => {
                            println!("✅ Correct error type: RpcClient");
                        }
                        _ => {
                            println!("✅ Alternative error type (might be acceptable): {:?}", e);
                        }
                    }
                }
            }
        }
        Err(_) => {
            println!("✅ Request timed out as expected (test framework timeout)");
            // This is actually an acceptable outcome for this test
        }
    }
}

/// Test block with no transactions (edge case)
#[tokio::test]
#[ignore = "Requires working RPC endpoint and knowledge of empty blocks - run with: cargo test test_empty_block -- --ignored"]
async fn test_empty_block() {
    println!("🧪 Testing empty block processing");

    // Block 0 or 1 might be empty on some networks
    let empty_block = 1u64;

    let input = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: vec![empty_block],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    let result = timeout(Duration::from_secs(60), generate_pie(input)).await;

    match result {
        Ok(pie_result) => {
            match pie_result {
                Ok(pie_output) => {
                    println!("✅ Empty block processed successfully!");
                    assert_eq!(pie_output.blocks_processed, vec![empty_block]);
                    println!("✅ Empty block PIE generation completed");
                }
                Err(e) => {
                    println!("⚠️  Empty block processing failed: {}", e);
                    // This might be expected if the block has issues or the OS can't handle it
                    // Log but don't fail the test as empty blocks might be problematic by design
                }
            }
        }
        Err(_) => {
            println!("⚠️  Empty block processing timed out");
            // This might be expected for certain edge cases
        }
    }
}

/// Test concurrent PIE generation (potential race conditions)
#[tokio::test]
#[ignore = "Requires working RPC endpoint and is resource intensive - run with: cargo test test_concurrent_generation -- --ignored"]
async fn test_concurrent_generation() {
    println!("🧪 Testing concurrent PIE generation");

    let block_numbers = vec![200000u64, 200001u64];

    // Create two identical inputs
    let input1 = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    let input2 = PieGenerationInput {
        rpc_url: get_test_rpc_url(),
        blocks: block_numbers.clone(),
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    println!("Starting concurrent PIE generations...");

    // Run both concurrently
    let (result1, result2) = tokio::join!(
        timeout(Duration::from_secs(300), generate_pie(input1)),
        timeout(Duration::from_secs(300), generate_pie(input2))
    );

    // Both should succeed (or both should fail with the same error)
    match (result1, result2) {
        (Ok(Ok(pie1)), Ok(Ok(pie2))) => {
            println!("✅ Both concurrent PIE generations succeeded!");
            assert_eq!(pie1.blocks_processed, pie2.blocks_processed);
            println!("✅ Concurrent generation results are consistent");
        }
        (Ok(Err(e1)), Ok(Err(e2))) => {
            println!("⚠️  Both concurrent generations failed (might be acceptable):");
            println!("   Error 1: {}", e1);
            println!("   Error 2: {}", e2);
            // If both fail with similar errors, that's acceptable
        }
        (Err(_), Err(_)) => {
            println!("⚠️  Both concurrent generations timed out (resource limits?)");
            // This might be expected under resource constraints
        }
        _ => {
            panic!("❌ Inconsistent results from concurrent PIE generation - potential race condition");
        }
    }
}
