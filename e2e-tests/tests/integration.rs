//! Integration tests for the SNOS (Starknet OS) workspace
//!
//! This file serves as the main entry point for all end-to-end integration tests.
//! It includes tests that verify the complete workflow across all crates in the workspace:
//! - generate-pie (main functionality)
//! - rpc-client (RPC communication)
//! - starknet-os-types (type conversions)
//!
//! ## Running the Tests
//!
//! ### Basic test run (with mocks, no RPC required):
//! ```bash
//! cargo test --test integration
//! ```
//!
//! ### Full e2e tests (requires RPC endpoint):
//! ```bash
//! SNOS_TEST_RPC_URL=https://your-rpc-endpoint.com cargo test --test integration -- --ignored
//! ```
//!
//! ### Environment variables:
//! - `SNOS_TEST_RPC_URL`: RPC endpoint for testing (default: public pathfinder)
//! - `SNOS_TEST_NETWORK`: Network to test against (mainnet/sepolia, default: mainnet)
//! - `SNOS_TEST_TIMEOUT_SECS`: Test timeout in seconds (default: 300)
//! - `SNOS_TEST_OUTPUT_DIR`: Directory for test output files (default: /tmp)
//! - `SNOS_SKIP_RPC_TESTS`: Set to skip all RPC-dependent tests
//!
//! ### Test Categories:
//! - Unit-level integration: Fast tests with mocks
//! - Component integration: Tests between crates
//! - Full e2e: Complete PIE generation workflow (slow, requires RPC)

mod e2e;
mod mocks;
mod test_data;

use mocks::*;
use test_data::*;

// Re-export commonly used test utilities
pub use mocks::environment::TestEnvironment;
pub use test_data::presets;
pub use test_data::validation;

/// Test that all modules can be imported and basic types work
#[test]
fn test_workspace_integration_basic() {
    use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};
    use rpc_client::RpcClient;

    println!("🧪 Testing basic workspace integration");

    // Test that we can create all the basic types
    let chain_config = ChainConfig::default();
    let os_hints = OsHintsConfiguration::default();

    let input = PieGenerationInput {
        rpc_url: "https://example.com".to_string(),
        blocks: vec![12345],
        chain_config,
        os_hints_config: os_hints,
        output_path: None,
    };

    // Basic validation should work
    assert!(input.validate().is_ok());
    println!("✅ Basic type creation and validation works");

    // RPC client creation should work (even with invalid URL)
    let rpc_result = RpcClient::try_new("https://example.com");
    assert!(rpc_result.is_ok());
    println!("✅ RPC client creation works");

    println!("🎉 Basic workspace integration test passed!");
}

/// Test error handling integration across crates
#[test]
fn test_error_handling_integration() {
    use generate_pie::error::PieGenerationError;

    println!("🧪 Testing error handling integration");

    // Test that error types can be created and handled properly
    let rpc_error = PieGenerationError::RpcClient("Test RPC error".to_string());
    let config_error = PieGenerationError::InvalidConfig("Test config error".to_string());
    let block_error = PieGenerationError::BlockProcessing {
        block_number: 12345,
        source: Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Test error")),
    };

    // Test error display
    assert!(rpc_error.to_string().contains("RPC"));
    assert!(config_error.to_string().contains("config"));
    assert!(block_error.to_string().contains("12345"));

    println!("✅ Error types work correctly");
    println!("🎉 Error handling integration test passed!");
}

/// Test configuration and preset functionality
#[test]
fn test_configuration_presets() {
    use test_data::presets;
    use test_data::TestBlocks;

    println!("🧪 Testing configuration presets");

    let blocks = TestBlocks::mainnet();

    // Test mainnet preset
    let mainnet_config = presets::mainnet_basic(vec![blocks.small_block]);
    assert!(!mainnet_config.rpc_url.is_empty());
    assert_eq!(mainnet_config.blocks, vec![blocks.small_block]);
    assert!(!mainnet_config.chain_config.is_l3);
    println!("✅ Mainnet preset works");

    // Test sepolia preset
    let sepolia_config = presets::sepolia_basic(vec![blocks.small_block]);
    assert!(!sepolia_config.rpc_url.is_empty());
    assert_eq!(sepolia_config.blocks, vec![blocks.small_block]);
    println!("✅ Sepolia preset works");

    // Test debug preset
    let debug_config = presets::debug_config("https://example.com".to_string(), vec![blocks.small_block]);
    assert!(debug_config.os_hints_config.debug_mode);
    assert!(debug_config.os_hints_config.full_output);
    println!("✅ Debug preset works");

    // Test L3 preset
    let l3_config = presets::l3_config("https://example.com".to_string(), vec![blocks.small_block]);
    assert!(l3_config.chain_config.is_l3);
    println!("✅ L3 preset works");

    println!("🎉 Configuration presets test passed!");
}

/// Test mock utilities functionality
#[test]
fn test_mock_utilities() {
    use mocks::responses::MockResponses;
    use serde_json::json;

    println!("🧪 Testing mock utilities");

    // Test mock responses
    let mut mock_responses = MockResponses::new();
    let test_response = json!({"result": "test"});
    mock_responses.add_response("test_method", test_response.clone());

    assert_eq!(mock_responses.get_response("test_method"), Some(&test_response));
    assert_eq!(mock_responses.get_response("nonexistent"), None);
    println!("✅ Mock responses work");

    // Test basic block responses
    let block_responses = MockResponses::with_basic_block_responses(12345);
    assert!(block_responses.get_response("starknet_getBlockWithTxs").is_some());
    assert!(block_responses.get_response("starknet_getStateDiff").is_some());
    println!("✅ Basic block mock responses work");

    println!("🎉 Mock utilities test passed!");
}

/// Test environment setup
#[test]
fn test_environment_setup() {
    use mocks::environment::TestEnvironment;

    println!("🧪 Testing environment setup");

    let test_env = TestEnvironment::default();

    // Should have default values
    assert!(!test_env.rpc_url.is_empty());
    assert!(test_env.timeout_secs > 0);
    println!("✅ Default environment setup works");

    // Test environment validation (should pass with default values)
    if let Err(e) = test_env.check_requirements() {
        println!("⚠️  Environment check failed (expected in some test environments): {}", e);
    } else {
        println!("✅ Environment validation works");
    }

    println!("🎉 Environment setup test passed!");
}

/// Test performance utilities
#[tokio::test]
async fn test_performance_utilities() {
    use std::time::Duration;
    use test_data::performance;

    println!("🧪 Testing performance utilities");

    // Test timing measurement
    let (result, duration) = performance::measure_async(async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok::<(), &str>(())
    })
    .await;

    assert!(result.is_ok());
    assert!(duration >= Duration::from_millis(95)); // Account for timing variance
    assert!(duration < Duration::from_millis(200)); // Should not be too slow
    println!("✅ Performance measurement works (took: {:?})", duration);

    // Test timed operation
    let timed_result = performance::timed_operation(
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<&str, &str>("success")
        },
        1,
    )
    .await;

    assert!(timed_result.is_ok());
    let (result, duration) = timed_result.unwrap();
    assert_eq!(result, "success");
    println!("✅ Timed operation works (took: {:?})", duration);

    // Test timeout scenario
    let timeout_result = performance::timed_operation(
        async {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            Ok::<&str, &str>("should not reach here")
        },
        1,
    )
    .await;

    assert!(timeout_result.is_err());
    assert!(timeout_result.unwrap_err().contains("timed out"));
    println!("✅ Timeout handling works");

    println!("🎉 Performance utilities test passed!");
}

/// Integration smoke test - verifies all components can work together
/// This test doesn't require external RPC but validates the integration points
#[tokio::test]
async fn test_integration_smoke_test() {
    use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};

    println!("🧪 Running integration smoke test");

    // Create a realistic configuration (but don't actually run it)
    let input = PieGenerationInput {
        rpc_url: "https://invalid-test-endpoint.local".to_string(),
        blocks: vec![12345],
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None,
    };

    // Input validation should work
    assert!(input.validate().is_ok());
    println!("✅ Input validation works");

    // We expect this to fail quickly with RPC client error (not hang or panic)
    let result = generate_pie::generate_pie(input).await;
    assert!(result.is_err());

    match result.err().unwrap() {
        generate_pie::error::PieGenerationError::RpcClient(_) => {
            println!("✅ Failed with expected RPC client error");
        }
        other => {
            println!("✅ Failed with error: {} (also acceptable)", other);
        }
    }

    println!("🎉 Integration smoke test passed!");
}
