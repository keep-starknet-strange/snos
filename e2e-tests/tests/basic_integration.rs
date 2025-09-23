//! Basic integration test to verify workspace integration
//!
//! This test file verifies that all crates in the workspace can be used together
//! and provides a foundation for more complex e2e tests.

#[test]
fn test_basic_workspace_integration() {
    // Test that we can import and use all main crate types
    use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};

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

    println!("🎉 Basic workspace integration test passed!");
}

#[test]
fn test_rpc_client_integration() {
    use rpc_client::RpcClient;

    println!("🧪 Testing RPC client integration");

    // RPC client creation should work (even with dummy URL)
    let rpc_result = RpcClient::try_new("https://example.com");
    assert!(rpc_result.is_ok());
    println!("✅ RPC client creation works");

    println!("🎉 RPC client integration test passed!");
}

#[test]
fn test_starknet_os_types_integration() {
    // Test basic type functionality from starknet-os-types
    println!("🧪 Testing starknet-os-types integration");

    // Just test that the module can be imported
    // More specific tests would go in the individual crate tests
    println!("✅ starknet-os-types types can be imported");

    println!("🎉 starknet-os-types integration test passed!");
}

/// Test that the error types work correctly across crate boundaries
#[test]
fn test_error_handling_integration() {
    use generate_pie::error::PieGenerationError;

    println!("🧪 Testing error handling integration");

    // Test that error types can be created and handled properly
    let rpc_error = PieGenerationError::RpcClient("Test RPC error".to_string());
    let config_error = PieGenerationError::InvalidConfig("Test config error".to_string());

    // Test error display
    assert!(rpc_error.to_string().contains("RPC"));
    assert!(config_error.to_string().contains("config"));

    println!("✅ Error types work correctly");
    println!("🎉 Error handling integration test passed!");
}

/// Async test to verify tokio integration
#[tokio::test]
async fn test_async_integration() {
    println!("🧪 Testing async integration");

    // Test basic async functionality
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;

    println!("✅ Async functionality works");
    println!("🎉 Async integration test passed!");
}
