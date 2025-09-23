//! Mock utilities for e2e testing
//!
//! This module provides mock implementations and utilities for testing
//! without requiring external dependencies like live RPC endpoints.

use serde_json::Value;
use std::collections::HashMap;

/// Mock RPC responses for testing
pub mod responses {
    use super::*;

    /// Common RPC response templates
    pub struct MockResponses {
        responses: HashMap<String, Value>,
    }

    impl MockResponses {
        pub fn new() -> Self {
            Self { responses: HashMap::new() }
        }

        /// Add a mock response for a given RPC method
        pub fn add_response(&mut self, method: &str, response: Value) {
            self.responses.insert(method.to_string(), response);
        }

        /// Get a mock response for a given method
        pub fn get_response(&self, method: &str) -> Option<&Value> {
            self.responses.get(method)
        }

        /// Create default mock responses for basic block operations
        pub fn with_basic_block_responses(block_number: u64) -> Self {
            let mut responses = Self::new();

            // Mock block response
            let block_response = serde_json::json!({
                "block_hash": format!("0x{:064x}", block_number),
                "block_number": block_number,
                "gas_used": "0x12345",
                "gas_limit": "0x67890",
                "timestamp": 1234567890,
                "transactions": [],
                "parent_hash": format!("0x{:064x}", block_number.saturating_sub(1)),
            });
            responses.add_response("starknet_getBlockWithTxs", block_response);

            // Mock state diff response
            let state_diff_response = serde_json::json!({
                "storage_diffs": [],
                "contract_classes": [],
                "nonces": [],
            });
            responses.add_response("starknet_getStateDiff", state_diff_response);

            responses
        }
    }

    impl Default for MockResponses {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Mock network conditions for testing robustness
pub mod network {
    use std::time::Duration;
    use tokio::time::sleep;

    /// Simulate network latency
    pub async fn simulate_latency(latency_ms: u64) {
        sleep(Duration::from_millis(latency_ms)).await;
    }

    /// Simulate network instability (random delays)
    pub async fn simulate_jitter(base_ms: u64, jitter_ms: u64) {
        let jitter = fastrand::u64(0..=jitter_ms);
        sleep(Duration::from_millis(base_ms + jitter)).await;
    }

    /// Network condition presets
    pub struct NetworkConditions {
        pub latency_ms: u64,
        pub jitter_ms: u64,
        pub error_rate: f64, // 0.0 to 1.0
    }

    impl NetworkConditions {
        pub fn good() -> Self {
            Self { latency_ms: 10, jitter_ms: 5, error_rate: 0.0 }
        }

        pub fn slow() -> Self {
            Self { latency_ms: 500, jitter_ms: 200, error_rate: 0.05 }
        }

        pub fn poor() -> Self {
            Self { latency_ms: 2000, jitter_ms: 1000, error_rate: 0.15 }
        }

        /// Apply these network conditions as a delay
        pub async fn apply(&self) {
            simulate_jitter(self.latency_ms, self.jitter_ms).await;

            // Simulate errors by randomly panicking (for error testing)
            if fastrand::f64() < self.error_rate {
                // In real tests, this might trigger retry logic or error handling
                println!("Simulating network error ({}% chance)", self.error_rate * 100.0);
            }
        }
    }
}

/// Mock filesystem operations
pub mod filesystem {
    use std::fs;
    use std::path::Path;

    /// Create a temporary directory for test files
    pub fn create_temp_test_dir(prefix: &str) -> Result<String, std::io::Error> {
        let temp_dir = format!("/tmp/snos_e2e_test_{}_{}", prefix, fastrand::u64(..));
        fs::create_dir_all(&temp_dir)?;
        Ok(temp_dir)
    }

    /// Clean up a test directory and all its contents
    pub fn cleanup_test_dir(path: &str) {
        if Path::new(path).exists() {
            if let Err(e) = fs::remove_dir_all(path) {
                eprintln!("Warning: Failed to cleanup test directory {}: {}", path, e);
            }
        }
    }

    /// Create a mock PIE file for testing (not a real PIE, just a file)
    pub fn create_mock_pie_file(path: &str, size_kb: usize) -> Result<(), std::io::Error> {
        let data = vec![0u8; size_kb * 1024];
        fs::write(path, data)?;
        Ok(())
    }
}

/// Test environment setup utilities
pub mod environment {
    use std::collections::HashMap;
    use std::env;

    /// Test environment configuration
    pub struct TestEnvironment {
        pub rpc_url: String,
        pub network: String,
        pub timeout_secs: u64,
        pub output_dir: Option<String>,
    }

    impl TestEnvironment {
        /// Load test environment from environment variables
        pub fn from_env() -> Self {
            Self {
                rpc_url: env::var("SNOS_TEST_RPC_URL")
                    .unwrap_or_else(|_| "https://pathfinder-mainnet.d.karnot.xyz".to_string()),
                network: env::var("SNOS_TEST_NETWORK").unwrap_or_else(|_| "mainnet".to_string()),
                timeout_secs: env::var("SNOS_TEST_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()
                    .unwrap_or(300),
                output_dir: env::var("SNOS_TEST_OUTPUT_DIR").ok(),
            }
        }

        /// Set up environment variables for testing
        pub fn setup_env_vars(&self) {
            env::set_var("SNOS_TEST_RPC_URL", &self.rpc_url);
            env::set_var("SNOS_TEST_NETWORK", &self.network);
            env::set_var("SNOS_TEST_TIMEOUT_SECS", self.timeout_secs.to_string());
            if let Some(ref output_dir) = self.output_dir {
                env::set_var("SNOS_TEST_OUTPUT_DIR", output_dir);
            }
        }

        /// Check if required environment is available for testing
        pub fn check_requirements(&self) -> Result<(), String> {
            // Basic URL validation
            if !self.rpc_url.starts_with("http") {
                return Err(format!("Invalid RPC URL: {}", self.rpc_url));
            }

            // Check if output directory is writable if specified
            if let Some(ref output_dir) = self.output_dir {
                if let Err(e) = std::fs::create_dir_all(output_dir) {
                    return Err(format!("Cannot create output directory {}: {}", output_dir, e));
                }
            }

            Ok(())
        }
    }

    impl Default for TestEnvironment {
        fn default() -> Self {
            Self::from_env()
        }
    }
}

/// Utility macros for e2e testing
#[macro_export]
macro_rules! skip_if_no_rpc {
    ($test_env:expr) => {
        if std::env::var("SNOS_SKIP_RPC_TESTS").is_ok() {
            println!("⏭️  Skipping RPC test (SNOS_SKIP_RPC_TESTS is set)");
            return;
        }
        if let Err(e) = $test_env.check_requirements() {
            println!("⏭️  Skipping test due to environment issue: {}", e);
            return;
        }
    };
}

#[macro_export]
macro_rules! cleanup_on_panic {
    ($cleanup_fn:expr) => {
        struct Guard<F: FnOnce()>(Option<F>);
        impl<F: FnOnce()> Drop for Guard<F> {
            fn drop(&mut self) {
                if let Some(f) = self.0.take() {
                    f();
                }
            }
        }
        let _guard = Guard(Some($cleanup_fn));
    };
}
