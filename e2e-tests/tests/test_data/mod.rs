//! Test data and utilities for e2e testing
//!
//! This module provides commonly used test data, block numbers,
//! and utility functions for consistent testing across e2e tests.

use std::collections::HashMap;

/// Well-known test block numbers that are likely to work across different networks
pub struct TestBlocks {
    /// A small, early block that should be fast to process
    pub small_block: u64,
    /// A medium-sized block with moderate complexity
    pub medium_block: u64,
    /// A larger block with more transactions (may take longer)
    pub large_block: u64,
    /// Consecutive blocks for multi-block testing
    pub consecutive_blocks: Vec<u64>,
}

impl TestBlocks {
    /// Get test blocks for mainnet
    pub fn mainnet() -> Self {
        Self {
            small_block: 10000,
            medium_block: 200000,
            large_block: 500000,
            consecutive_blocks: vec![200000, 200001, 200002],
        }
    }

    /// Get test blocks for sepolia testnet
    pub fn sepolia() -> Self {
        Self {
            small_block: 1000,
            medium_block: 50000,
            large_block: 100000,
            consecutive_blocks: vec![50000, 50001, 50002],
        }
    }

    /// Get all test blocks as a vector
    pub fn all(&self) -> Vec<u64> {
        let mut blocks = vec![self.small_block, self.medium_block, self.large_block];
        blocks.extend(&self.consecutive_blocks);
        blocks.sort();
        blocks.dedup();
        blocks
    }
}

/// Test RPC endpoints for different networks
#[derive(Debug, Clone)]
pub struct TestRpcEndpoints {
    pub mainnet: Vec<String>,
    pub sepolia: Vec<String>,
    pub integration: Vec<String>,
}

impl Default for TestRpcEndpoints {
    fn default() -> Self {
        Self {
            mainnet: vec![
                "https://pathfinder-mainnet.d.karnot.xyz".to_string(),
                "https://starknet-mainnet.public.blastapi.io".to_string(),
            ],
            sepolia: vec![
                "https://pathfinder-sepolia.d.karnot.xyz".to_string(),
                "https://starknet-sepolia.public.blastapi.io".to_string(),
            ],
            integration: vec!["http://localhost:9545".to_string(), "http://127.0.0.1:9545".to_string()],
        }
    }
}

impl TestRpcEndpoints {
    /// Get the primary RPC endpoint for a given network
    pub fn primary(&self, network: &str) -> Option<String> {
        match network.to_lowercase().as_str() {
            "mainnet" => self.mainnet.first().cloned(),
            "sepolia" => self.sepolia.first().cloned(),
            "integration" | "local" => self.integration.first().cloned(),
            _ => None,
        }
    }

    /// Get all RPC endpoints for a given network
    pub fn all(&self, network: &str) -> Vec<String> {
        match network.to_lowercase().as_str() {
            "mainnet" => self.mainnet.clone(),
            "sepolia" => self.sepolia.clone(),
            "integration" | "local" => self.integration.clone(),
            _ => Vec::new(),
        }
    }
}

/// Test configuration presets
pub mod presets {
    use super::*;
    use generate_pie::types::{ChainConfig, OsHintsConfiguration, PieGenerationInput};

    /// Create a basic test configuration for mainnet
    pub fn mainnet_basic(blocks: Vec<u64>) -> PieGenerationInput {
        PieGenerationInput {
            rpc_url: TestRpcEndpoints::default().primary("mainnet").unwrap(),
            blocks,
            chain_config: ChainConfig::default(), // Mainnet defaults
            os_hints_config: OsHintsConfiguration::default(),
            output_path: None,
        }
    }

    /// Create a basic test configuration for sepolia
    pub fn sepolia_basic(blocks: Vec<u64>) -> PieGenerationInput {
        let mut chain_config = ChainConfig::default();
        // Sepolia-specific configuration would go here
        // For now, using defaults which should work for sepolia too

        PieGenerationInput {
            rpc_url: TestRpcEndpoints::default().primary("sepolia").unwrap(),
            blocks,
            chain_config,
            os_hints_config: OsHintsConfiguration::default(),
            output_path: None,
        }
    }

    /// Create a debug-enabled configuration
    pub fn debug_config(rpc_url: String, blocks: Vec<u64>) -> PieGenerationInput {
        let mut os_hints = OsHintsConfiguration::default();
        os_hints.debug_mode = true;
        os_hints.full_output = true;

        PieGenerationInput {
            rpc_url,
            blocks,
            chain_config: ChainConfig::default(),
            os_hints_config: os_hints,
            output_path: None,
        }
    }

    /// Create an L3-enabled configuration
    pub fn l3_config(rpc_url: String, blocks: Vec<u64>) -> PieGenerationInput {
        let mut chain_config = ChainConfig::default();
        chain_config.is_l3 = true;

        PieGenerationInput {
            rpc_url,
            blocks,
            chain_config,
            os_hints_config: OsHintsConfiguration::default(),
            output_path: None,
        }
    }
}

/// Utility functions for test validation
pub mod validation {
    use std::fs;
    use std::path::Path;

    /// Validate that a PIE file exists and has reasonable size
    pub fn validate_pie_file(path: &str) -> Result<u64, String> {
        if !Path::new(path).exists() {
            return Err(format!("PIE file does not exist: {}", path));
        }

        let metadata = fs::metadata(path).map_err(|e| format!("Cannot read PIE file metadata: {}", e))?;

        let size = metadata.len();

        // PIE files should be at least a few KB
        if size < 1024 {
            return Err(format!("PIE file suspiciously small: {} bytes", size));
        }

        // PIE files shouldn't be unreasonably large (> 1GB seems suspicious)
        if size > 1_000_000_000 {
            return Err(format!("PIE file suspiciously large: {} bytes", size));
        }

        Ok(size)
    }

    /// Clean up test files
    pub fn cleanup_test_files(patterns: &[&str]) {
        for pattern in patterns {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries.flatten() {
                    if let Err(e) = fs::remove_file(&entry) {
                        eprintln!("Warning: Failed to cleanup {}: {}", entry.display(), e);
                    }
                }
            }
        }
    }
}

/// Mock data for testing error conditions
pub mod error_scenarios {
    use super::*;

    /// Invalid RPC URLs for testing error handling
    pub fn invalid_rpc_urls() -> Vec<String> {
        vec![
            "not-a-url".to_string(),
            "http://".to_string(),
            "https://nonexistent.invalid:12345".to_string(),
            "http://127.0.0.1:99999".to_string(), // Port likely not in use
            "ftp://invalid-protocol.com".to_string(),
        ]
    }

    /// Block numbers that are likely to cause errors
    pub fn problematic_blocks() -> Vec<u64> {
        vec![
            0,          // Genesis block might have special handling
            u64::MAX,   // Definitely doesn't exist
            99_999_999, // Very high block number
        ]
    }

    /// Invalid output paths for testing I/O errors
    pub fn invalid_output_paths() -> Vec<String> {
        vec![
            "/root/restricted.pie".to_string(),
            "/nonexistent/path/output.pie".to_string(),
            "".to_string(), // Empty path
            "/dev/null/cannot_create_file_here.pie".to_string(),
        ]
    }
}

/// Performance test utilities
pub mod performance {
    use std::time::{Duration, Instant};
    use tokio::time::timeout;

    /// Measure execution time of an async function
    pub async fn measure_async<F, T, E>(operation: F) -> (Result<T, E>, Duration)
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        let start = Instant::now();
        let result = operation.await;
        let duration = start.elapsed();
        (result, duration)
    }

    /// Run an operation with timeout and measure performance
    pub async fn timed_operation<F, T, E>(operation: F, timeout_secs: u64) -> Result<(T, Duration), String>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let start = Instant::now();

        match timeout(Duration::from_secs(timeout_secs), operation).await {
            Ok(Ok(result)) => {
                let duration = start.elapsed();
                Ok((result, duration))
            }
            Ok(Err(e)) => Err(format!("Operation failed: {}", e)),
            Err(_) => Err(format!("Operation timed out after {} seconds", timeout_secs)),
        }
    }

    /// Performance thresholds for different types of operations
    pub struct PerformanceThresholds {
        pub single_block_max_secs: u64,
        pub multi_block_max_secs: u64,
        pub rpc_connection_max_secs: u64,
    }

    impl Default for PerformanceThresholds {
        fn default() -> Self {
            Self {
                single_block_max_secs: 300,  // 5 minutes
                multi_block_max_secs: 600,   // 10 minutes
                rpc_connection_max_secs: 30, // 30 seconds
            }
        }
    }
}
