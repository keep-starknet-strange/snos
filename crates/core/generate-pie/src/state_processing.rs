use starknet::core::types::BlockId;
use starknet_os::io::os_input::CachedStateInput;
use std::collections::HashMap;

/// Represents the previous BlockId for the current scope
/// Defaults to None when the current BlockId is 0
pub type PreviousBlockId = Option<BlockId>;

/// Error type for state processing operations
#[derive(Debug, thiserror::Error)]
pub enum StateProcessingError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] starknet::providers::ProviderError),
    #[error("State processing error: {0}")]
    ProcessingError(String),
}

/// Helper function to create a complete CachedStateInput
///
/// This can combine multiple state updates if needed
#[allow(dead_code)]
pub fn merge_cached_state_inputs(inputs: &[CachedStateInput]) -> CachedStateInput {
    let mut merged = CachedStateInput {
        storage: HashMap::new(),
        address_to_class_hash: HashMap::new(),
        address_to_nonce: HashMap::new(),
        class_hash_to_compiled_class_hash: HashMap::new(),
    };

    for input in inputs {
        // Merge storage
        for (address, storage) in &input.storage {
            merged
                .storage
                .entry(*address)
                .or_default()
                .extend(storage.clone());
        }

        // Merge other mappings (later entries overwrite earlier ones)
        merged
            .address_to_class_hash
            .extend(&input.address_to_class_hash);
        merged.address_to_nonce.extend(&input.address_to_nonce);
        merged
            .class_hash_to_compiled_class_hash
            .extend(&input.class_hash_to_compiled_class_hash);
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_cached_state_inputs_empty() {
        let merged = merge_cached_state_inputs(&[]);
        assert!(merged.storage.is_empty());
        assert!(merged.address_to_class_hash.is_empty());
        assert!(merged.address_to_nonce.is_empty());
        assert!(merged.class_hash_to_compiled_class_hash.is_empty());
    }

    // #[test]
    // fn test_processed_state_update_structure() {
    //     let processed = ProcessedStateUpdate {
    //         cached_state_input: CachedStateInput::default(),
    //         compiled_classes: BTreeMap::new(),
    //         deprecated_compiled_classes: BTreeMap::new(),
    //         declared_class_hash_component_hashes: HashMap::new(),
    //     };

    //     // Test that structure is correctly organized
    //     assert!(processed.compiled_classes.is_empty());
    //     assert!(processed.deprecated_compiled_classes.is_empty());
    // }

    // TODO: Add integration tests with RPC client
    // This would require setting up test infrastructure
}

// TODO: Functions to implement for full functionality:
// 1. get_subcalled_contracts_from_tx_traces() - Extract contract addresses from traces
// 2. build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash() - Class compilation
// 3. format_declared_classes() - Format declared classes for OS consumption
// 4. compile_contract_class() - Compile Sierra to CASM
// 5. Full integration with commitment_utils for creating complete OsBlockInput
