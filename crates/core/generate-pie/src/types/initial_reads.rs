use crate::constants::{MAX_CONCURRENT_INITIAL_READ_STORAGE_FETCHES, SPECIAL_CONTRACT_ADDRESSES};
use crate::error::BlockProcessingError;
use blockifier::state::cached_state::{CachedState, StateMaps};
use blockifier::state::errors::StateError;
use blockifier::state::state_api::StateReader;
use futures::stream::{self, StreamExt, TryStreamExt};
use rpc_client::state_reader::AsyncRpcStateReader;
use starknet_api::core::ContractAddress;
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};

pub(crate) fn capture_extended_initial_reads(
    block_state: &CachedState<AsyncRpcStateReader>,
) -> Result<StateMaps, BlockProcessingError> {
    // The first snapshot tells us which metadata needs to be hydrated into Blockifier's witness.
    // The second snapshot captures that expanded witness after those reads have been forced.
    let hydration_targets = get_initial_reads_snapshot(block_state, "capture initial reads for hydration")?;
    hydrate_initial_reads(block_state, &hydration_targets)?;
    get_extended_initial_reads_snapshot(block_state)
}

pub(crate) fn accessed_keys_from_initial_reads(
    initial_reads: &StateMaps,
) -> HashMap<ContractAddress, HashSet<StorageKey>> {
    let mut accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>> = HashMap::new();

    for (contract_address, storage_key) in initial_reads.storage.keys() {
        accessed_keys_by_address.entry(*contract_address).or_default().insert(*storage_key);
    }

    accessed_keys_by_address
}

/// Extends `initial_reads.storage` with storage entries that SNOS adds after execution.
///
/// Blockifier records only storage cells that were actually read during transaction execution.
/// SNOS later augments the witness with synthetic reads for OS/proof completeness, most notably:
/// - block-hash contract (`0x1`) keys used during OS preprocessing and `get_block_hash_syscall`
/// - alias contract (`0x2`) keys introduced by stateful storage/class mapping
///
/// These cells must be fetched from the same pre-state used by execution, otherwise stateless OS
/// replay can panic when it encounters a synthetic key that is not present in `initial_reads`.
pub(crate) async fn extend_initial_reads_storage(
    state_reader: &AsyncRpcStateReader,
    initial_reads: &mut StateMaps,
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
) -> Result<(), StateError> {
    let missing_entries = collect_missing_initial_read_storage_entries(initial_reads, accessed_keys_by_address);
    if missing_entries.is_empty() {
        return Ok(());
    }

    let fetched_entries = fetch_missing_initial_read_storage_entries(state_reader, &missing_entries).await?;

    for (storage_entry, value) in fetched_entries {
        initial_reads.storage.insert(storage_entry, value);
    }

    Ok(())
}

fn hydrate_initial_reads(
    block_state: &CachedState<AsyncRpcStateReader>,
    hydration_targets: &StateMaps,
) -> Result<(), BlockProcessingError> {
    hydrate_initial_read_contract_metadata(block_state, hydration_targets)?;
    hydrate_initial_read_declared_classes(block_state, hydration_targets)
}

fn get_extended_initial_reads_snapshot(
    block_state: &CachedState<AsyncRpcStateReader>,
) -> Result<StateMaps, BlockProcessingError> {
    let mut initial_reads = get_initial_reads_snapshot(block_state, "capture hydrated initial reads")?;
    // `declared_contracts` is only used to discover which compiled class hashes must be hydrated.
    initial_reads.declared_contracts.clear();
    Ok(initial_reads)
}

fn get_initial_reads_snapshot(
    block_state: &CachedState<AsyncRpcStateReader>,
    context: &str,
) -> Result<StateMaps, BlockProcessingError> {
    block_state
        .get_initial_reads()
        .map_err(|source| BlockProcessingError::InitialReadsSnapshot { context: context.to_string(), source })
}

fn hydrate_initial_read_contract_metadata(
    block_state: &CachedState<AsyncRpcStateReader>,
    raw_initial_reads: &StateMaps,
) -> Result<(), BlockProcessingError> {
    let mut hydrated_contract_addresses = raw_initial_reads.get_contract_addresses();
    hydrated_contract_addresses.extend(SPECIAL_CONTRACT_ADDRESSES);

    for contract_address in hydrated_contract_addresses {
        block_state
            .get_class_hash_at(contract_address)
            .map_err(|source| BlockProcessingError::InitialReadClassHashHydration { contract_address, source })?;
        block_state
            .get_nonce_at(contract_address)
            .map_err(|source| BlockProcessingError::InitialReadNonceHydration { contract_address, source })?;
    }

    Ok(())
}

fn hydrate_initial_read_declared_classes(
    block_state: &CachedState<AsyncRpcStateReader>,
    raw_initial_reads: &StateMaps,
) -> Result<(), BlockProcessingError> {
    for class_hash in raw_initial_reads.declared_contracts.keys().copied().collect::<Vec<_>>() {
        block_state
            .get_compiled_class_hash(class_hash)
            .map_err(|source| BlockProcessingError::InitialReadCompiledClassHashHydration { class_hash, source })?;
    }

    Ok(())
}

/// Returns only the storage entries that were added to the SNOS witness after execution and are
/// therefore absent from Blockifier's raw `initial_reads.storage`.
fn collect_missing_initial_read_storage_entries(
    initial_reads: &StateMaps,
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
) -> Vec<(ContractAddress, StorageKey)> {
    let mut missing_entries = Vec::new();

    for (contract_address, storage_keys) in accessed_keys_by_address {
        for storage_key in storage_keys {
            let storage_entry = (*contract_address, *storage_key);
            if !initial_reads.storage.contains_key(&storage_entry) {
                missing_entries.push(storage_entry);
            }
        }
    }
    missing_entries
}

/// Fetches missing witness cells concurrently because each lookup is an independent pre-state RPC
/// read against the same block snapshot.
async fn fetch_missing_initial_read_storage_entries(
    state_reader: &AsyncRpcStateReader,
    missing_entries: &[(ContractAddress, StorageKey)],
) -> Result<Vec<((ContractAddress, StorageKey), Felt)>, StateError> {
    stream::iter(missing_entries.iter().copied())
        .map(|(contract_address, storage_key)| async move {
            let value = state_reader.get_storage_at_async(contract_address, storage_key).await?;
            Ok::<_, StateError>(((contract_address, storage_key), value))
        })
        .buffer_unordered(MAX_CONCURRENT_INITIAL_READ_STORAGE_FETCHES)
        .try_collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{ALIAS_CONTRACT_ADDRESS, BLOCK_HASH_CONTRACT_ADDRESS};

    #[test]
    fn collect_missing_initial_read_storage_entries_only_returns_absent_entries() {
        let mut initial_reads = StateMaps::default();
        let existing_key = StorageKey::try_from(Felt::ONE).unwrap();
        let missing_key = StorageKey::try_from(Felt::from(2_u8)).unwrap();
        let alias_key = StorageKey::try_from(Felt::from(3_u8)).unwrap();

        initial_reads.storage.insert((BLOCK_HASH_CONTRACT_ADDRESS, existing_key), Felt::from(11_u8));

        let accessed_keys_by_address = HashMap::from([
            (BLOCK_HASH_CONTRACT_ADDRESS, HashSet::from([existing_key, missing_key])),
            (ALIAS_CONTRACT_ADDRESS, HashSet::from([alias_key])),
        ]);

        let missing_entries = collect_missing_initial_read_storage_entries(&initial_reads, &accessed_keys_by_address);

        assert_eq!(missing_entries.len(), 2);
        assert!(missing_entries.contains(&(BLOCK_HASH_CONTRACT_ADDRESS, missing_key)));
        assert!(missing_entries.contains(&(ALIAS_CONTRACT_ADDRESS, alias_key)));
    }
}
