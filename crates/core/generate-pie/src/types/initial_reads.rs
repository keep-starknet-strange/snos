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
use std::future::Future;

pub(crate) fn capture_extended_initial_reads<S: StateReader>(
    block_state: &CachedState<S>,
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
    extend_initial_reads_storage_with_fetcher(
        initial_reads,
        accessed_keys_by_address,
        |contract_address, storage_key| async move {
            state_reader.get_storage_at_async(contract_address, storage_key).await
        },
    )
    .await
}

fn hydrate_initial_reads<S: StateReader>(
    block_state: &CachedState<S>,
    hydration_targets: &StateMaps,
) -> Result<(), BlockProcessingError> {
    hydrate_initial_read_contract_metadata(block_state, hydration_targets)?;
    hydrate_initial_read_declared_classes(block_state, hydration_targets)
}

fn get_extended_initial_reads_snapshot<S: StateReader>(
    block_state: &CachedState<S>,
) -> Result<StateMaps, BlockProcessingError> {
    let mut initial_reads = get_initial_reads_snapshot(block_state, "capture hydrated initial reads")?;
    // `declared_contracts` is only used to discover which compiled class hashes must be hydrated.
    initial_reads.declared_contracts.clear();
    Ok(initial_reads)
}

fn get_initial_reads_snapshot<S: StateReader>(
    block_state: &CachedState<S>,
    context: &str,
) -> Result<StateMaps, BlockProcessingError> {
    block_state
        .get_initial_reads()
        .map_err(|source| BlockProcessingError::InitialReadsSnapshot { context: context.to_string(), source })
}

fn hydrate_initial_read_contract_metadata<S: StateReader>(
    block_state: &CachedState<S>,
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

fn hydrate_initial_read_declared_classes<S: StateReader>(
    block_state: &CachedState<S>,
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
async fn extend_initial_reads_storage_with_fetcher<F, Fut>(
    initial_reads: &mut StateMaps,
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
    fetch_storage_at: F,
) -> Result<(), StateError>
where
    F: Clone + Send + Fn(ContractAddress, StorageKey) -> Fut,
    Fut: Future<Output = Result<Felt, StateError>> + Send,
{
    let missing_entries = collect_missing_initial_read_storage_entries(initial_reads, accessed_keys_by_address);
    if missing_entries.is_empty() {
        return Ok(());
    }

    let fetched_entries = fetch_missing_initial_read_storage_entries_with(&missing_entries, fetch_storage_at).await?;
    initial_reads.storage.extend(fetched_entries);
    Ok(())
}

async fn fetch_missing_initial_read_storage_entries_with<F, Fut>(
    missing_entries: &[(ContractAddress, StorageKey)],
    fetch_storage_at: F,
) -> Result<Vec<((ContractAddress, StorageKey), Felt)>, StateError>
where
    F: Clone + Send + Fn(ContractAddress, StorageKey) -> Fut,
    Fut: Future<Output = Result<Felt, StateError>> + Send,
{
    stream::iter(missing_entries.iter().copied())
        .map(move |(contract_address, storage_key)| {
            let fetch_storage_at = fetch_storage_at.clone();

            async move {
                let value = fetch_storage_at(contract_address, storage_key).await?;
                Ok::<_, StateError>(((contract_address, storage_key), value))
            }
        })
        .buffer_unordered(MAX_CONCURRENT_INITIAL_READ_STORAGE_FETCHES)
        .try_collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{ALIAS_CONTRACT_ADDRESS, BLOCK_HASH_CONTRACT_ADDRESS};
    use blockifier::execution::contract_class::{CompiledClassV0, RunnableCompiledClass};
    use blockifier::state::cached_state::CachedState;
    use blockifier::state::state_api::StateReader;
    use blockifier::test_utils::dict_state_reader::DictStateReader;
    use starknet_api::contract_address;
    use starknet_api::core::{ClassHash, CompiledClassHash, Nonce};
    use std::sync::{Arc, Mutex};

    fn storage_key(value: u8) -> StorageKey {
        StorageKey::try_from(Felt::from(value)).unwrap()
    }

    #[test]
    fn collect_missing_initial_read_storage_entries_only_returns_absent_entries() {
        let mut initial_reads = StateMaps::default();
        let existing_key = storage_key(1);
        let missing_key = storage_key(2);
        let alias_key = storage_key(3);

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

    #[test]
    fn capture_extended_initial_reads_hydrates_contract_metadata_and_clears_declared_contracts() {
        let contract_address = contract_address!("0x123");
        let contract_storage_key = storage_key(7);
        let contract_class_hash = ClassHash(Felt::from(33_u8));
        let block_hash_class_hash = ClassHash(Felt::from(44_u8));
        let alias_class_hash = ClassHash(Felt::from(55_u8));
        let declared_class_hash = ClassHash(Felt::from(66_u8));
        let declared_compiled_class_hash = CompiledClassHash(Felt::from(77_u8));

        let mut state_reader = DictStateReader::default();
        state_reader.storage_view.insert((contract_address, contract_storage_key), Felt::from(11_u8));
        state_reader.address_to_class_hash.insert(contract_address, contract_class_hash);
        state_reader.address_to_nonce.insert(contract_address, Nonce(Felt::from(7_u8)));
        state_reader.address_to_class_hash.insert(BLOCK_HASH_CONTRACT_ADDRESS, block_hash_class_hash);
        state_reader.address_to_nonce.insert(BLOCK_HASH_CONTRACT_ADDRESS, Nonce(Felt::ONE));
        state_reader.address_to_class_hash.insert(ALIAS_CONTRACT_ADDRESS, alias_class_hash);
        state_reader.address_to_nonce.insert(ALIAS_CONTRACT_ADDRESS, Nonce(Felt::from(2_u8)));
        state_reader
            .class_hash_to_class
            .insert(declared_class_hash, RunnableCompiledClass::V0(CompiledClassV0::default()));
        state_reader.class_hash_to_compiled_class_hash.insert(declared_class_hash, declared_compiled_class_hash);

        let block_state = CachedState::new(state_reader);
        block_state.get_storage_at(contract_address, contract_storage_key).unwrap();
        block_state.get_compiled_class(declared_class_hash).unwrap();

        let initial_reads = capture_extended_initial_reads(&block_state).unwrap();

        assert_eq!(initial_reads.storage.get(&(contract_address, contract_storage_key)), Some(&Felt::from(11_u8)));
        assert_eq!(initial_reads.class_hashes.get(&contract_address), Some(&contract_class_hash));
        assert_eq!(initial_reads.nonces.get(&contract_address), Some(&Nonce(Felt::from(7_u8))));
        assert_eq!(initial_reads.class_hashes.get(&BLOCK_HASH_CONTRACT_ADDRESS), Some(&block_hash_class_hash));
        assert_eq!(initial_reads.nonces.get(&BLOCK_HASH_CONTRACT_ADDRESS), Some(&Nonce(Felt::ONE)));
        assert_eq!(initial_reads.class_hashes.get(&ALIAS_CONTRACT_ADDRESS), Some(&alias_class_hash));
        assert_eq!(initial_reads.nonces.get(&ALIAS_CONTRACT_ADDRESS), Some(&Nonce(Felt::from(2_u8))));
        assert_eq!(initial_reads.compiled_class_hashes.get(&declared_class_hash), Some(&declared_compiled_class_hash));
        assert!(initial_reads.declared_contracts.is_empty());
    }

    #[tokio::test]
    async fn extend_initial_reads_storage_fetches_only_missing_entries() {
        let existing_key = storage_key(1);
        let missing_key = storage_key(2);
        let alias_key = storage_key(3);
        let missing_entries = Arc::new(HashMap::from([
            ((BLOCK_HASH_CONTRACT_ADDRESS, missing_key), Felt::from(22_u8)),
            ((ALIAS_CONTRACT_ADDRESS, alias_key), Felt::from(33_u8)),
        ]));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let mut initial_reads = StateMaps::default();
        initial_reads.storage.insert((BLOCK_HASH_CONTRACT_ADDRESS, existing_key), Felt::from(11_u8));

        let accessed_keys_by_address = HashMap::from([
            (BLOCK_HASH_CONTRACT_ADDRESS, HashSet::from([existing_key, missing_key])),
            (ALIAS_CONTRACT_ADDRESS, HashSet::from([alias_key])),
        ]);

        extend_initial_reads_storage_with_fetcher(&mut initial_reads, &accessed_keys_by_address, {
            let missing_entries = Arc::clone(&missing_entries);
            let requests = Arc::clone(&requests);

            move |contract_address, storage_key| {
                let missing_entries = Arc::clone(&missing_entries);
                let requests = Arc::clone(&requests);

                async move {
                    requests.lock().unwrap().push((contract_address, storage_key));
                    missing_entries
                        .get(&(contract_address, storage_key))
                        .copied()
                        .ok_or_else(|| StateError::StateReadError("missing test storage value".to_string()))
                }
            }
        })
        .await
        .unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.contains(&(BLOCK_HASH_CONTRACT_ADDRESS, missing_key)));
        assert!(requests.contains(&(ALIAS_CONTRACT_ADDRESS, alias_key)));

        assert_eq!(initial_reads.storage.get(&(BLOCK_HASH_CONTRACT_ADDRESS, existing_key)), Some(&Felt::from(11_u8)));
        assert_eq!(initial_reads.storage.get(&(BLOCK_HASH_CONTRACT_ADDRESS, missing_key)), Some(&Felt::from(22_u8)));
        assert_eq!(initial_reads.storage.get(&(ALIAS_CONTRACT_ADDRESS, alias_key)), Some(&Felt::from(33_u8)));
    }
}
