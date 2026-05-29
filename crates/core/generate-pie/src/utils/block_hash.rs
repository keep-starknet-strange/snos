use std::collections::HashMap;

use blockifier::transaction::objects::TransactionExecutionInfo;
use starknet::core::types::{L1DataAvailabilityMode as CoreL1DataAvailabilityMode, StateDiff as CoreStateDiff};
use starknet_api::block::StarknetVersion;
use starknet_api::block_hash::block_hash_calculator::{
    calculate_block_commitments, BlockHeaderCommitments, TransactionHashingData,
};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::executable_transaction::Transaction as ExecutableTransaction;
use starknet_api::state::{StorageKey, ThinStateDiff};
use starknet_api::transaction::fields::TransactionSignature;
use starknet_types_core::felt::Felt;

use crate::conversions::convert_l1_da_mode;
use crate::error::BlockProcessingError;
use crate::utils::revert_reason::transaction_output_for_block_hash;

type StorageDiffEntries = Vec<(StorageKey, starknet_types_core::felt::Felt)>;
type StorageDiffItem = (ContractAddress, StorageDiffEntries);

pub(crate) fn tx_signature_for_hashing(tx: &ExecutableTransaction) -> TransactionSignature {
    match tx {
        ExecutableTransaction::Account(account_tx) => account_tx.signature(),
        ExecutableTransaction::L1Handler(_) => TransactionSignature::default(),
    }
}

fn build_transaction_hashing_data(
    transactions: &[ExecutableTransaction],
    tx_execution_infos: &[TransactionExecutionInfo],
    committed_revert_reasons: &HashMap<Felt, String>,
) -> Result<Vec<TransactionHashingData>, BlockProcessingError> {
    if transactions.len() != tx_execution_infos.len() {
        return Err(BlockProcessingError::new_custom(format!(
            "Transaction/execution info length mismatch: {} vs {}",
            transactions.len(),
            tx_execution_infos.len()
        )));
    }

    Ok(transactions
        .iter()
        .zip(tx_execution_infos.iter())
        .map(|(tx, tx_execution_info)| {
            // Prefer the revert reason committed on-chain (keyed by transaction hash) so the
            // recomputed receipt commitment matches the block hash regardless of sequencer version.
            let committed_revert_reason = committed_revert_reasons.get(&tx.tx_hash().0).map(String::as_str);
            let transaction_output = transaction_output_for_block_hash(tx_execution_info, committed_revert_reason);

            TransactionHashingData {
                transaction_signature: tx_signature_for_hashing(tx),
                transaction_output,
                transaction_hash: tx.tx_hash(),
            }
        })
        .collect())
}

fn contract_address_from_felt(
    address: starknet_types_core::felt::Felt,
    context: &str,
) -> Result<ContractAddress, BlockProcessingError> {
    ContractAddress::try_from(address).map_err(|error| {
        BlockProcessingError::new_custom(format!("Failed converting {context} address {address:#x}: {error:?}"))
    })
}

fn storage_key_from_felt(
    contract_address: starknet_types_core::felt::Felt,
    storage_key: starknet_types_core::felt::Felt,
) -> Result<StorageKey, BlockProcessingError> {
    StorageKey::try_from(storage_key).map_err(|error| {
        BlockProcessingError::new_custom(format!(
            "Failed converting storage key {storage_key:#x} for contract {contract_address:#x}: {error:?}"
        ))
    })
}

fn deployed_contract_items(
    state_diff: &CoreStateDiff,
) -> Result<Vec<(ContractAddress, ClassHash)>, BlockProcessingError> {
    state_diff
        .deployed_contracts
        .iter()
        .map(|contract| {
            Ok((contract_address_from_felt(contract.address, "deployed contract")?, ClassHash(contract.class_hash)))
        })
        .chain(state_diff.replaced_classes.iter().map(|class_replacement| {
            Ok((
                contract_address_from_felt(class_replacement.contract_address, "replaced contract")?,
                ClassHash(class_replacement.class_hash),
            ))
        }))
        .collect()
}

fn storage_diff_items(state_diff: &CoreStateDiff) -> Result<Vec<StorageDiffItem>, BlockProcessingError> {
    state_diff
        .storage_diffs
        .iter()
        .map(|contract_storage_diff| {
            let address = contract_address_from_felt(contract_storage_diff.address, "storage diff")?;
            let entries = contract_storage_diff
                .storage_entries
                .iter()
                .map(|entry| {
                    Ok::<_, BlockProcessingError>((
                        storage_key_from_felt(contract_storage_diff.address, entry.key)?,
                        entry.value,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((address, entries))
        })
        .collect()
}

fn class_hash_to_compiled_class_hash_items(state_diff: &CoreStateDiff) -> Vec<(ClassHash, CompiledClassHash)> {
    state_diff
        .declared_classes
        .iter()
        .map(|declared_class| {
            (ClassHash(declared_class.class_hash), CompiledClassHash(declared_class.compiled_class_hash))
        })
        .chain(state_diff.migrated_compiled_classes.iter().flatten().map(|migrated_class| {
            (ClassHash(migrated_class.class_hash), CompiledClassHash(migrated_class.compiled_class_hash))
        }))
        .collect()
}

fn deprecated_declared_classes(state_diff: &CoreStateDiff) -> Vec<ClassHash> {
    state_diff.deprecated_declared_classes.iter().map(|class_hash| ClassHash(*class_hash)).collect()
}

fn nonce_items(state_diff: &CoreStateDiff) -> Result<Vec<(ContractAddress, Nonce)>, BlockProcessingError> {
    state_diff
        .nonces
        .iter()
        .map(|nonce_update| {
            Ok((contract_address_from_felt(nonce_update.contract_address, "nonce update")?, Nonce(nonce_update.nonce)))
        })
        .collect()
}

pub(crate) fn core_state_diff_to_thin_state_diff(
    state_diff: &CoreStateDiff,
) -> Result<ThinStateDiff, BlockProcessingError> {
    let deployed_contracts_items = deployed_contract_items(state_diff)?;
    let storage_diff_items = storage_diff_items(state_diff)?;
    let class_hash_to_compiled_class_hash_items = class_hash_to_compiled_class_hash_items(state_diff);
    let deprecated_declared_classes = deprecated_declared_classes(state_diff);
    let nonce_items = nonce_items(state_diff)?;

    Ok(ThinStateDiff {
        deployed_contracts: deployed_contracts_items.into_iter().collect(),
        storage_diffs: storage_diff_items
            .into_iter()
            .map(|(address, entries)| (address, entries.into_iter().collect()))
            .collect(),
        class_hash_to_compiled_class_hash: class_hash_to_compiled_class_hash_items.into_iter().collect(),
        deprecated_declared_classes,
        nonces: nonce_items.into_iter().collect(),
    })
}

pub async fn compute_block_hash_commitments(
    transactions: &[ExecutableTransaction],
    tx_execution_infos: &[TransactionExecutionInfo],
    thin_state_diff: ThinStateDiff,
    l1_da_mode: CoreL1DataAvailabilityMode,
    starknet_version: &StarknetVersion,
    committed_revert_reasons: &HashMap<Felt, String>,
) -> Result<BlockHeaderCommitments, BlockProcessingError> {
    let transaction_hashing_data =
        build_transaction_hashing_data(transactions, tx_execution_infos, committed_revert_reasons)?;
    let (commitments, _measurements) = calculate_block_commitments(
        &transaction_hashing_data,
        thin_state_diff,
        convert_l1_da_mode(l1_da_mode),
        starknet_version,
    )
    .await;
    Ok(commitments)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rstest::rstest;
    use starknet::core::types::{
        ContractStorageDiffItem, DeclaredClassItem, DeployedContractItem, L1DataAvailabilityMode,
        MigratedCompiledClassItem, NonceUpdate, ReplacedClassItem, StateDiff, StorageEntry,
    };
    use starknet_api::executable_transaction::{
        AccountTransaction, InvokeTransaction as ExecutableInvokeTransaction, L1HandlerTransaction,
        Transaction as ExecutableTransaction,
    };
    use starknet_api::transaction::fields::TransactionSignature;
    use starknet_api::transaction::{InvokeTransaction as ApiInvokeTransaction, InvokeTransactionV1, TransactionHash};
    use starknet_types_core::felt::Felt;

    use super::{core_state_diff_to_thin_state_diff, tx_signature_for_hashing};

    fn state_diff() -> StateDiff {
        StateDiff {
            storage_diffs: vec![],
            deprecated_declared_classes: vec![],
            declared_classes: vec![],
            migrated_compiled_classes: None,
            deployed_contracts: vec![],
            replaced_classes: vec![],
            nonces: vec![],
        }
    }

    fn populated_state_diff() -> StateDiff {
        let mut diff = state_diff();
        diff.storage_diffs = vec![ContractStorageDiffItem {
            address: Felt::from(11_u64),
            storage_entries: vec![
                StorageEntry { key: Felt::from(101_u64), value: Felt::from(1001_u64) },
                StorageEntry { key: Felt::from(102_u64), value: Felt::from(1002_u64) },
            ],
        }];
        diff.deprecated_declared_classes = vec![Felt::from(21_u64)];
        diff.declared_classes =
            vec![DeclaredClassItem { class_hash: Felt::from(31_u64), compiled_class_hash: Felt::from(41_u64) }];
        diff.migrated_compiled_classes = Some(vec![MigratedCompiledClassItem {
            class_hash: Felt::from(32_u64),
            compiled_class_hash: Felt::from(42_u64),
        }]);
        diff.deployed_contracts =
            vec![DeployedContractItem { address: Felt::from(12_u64), class_hash: Felt::from(22_u64) }];
        diff.replaced_classes =
            vec![ReplacedClassItem { contract_address: Felt::from(13_u64), class_hash: Felt::from(23_u64) }];
        diff.nonces = vec![NonceUpdate { contract_address: Felt::from(14_u64), nonce: Felt::from(24_u64) }];
        diff
    }

    #[rstest]
    #[case::empty(state_diff(), [0, 0, 0, 0, 0])]
    #[case::populated(populated_state_diff(), [2, 1, 2, 1, 1])]
    fn core_state_diff_conversion_works(#[case] state_diff: StateDiff, #[case] expected_counts: [usize; 5]) {
        let thin_state_diff = core_state_diff_to_thin_state_diff(&state_diff).expect("state diff conversion");

        assert_eq!(
            [
                thin_state_diff.deployed_contracts.len(),
                thin_state_diff.storage_diffs.len(),
                thin_state_diff.class_hash_to_compiled_class_hash.len(),
                thin_state_diff.deprecated_declared_classes.len(),
                thin_state_diff.nonces.len(),
            ],
            expected_counts
        );
    }

    fn account_invoke_tx_with_signature(signature_felts: &[u64]) -> ExecutableTransaction {
        let tx = ExecutableInvokeTransaction {
            tx: ApiInvokeTransaction::V1(InvokeTransactionV1 {
                signature: TransactionSignature(Arc::new(signature_felts.iter().copied().map(Felt::from).collect())),
                ..Default::default()
            }),
            tx_hash: TransactionHash::default(),
        };
        ExecutableTransaction::Account(AccountTransaction::Invoke(tx))
    }

    #[rstest]
    #[case::account(account_invoke_tx_with_signature(&[7]), 1)]
    #[case::l1_handler(ExecutableTransaction::L1Handler(L1HandlerTransaction::default()), 0)]
    fn tx_signature_extraction_for_hashing_is_correct(
        #[case] tx: ExecutableTransaction,
        #[case] expected_signature_len: usize,
    ) {
        let signature = tx_signature_for_hashing(&tx);
        assert_eq!(signature.0.len(), expected_signature_len);
    }

    #[test]
    fn da_mode_mapping_shape_is_covered_by_compiler() {
        let blob = crate::conversions::convert_l1_da_mode(L1DataAvailabilityMode::Blob);
        let calldata = crate::conversions::convert_l1_da_mode(L1DataAvailabilityMode::Calldata);
        assert_ne!(blob, calldata);
    }
}
