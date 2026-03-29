use blockifier::transaction::objects::TransactionExecutionInfo;
use starknet::core::types::{L1DataAvailabilityMode as CoreL1DataAvailabilityMode, StateDiff as CoreStateDiff};
use starknet_api::block::StarknetVersion;
use starknet_api::block_hash::block_hash_calculator::{
    calculate_block_commitments, BlockHeaderCommitments, TransactionHashingData,
};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::L1DataAvailabilityMode;
use starknet_api::executable_transaction::Transaction as ExecutableTransaction;
use starknet_api::state::{StorageKey, ThinStateDiff};
use starknet_api::transaction::fields::TransactionSignature;

use crate::error::BlockProcessingError;
use crate::utils::revert_reason::transaction_output_for_block_hash;

fn convert_da_mode(mode: CoreL1DataAvailabilityMode) -> L1DataAvailabilityMode {
    match mode {
        CoreL1DataAvailabilityMode::Blob => L1DataAvailabilityMode::Blob,
        CoreL1DataAvailabilityMode::Calldata => L1DataAvailabilityMode::Calldata,
    }
}

pub(crate) fn tx_signature_for_hashing(tx: &ExecutableTransaction) -> TransactionSignature {
    match tx {
        ExecutableTransaction::Account(account_tx) => account_tx.signature(),
        ExecutableTransaction::L1Handler(_) => TransactionSignature::default(),
    }
}

fn build_transaction_hashing_data(
    transactions: &[ExecutableTransaction],
    tx_execution_infos: &[TransactionExecutionInfo],
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
        .map(|(tx, tx_execution_info)| TransactionHashingData {
            transaction_signature: tx_signature_for_hashing(tx),
            transaction_output: transaction_output_for_block_hash(tx_execution_info),
            transaction_hash: tx.tx_hash(),
        })
        .collect())
}

pub(crate) fn core_state_diff_to_thin_state_diff(
    state_diff: &CoreStateDiff,
) -> Result<ThinStateDiff, BlockProcessingError> {
    let deployed_contracts_items: Vec<(ContractAddress, ClassHash)> = state_diff
        .deployed_contracts
        .iter()
        .map(|contract| {
            let address = ContractAddress::try_from(contract.address).map_err(|e| {
                BlockProcessingError::new_custom(format!(
                    "Failed converting deployed contract address {:#x}: {:?}",
                    contract.address, e
                ))
            })?;
            Ok::<(ContractAddress, ClassHash), BlockProcessingError>((address, ClassHash(contract.class_hash)))
        })
        .chain(state_diff.replaced_classes.iter().map(|class_replacement| {
            let address = ContractAddress::try_from(class_replacement.contract_address).map_err(|e| {
                BlockProcessingError::new_custom(format!(
                    "Failed converting replaced contract address {:#x}: {:?}",
                    class_replacement.contract_address, e
                ))
            })?;
            Ok::<(ContractAddress, ClassHash), BlockProcessingError>((address, ClassHash(class_replacement.class_hash)))
        }))
        .collect::<Result<_, _>>()?;

    let storage_diff_items: Vec<(ContractAddress, Vec<(StorageKey, starknet_types_core::felt::Felt)>)> = state_diff
        .storage_diffs
        .iter()
        .map(|contract_storage_diff| {
            let address = ContractAddress::try_from(contract_storage_diff.address).map_err(|e| {
                BlockProcessingError::new_custom(format!(
                    "Failed converting storage diff address {:#x}: {:?}",
                    contract_storage_diff.address, e
                ))
            })?;
            let entries = contract_storage_diff
                .storage_entries
                .iter()
                .map(|entry| {
                    let key = StorageKey::try_from(entry.key).map_err(|e| {
                        BlockProcessingError::new_custom(format!(
                            "Failed converting storage key {:#x} for contract {:#x}: {:?}",
                            entry.key, contract_storage_diff.address, e
                        ))
                    })?;
                    Ok::<(StorageKey, starknet_types_core::felt::Felt), BlockProcessingError>((key, entry.value))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<(ContractAddress, Vec<(StorageKey, starknet_types_core::felt::Felt)>), BlockProcessingError>((
                address, entries,
            ))
        })
        .collect::<Result<_, _>>()?;

    let class_hash_to_compiled_class_hash_items: Vec<(ClassHash, CompiledClassHash)> = state_diff
        .declared_classes
        .iter()
        .map(|declared_class| {
            (ClassHash(declared_class.class_hash), CompiledClassHash(declared_class.compiled_class_hash))
        })
        .chain(state_diff.migrated_compiled_classes.iter().flatten().map(|migrated_class| {
            (ClassHash(migrated_class.class_hash), CompiledClassHash(migrated_class.compiled_class_hash))
        }))
        .collect();

    let deprecated_declared_classes: Vec<ClassHash> =
        state_diff.deprecated_declared_classes.iter().map(|class_hash| ClassHash(*class_hash)).collect();

    let nonce_items: Vec<(ContractAddress, Nonce)> = state_diff
        .nonces
        .iter()
        .map(|nonce_update| {
            let address = ContractAddress::try_from(nonce_update.contract_address).map_err(|e| {
                BlockProcessingError::new_custom(format!(
                    "Failed converting nonce update address {:#x}: {:?}",
                    nonce_update.contract_address, e
                ))
            })?;
            Ok::<(ContractAddress, Nonce), BlockProcessingError>((address, Nonce(nonce_update.nonce)))
        })
        .collect::<Result<_, _>>()?;

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
    thin_state_diff: &ThinStateDiff,
    l1_da_mode: CoreL1DataAvailabilityMode,
    starknet_version: &StarknetVersion,
) -> Result<BlockHeaderCommitments, BlockProcessingError> {
    let transaction_hashing_data = build_transaction_hashing_data(transactions, tx_execution_infos)?;
    let (commitments, _measurements) = calculate_block_commitments(
        &transaction_hashing_data,
        thin_state_diff.clone(),
        convert_da_mode(l1_da_mode),
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

    fn empty_state_diff() -> StateDiff {
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
        StateDiff {
            storage_diffs: vec![ContractStorageDiffItem {
                address: Felt::from(11_u64),
                storage_entries: vec![
                    StorageEntry { key: Felt::from(101_u64), value: Felt::from(1001_u64) },
                    StorageEntry { key: Felt::from(102_u64), value: Felt::from(1002_u64) },
                ],
            }],
            deprecated_declared_classes: vec![Felt::from(21_u64)],
            declared_classes: vec![DeclaredClassItem {
                class_hash: Felt::from(31_u64),
                compiled_class_hash: Felt::from(41_u64),
            }],
            migrated_compiled_classes: Some(vec![MigratedCompiledClassItem {
                class_hash: Felt::from(32_u64),
                compiled_class_hash: Felt::from(42_u64),
            }]),
            deployed_contracts: vec![DeployedContractItem {
                address: Felt::from(12_u64),
                class_hash: Felt::from(22_u64),
            }],
            replaced_classes: vec![ReplacedClassItem {
                contract_address: Felt::from(13_u64),
                class_hash: Felt::from(23_u64),
            }],
            nonces: vec![NonceUpdate { contract_address: Felt::from(14_u64), nonce: Felt::from(24_u64) }],
        }
    }

    #[rstest]
    #[case::empty(empty_state_diff(), 0, 0, 0, 0, 0)]
    #[case::populated(populated_state_diff(), 2, 1, 2, 1, 1)]
    fn core_state_diff_conversion_works(
        #[case] state_diff: StateDiff,
        #[case] expected_deployed_or_replaced: usize,
        #[case] expected_storage_contracts: usize,
        #[case] expected_declared_or_migrated: usize,
        #[case] expected_deprecated_declared: usize,
        #[case] expected_nonce_updates: usize,
    ) {
        let thin_state_diff = core_state_diff_to_thin_state_diff(&state_diff).expect("state diff conversion");

        assert_eq!(thin_state_diff.deployed_contracts.len(), expected_deployed_or_replaced);
        assert_eq!(thin_state_diff.storage_diffs.len(), expected_storage_contracts);
        assert_eq!(thin_state_diff.class_hash_to_compiled_class_hash.len(), expected_declared_or_migrated);
        assert_eq!(thin_state_diff.deprecated_declared_classes.len(), expected_deprecated_declared);
        assert_eq!(thin_state_diff.nonces.len(), expected_nonce_updates);
    }

    fn account_invoke_tx_with_signature(signature_felts: Vec<Felt>) -> ExecutableTransaction {
        let tx = ExecutableInvokeTransaction {
            tx: ApiInvokeTransaction::V1(InvokeTransactionV1 {
                signature: TransactionSignature(Arc::new(signature_felts)),
                ..Default::default()
            }),
            tx_hash: TransactionHash::default(),
        };
        ExecutableTransaction::Account(AccountTransaction::Invoke(tx))
    }

    #[rstest]
    #[case::account(account_invoke_tx_with_signature(vec![Felt::from(7_u64)]), 1)]
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
        let blob = super::convert_da_mode(L1DataAvailabilityMode::Blob);
        let calldata = super::convert_da_mode(L1DataAvailabilityMode::Calldata);
        assert_ne!(blob, calldata);
    }
}
