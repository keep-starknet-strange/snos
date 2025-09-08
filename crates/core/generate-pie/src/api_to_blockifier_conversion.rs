use std::sync::Arc;

use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::errors::TransactionExecutionError;
use cairo_lang_starknet_classes::contract_class::version_id_from_serialized_sierra_program;
use rpc_client::RpcClient;
use starknet::core::types::{
    BlockId, DeclareTransaction, DeclareTransactionV0, DeclareTransactionV1, DeclareTransactionV2,
    DeclareTransactionV3, DeployAccountTransaction, DeployAccountTransactionV1,
    DeployAccountTransactionV3, Felt, InvokeTransaction, InvokeTransactionV1, InvokeTransactionV3,
    L1HandlerTransaction, ResourceBoundsMapping, Transaction, TransactionTrace,
    TransactionTraceWithHash,
};
use starknet::providers::{Provider, ProviderError};
use starknet_api::block::{GasPrice, GasPrices};
use starknet_api::contract_class::{ClassInfo, SierraVersion};
use starknet_api::core::{ChainId, PatriciaKey};
use starknet_api::execution_resources::GasAmount;
use starknet_api::transaction::fields::{AllResourceBounds, Fee};
use starknet_api::transaction::TransactionHash;
use starknet_api::StarknetApiError;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_os_types::starknet_core_addons::LegacyContractDecompressionError;
use thiserror::Error;
// use starknet_api::core::{ChainId, ClassHash, CompiledClassHash, ContractAddress, Nonce};

/// Struct to hold both starknet-api and blockifier transaction representations
#[derive(Debug)]
pub struct TransactionConversionResult {
    pub starknet_api_tx: starknet_api::executable_transaction::Transaction,
    pub blockifier_tx: blockifier::transaction::transaction_execution::Transaction,
}

#[derive(Error, Debug)]
pub enum FeltConversionError {
    #[error("Overflow Error: Felt exceeds u128 max value")]
    OverflowError,
    #[error("{0}")]
    CustomError(String),
}

pub fn felt_to_u128(felt: &Felt) -> Result<u128, FeltConversionError> {
    let digits = felt.to_be_digits();

    // Check if there are any significant bits in the higher 128 bits
    if digits[0] != 0 || digits[1] != 0 {
        return Err(FeltConversionError::OverflowError);
    }

    // Safe conversion since we've checked for overflow
    Ok(((digits[2] as u128) << 64) + digits[3] as u128)
}
#[derive(Error, Debug)]
pub enum ToBlockifierError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
    #[error("OS Contract Class Error: {0}")]
    StarknetContractClassError(#[from] starknet_os_types::error::ContractClassError),
    // #[error("Blockifier Contract Class Error: {0}")]
    // BlockifierContractClassError(#[from] blockifier::execution::errors::ContractClassError),
    #[error("Legacy Contract Decompression Error: {0}")]
    LegacyContractDecompressionError(#[from] LegacyContractDecompressionError),
    #[error("Starknet API Error: {0}")]
    StarknetApiError(#[from] StarknetApiError),
    #[error("Transaction Execution Error: {0}")]
    TransactionExecutionError(#[from] TransactionExecutionError),
    #[error("Felt Conversion Error: {0}")]
    FeltConversionError(#[from] FeltConversionError),
}

pub fn resource_bounds_core_to_api(
    resource_bounds: &ResourceBoundsMapping,
) -> starknet_api::transaction::fields::ValidResourceBounds {
    // starknet_api::transaction::ResourceBoundsMapping(BTreeMap::from([
    //     (
    //         starknet_api::transaction::fields::Resource::L1Gas,
    //         starknet_api::transaction::fields::ResourceBounds {
    //             max_amount: GasAmount(resource_bounds.l1_gas.max_amount),
    //             max_price_per_unit: GasPrice(resource_bounds.l1_gas.max_price_per_unit),
    //         },
    //     ),
    //     (
    //         starknet_api::transaction::fields::Resource::L2Gas,
    //         starknet_api::transaction::fields::ResourceBounds {
    //             max_amount: GasAmount(resource_bounds.l2_gas.max_amount),
    //             max_price_per_unit: GasPrice::from(resource_bounds.l2_gas.max_price_per_unit),
    //         },
    //     ),
    // ]))
    starknet_api::transaction::fields::ValidResourceBounds::AllResources(AllResourceBounds {
        l1_gas: starknet_api::transaction::fields::ResourceBounds {
            max_amount: GasAmount(resource_bounds.l1_gas.max_amount.into()),
            max_price_per_unit: GasPrice(resource_bounds.l1_gas.max_price_per_unit),
        },
        l1_data_gas: starknet_api::transaction::fields::ResourceBounds {
            max_amount: GasAmount(resource_bounds.l1_data_gas.max_amount),
            max_price_per_unit: GasPrice(resource_bounds.l1_data_gas.max_price_per_unit),
        },
        l2_gas: starknet_api::transaction::fields::ResourceBounds {
            max_amount: GasAmount(resource_bounds.l2_gas.max_amount),
            max_price_per_unit: GasPrice(resource_bounds.l2_gas.max_price_per_unit),
        },
    })
}

fn da_mode_core_to_api(
    da_mode: starknet::core::types::DataAvailabilityMode,
) -> starknet_api::data_availability::DataAvailabilityMode {
    match da_mode {
        starknet::core::types::DataAvailabilityMode::L1 => {
            starknet_api::data_availability::DataAvailabilityMode::L1
        }
        starknet::core::types::DataAvailabilityMode::L2 => {
            starknet_api::data_availability::DataAvailabilityMode::L2
        }
    }
}

fn invoke_v1_to_blockifier(
    tx: &InvokeTransactionV1,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V1(
        starknet_api::transaction::InvokeTransactionV1 {
            max_fee: Fee(felt_to_u128(&tx.max_fee)?),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                tx.signature.to_vec(),
            )),
            nonce: starknet_api::core::Nonce(tx.nonce),
            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(
                tx.sender_address,
            )?),
            calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.to_vec())),
        },
    );

    let api_txn_real =
        starknet_api::executable_transaction::InvokeTransaction::create(api_tx, &chain_id).unwrap();
    let again_once =
        starknet_api::executable_transaction::AccountTransaction::Invoke(api_txn_real.clone());

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::Invoke(api_txn_real),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
}

fn invoke_v3_to_blockifier(
    tx: &InvokeTransactionV3,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V3(
        starknet_api::transaction::InvokeTransactionV3 {
            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
            tip: starknet_api::transaction::fields::Tip(tx.tip),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                tx.signature.to_vec(),
            )),
            nonce: starknet_api::core::Nonce(tx.nonce),
            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(
                tx.sender_address,
            )?),
            calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.to_vec())),
            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
            paymaster_data: starknet_api::transaction::fields::PaymasterData(
                tx.paymaster_data.to_vec(),
            ),
            account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
                tx.account_deployment_data.to_vec(),
            ),
        },
    );

    let api_txn_real =
        starknet_api::executable_transaction::InvokeTransaction::create(api_tx, &chain_id).unwrap();
    let again_once =
        starknet_api::executable_transaction::AccountTransaction::Invoke(api_txn_real.clone());

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::Invoke(api_txn_real),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
    // Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::new_for_sequencing(starknet_api::executable_transaction::AccountTransaction::Invoke(starknet_api::executable_transaction::InvokeTransaction::create(api_tx, ChainId::Other("asdf")).unwrap()))))
}

/// Creates a ClassInfo instance from the given class hash by retrieving the contract class
/// from the Starknet RPC client and converting it to a Blockifier-compatible format.
/// Handle both Sierra and Legacy classes
async fn create_class_info(
    class_hash: Felt,
    client: &RpcClient,
    block_number: u64,
) -> Result<ClassInfo, ToBlockifierError> {
    // TODO: improve this to avoid retrieving this twice. Already done in lib.rs from prove_block
    let starknet_contract_class: starknet::core::types::ContractClass = client
        .starknet_rpc()
        .get_class(BlockId::Number(block_number), class_hash)
        .await?;

    let (blockifier_contract_class, program_length, abi_length, version) =
        match starknet_contract_class {
            starknet::core::types::ContractClass::Sierra(sierra) => {
                let generic_sierra = GenericSierraContractClass::from(sierra.clone());
                let flattened_sierra = generic_sierra.clone().to_starknet_core_contract_class()?;
                let generic_cairo_lang_class = generic_sierra.get_cairo_lang_contract_class()?;
                let (version_id, _) = version_id_from_serialized_sierra_program(
                    &generic_cairo_lang_class.sierra_program,
                )
                .unwrap();
                let sierra_version = SierraVersion::new(
                    version_id.major.try_into().unwrap(),
                    version_id.minor.try_into().unwrap(),
                    version_id.patch.try_into().unwrap(),
                );
                let contract_class = starknet_api::contract_class::ContractClass::V1(
                    generic_sierra
                        .compile()?
                        .to_blockifier_contract_class(sierra_version)?,
                );

                (
                    contract_class,
                    flattened_sierra.sierra_program.len(),
                    flattened_sierra.abi.len(),
                    SierraVersion::extract_from_program(&sierra.sierra_program).unwrap(),
                )
            }

            starknet::core::types::ContractClass::Legacy(legacy) => {
                let generic_legacy = GenericDeprecatedCompiledClass::try_from(legacy)?;
                let contract_class = starknet_api::contract_class::ContractClass::V0(
                    generic_legacy.to_blockifier_contract_class()?,
                );

                (contract_class, 0usize, 0usize, SierraVersion::default())
            }
        };

    Ok(ClassInfo::new(
        &blockifier_contract_class,
        program_length,
        abi_length,
        version,
    )?)
}

async fn declare_v0_to_blockifier(
    tx: &DeclareTransactionV0,
    client: &RpcClient,
    block_number: u64,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V0(
        starknet_api::transaction::DeclareTransactionV0V1 {
            max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                tx.signature.clone(),
            )),
            // Declare v0 does not have a nonce
            // So we default to 0
            nonce: starknet_api::core::Nonce(Default::default()),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(
                tx.sender_address,
            )?),
        },
    );
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    // let declare = blockifier::transaction::transactions::DeclareTransaction { tx: api_tx, tx_hash, class_info };

    // Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Declare(
    //     declare,
    // )))
    let api_txn_real = starknet_api::executable_transaction::DeclareTransaction::create(
        api_tx, class_info, &chain_id,
    )
    .unwrap();
    let again_once =
        starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real.clone());

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
}

async fn declare_v1_to_blockifier(
    tx: &DeclareTransactionV1,
    client: &RpcClient,
    block_number: u64,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V1(
        starknet_api::transaction::DeclareTransactionV0V1 {
            max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                tx.signature.clone(),
            )),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(
                tx.sender_address,
            )?),
        },
    );
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    // let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

    // Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Declare(
    //     declare,
    // )))
    let api_txn_real = starknet_api::executable_transaction::DeclareTransaction::create(
        api_tx, class_info, &chain_id,
    )
    .unwrap();
    let again_once =
        starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real.clone());

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
}

async fn declare_v2_to_blockifier(
    tx: &DeclareTransactionV2,
    client: &RpcClient,
    block_number: u64,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V2(
        starknet_api::transaction::DeclareTransactionV2 {
            max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                tx.signature.clone(),
            )),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(
                tx.sender_address,
            )?),
        },
    );
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    // let declare = blockifier::transaction::transactions::DeclareTransaction { tx: api_tx, tx_hash, class_info};

    // Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Declare(
    //     declare,
    // )))
    let api_txn_real = starknet_api::executable_transaction::DeclareTransaction::create(
        api_tx, class_info, &chain_id,
    )
    .unwrap();
    let again_once =
        starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real.clone());

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
}

async fn declare_v3_to_blockifier(
    tx: &DeclareTransactionV3,
    client: &RpcClient,
    block_number: u64,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V3(
        starknet_api::transaction::DeclareTransactionV3 {
            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
            tip: starknet_api::transaction::fields::Tip(tx.tip),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                tx.signature.clone(),
            )),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(
                tx.sender_address,
            )?),
            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
            paymaster_data: starknet_api::transaction::fields::PaymasterData(
                tx.paymaster_data.clone(),
            ),
            account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
                tx.account_deployment_data.clone(),
            ),
        },
    );
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    // let declare = blockifier::transaction::transactions::DeclareTransaction { tx: api_tx, tx_hash, class_info };

    // Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::new_for_sequencing(api_tx.get().into())))

    let api_txn_real = starknet_api::executable_transaction::DeclareTransaction::create(
        api_tx, class_info, &chain_id,
    )
    .unwrap();
    let again_once =
        starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real.clone());

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::Declare(api_txn_real),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
}

fn l1_handler_to_blockifier(
    tx: &L1HandlerTransaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::L1HandlerTransaction {
        version: starknet_api::transaction::TransactionVersion(tx.version),
        nonce: starknet_api::core::Nonce(Felt::from(tx.nonce)),
        contract_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(
            tx.contract_address,
        )?),
        entry_point_selector: starknet_api::core::EntryPointSelector(tx.entry_point_selector),
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.clone())),
    };

    // TODO: checkout for the l2 gas here
    let (l1_gas, l1_data_gas) = match &trace.trace_root {
        TransactionTrace::L1Handler(l1_handler) => (
            l1_handler.execution_resources.l1_gas,
            l1_handler.execution_resources.l1_data_gas,
        ),
        _ => unreachable!("Expected L1Handler type for TransactionTrace"),
    };

    let fee = match (l1_gas, l1_data_gas) {
        // There are the cases where both these values are zero and that means no matter what we multiply,
        // we will get a value of 0.
        // Having the fee as 0 for L1 handler will fail on the blockifier execution
        // Learn more:
        // https://github.com/starkware-libs/sequencer/blob/b5a877719dc2ce5b1ca833f14d9473c1f1c27059/crates/blockifier/src/transaction/transaction_execution.rs#L166
        // https://github.com/eqlabs/pathfinder/blob/eb81bf149fe516c3542a90a5c1715c5a3a141d0b/crates/rpc/src/executor.rs#L548
        // The comment(which is not very helpful) on the line above is:
        // // For now, assert only that any amount of fee was paid.
        // More investigations are recommended
        (0, 0) => 1_000_000_000_000u128,
        (0, l1_data_gas) => {
            gas_prices.eth_gas_prices.l1_data_gas_price.get().0 * l1_data_gas as u128
        }
        (l1_gas, 0) => gas_prices.strk_gas_prices.l1_gas_price.get().0 * l1_gas as u128,
        _ => unreachable!("At least l1_gas or l1_data_gas must be zero"),
    };

    let paid_fee_on_l1 = Fee(fee);
    let api_txn_real = starknet_api::executable_transaction::L1HandlerTransaction::create(
        api_tx,
        &chain_id,
        paid_fee_on_l1,
    )
    .unwrap();
    let starknet_api_tx =
        starknet_api::executable_transaction::Transaction::L1Handler(api_txn_real.clone());
    let another_one =
        starknet_api::executable_transaction::Transaction::L1Handler(api_txn_real.clone());

    Ok(TransactionConversionResult {
        starknet_api_tx,
        blockifier_tx:
            blockifier::transaction::transaction_execution::Transaction::new_for_sequencing(
                another_one,
            ),
    })
}

fn deploy_account_v1_to_blockifier(
    tx: &DeployAccountTransactionV1,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);

    let (max_fee, signature, nonce, class_hash, constructor_calldata, contract_address_salt) = (
        Fee(felt_to_u128(&tx.max_fee)?),
        starknet_api::transaction::fields::TransactionSignature(Arc::new(tx.signature.to_vec())),
        starknet_api::core::Nonce(tx.nonce),
        starknet_api::core::ClassHash(tx.class_hash),
        starknet_api::transaction::fields::Calldata(Arc::new(tx.constructor_calldata.to_vec())),
        starknet_api::transaction::fields::ContractAddressSalt(tx.contract_address_salt),
    );
    // let contract_address = calculate_contract_address(
    //     contract_address_salt,
    //     class_hash,
    //     &constructor_calldata,
    //     ContractAddress::default(),
    // )?;

    let api_tx = starknet_api::transaction::DeployAccountTransaction::V1(
        starknet_api::transaction::DeployAccountTransactionV1 {
            max_fee,
            signature,
            nonce,
            class_hash,
            constructor_calldata,
            contract_address_salt,
        },
    );

    let api_txn_real =
        starknet_api::executable_transaction::DeployAccountTransaction::create(api_tx, &chain_id)
            .unwrap();
    let again_once = starknet_api::executable_transaction::AccountTransaction::DeployAccount(
        api_txn_real.clone(),
    );

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::DeployAccount(api_txn_real),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
}

fn deploy_account_v3_to_blockifier(
    tx: &DeployAccountTransactionV3,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, StarknetApiError> {
    let _tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeployAccountTransaction::V3(
        starknet_api::transaction::DeployAccountTransactionV3 {
            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
            tip: starknet_api::transaction::fields::Tip(tx.tip),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                tx.signature.to_vec(),
            )),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            contract_address_salt: starknet_api::transaction::fields::ContractAddressSalt(
                tx.contract_address_salt,
            ),
            constructor_calldata: starknet_api::transaction::fields::Calldata(Arc::new(
                tx.constructor_calldata.clone(),
            )),
            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
            paymaster_data: starknet_api::transaction::fields::PaymasterData(
                tx.paymaster_data.clone(),
            ),
        },
    );
    let api_txn_real =
        starknet_api::executable_transaction::DeployAccountTransaction::create(api_tx, &chain_id)
            .unwrap();
    let again_once = starknet_api::executable_transaction::AccountTransaction::DeployAccount(
        api_txn_real.clone(),
    );

    Ok(TransactionConversionResult {
        starknet_api_tx: starknet_api::executable_transaction::Transaction::Account(
            starknet_api::executable_transaction::AccountTransaction::DeployAccount(
                api_txn_real.clone(),
            ),
        ),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(
            AccountTransaction::new_for_sequencing(again_once),
        ),
    })
}

/// Maps starknet-core transactions to Blockifier-compatible types.
pub async fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
    client: &RpcClient,
    block_number: u64,
    chain_id: ChainId,
) -> Result<TransactionConversionResult, ToBlockifierError> {
    let conversion_result = match sn_core_tx {
        Transaction::Invoke(tx) => match tx {
            InvokeTransaction::V0(_) => {
                unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0")
            }
            InvokeTransaction::V1(tx) => invoke_v1_to_blockifier(tx, chain_id)?,
            InvokeTransaction::V3(tx) => invoke_v3_to_blockifier(tx, chain_id)?,
        },
        Transaction::Declare(tx) => match tx {
            DeclareTransaction::V0(tx) => {
                declare_v0_to_blockifier(tx, client, block_number, chain_id).await?
            }
            DeclareTransaction::V1(tx) => {
                declare_v1_to_blockifier(tx, client, block_number, chain_id).await?
            }
            DeclareTransaction::V2(tx) => {
                declare_v2_to_blockifier(tx, client, block_number, chain_id).await?
            }
            DeclareTransaction::V3(tx) => {
                declare_v3_to_blockifier(tx, client, block_number, chain_id).await?
            }
        },
        Transaction::L1Handler(tx) => l1_handler_to_blockifier(tx, trace, gas_prices, chain_id)?,
        Transaction::DeployAccount(tx) => match tx {
            DeployAccountTransaction::V1(tx) => deploy_account_v1_to_blockifier(tx, chain_id)?,
            DeployAccountTransaction::V3(tx) => deploy_account_v3_to_blockifier(tx, chain_id)?,
        },

        Transaction::Deploy(_) => {
            unimplemented!("we do not plan to support deprecated deploy txs, only deploy_account")
        }
    };

    Ok(conversion_result)
}
