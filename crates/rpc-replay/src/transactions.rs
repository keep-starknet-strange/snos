use std::collections::BTreeMap;
use std::sync::Arc;

use blockifier::blockifier::block::GasPrices;
use blockifier::execution::contract_class::ClassInfo;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::errors::TransactionExecutionError;
use blockifier::transaction::objects::FeeType;
use rpc_client::RpcClient;
use starknet::core::types::{
    BlockId, DeclareTransaction, DeclareTransactionV1, DeclareTransactionV2, DeclareTransactionV3,
    DeployAccountTransaction, DeployAccountTransactionV1, DeployAccountTransactionV3, Felt, InvokeTransaction,
    InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction, ResourceBoundsMapping, Transaction,
    TransactionTrace, TransactionTraceWithHash,
};
use starknet::providers::{Provider, ProviderError};
use starknet_api::core::{calculate_contract_address, ContractAddress, PatriciaKey};
use starknet_api::execution_resources::GasAmount;
use starknet_api::transaction::fields::{Fee, ValidResourceBounds};
use starknet_api::transaction::TransactionHash;
use starknet_api::StarknetApiError;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_os_types::starknet_core_addons::LegacyContractDecompressionError;
use thiserror::Error;

use crate::utils::{felt_to_u128, FeltConversionError};

#[derive(Error, Debug)]
pub enum ToBlockifierError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
    #[error("OS Contract Class Error: {0}")]
    StarknetContractClassError(#[from] starknet_os_types::error::ContractClassError),
    #[error("Blockifier Contract Class Error: {0}")]
    BlockifierContractClassError(#[from] blockifier::execution::errors::ContractClassError),
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
) -> starknet_api::transaction::ResourceBoundsMapping {
    starknet_api::transaction::ResourceBoundsMapping(BTreeMap::from([
        (
            starknet_api::transaction::Resource::L1Gas,
            starknet_api::transaction::ResourceBounds {
                max_amount: resource_bounds.l1_gas.max_amount,
                max_price_per_unit: resource_bounds.l1_gas.max_price_per_unit,
            },
        ),
        (
            starknet_api::transaction::Resource::L2Gas,
            starknet_api::transaction::ResourceBounds {
                max_amount: resource_bounds.l2_gas.max_amount,
                max_price_per_unit: resource_bounds.l2_gas.max_price_per_unit,
            },
        ),
    ]))
}

fn da_mode_core_to_api(
    da_mode: starknet::core::types::DataAvailabilityMode,
) -> starknet_api::data_availability::DataAvailabilityMode {
    match da_mode {
        starknet::core::types::DataAvailabilityMode::L1 => starknet_api::data_availability::DataAvailabilityMode::L1,
        starknet::core::types::DataAvailabilityMode::L2 => starknet_api::data_availability::DataAvailabilityMode::L2,
    }
}

fn invoke_v1_to_blockifier(
    tx: &InvokeTransactionV1,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V1(starknet_api::transaction::InvokeTransactionV1 {
        max_fee: Fee(felt_to_u128(&tx.max_fee)?),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.to_vec())),
    });

    let invoke = blockifier::transaction::transactions::InvokeTransaction {
        tx: starknet_api::executable_transaction::InvokeTransaction { tx: api_tx, tx_hash },
        only_query: false,
    };
    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::Invoke(invoke)))
}

fn invoke_v3_to_blockifier(
    tx: &InvokeTransactionV3,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V3(starknet_api::transaction::InvokeTransactionV3 {
        resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
        tip: starknet_api::transaction::fields::Tip(tx.tip),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.to_vec())),
        nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
        fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
        paymaster_data: starknet_api::transaction::fields::PaymasterData(tx.paymaster_data.to_vec()),
        account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
            tx.account_deployment_data.to_vec(),
        ),
    });

    let invoke = blockifier::transaction::transactions::InvokeTransaction {
        tx: starknet_api::executable_transaction::InvokeTransaction { tx: api_tx, tx_hash },
        only_query: false,
    };
    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::Invoke(invoke)))
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
    let starknet_contract_class: starknet::core::types::ContractClass =
        client.starknet_rpc().get_class(BlockId::Number(block_number), class_hash).await?;

    let (blockifier_contract_class, program_length, abi_length) = match starknet_contract_class {
        starknet::core::types::ContractClass::Sierra(sierra) => {
            let generic_sierra = GenericSierraContractClass::from(sierra);
            let flattened_sierra = generic_sierra.clone().to_starknet_core_contract_class()?;
            let contract_class = starknet_api::contract_class::ContractClass::V1(
                generic_sierra.compile()?.to_blockifier_contract_class()?,
            );

            (contract_class, flattened_sierra.sierra_program.len(), flattened_sierra.abi.len())
        }

        starknet::core::types::ContractClass::Legacy(legacy) => {
            let generic_legacy = GenericDeprecatedCompiledClass::try_from(legacy)?;
            let contract_class =
                starknet_api::contract_class::ContractClass::V0(generic_legacy.to_blockifier_contract_class()?);

            (contract_class, 0, 0)
        }
    };

    Ok(ClassInfo::new(&blockifier_contract_class, program_length, abi_length)?)
}

async fn declare_v1_to_blockifier(
    tx: &DeclareTransactionV1,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V1(starknet_api::transaction::DeclareTransactionV0V1 {
        max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
    });
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::Declare(declare)))
}

async fn declare_v2_to_blockifier(
    tx: &DeclareTransactionV2,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V2(starknet_api::transaction::DeclareTransactionV2 {
        max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
    });
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::Declare(declare)))
}

async fn declare_v3_to_blockifier(
    tx: &DeclareTransactionV3,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V3(starknet_api::transaction::DeclareTransactionV3 {
        resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
        tip: starknet_api::transaction::fields::Tip(tx.tip),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
        fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
        paymaster_data: starknet_api::transaction::fields::PaymasterData(tx.paymaster_data.clone()),
        account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
            tx.account_deployment_data.clone(),
        ),
    });
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::Declare(declare)))
}

fn l1_handler_to_blockifier(
    tx: &L1HandlerTransaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::L1HandlerTransaction {
        version: starknet_api::transaction::TransactionVersion(tx.version),
        nonce: starknet_api::core::Nonce(Felt::from(tx.nonce)),
        contract_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.contract_address)?),
        entry_point_selector: starknet_api::core::EntryPointSelector(tx.entry_point_selector),
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.clone())),
    };

    let (l1_gas, l1_data_gas) = match &trace.trace_root {
        TransactionTrace::L1Handler(l1_handler) => (
            l1_handler.execution_resources.data_resources.data_availability.l1_gas,
            l1_handler.execution_resources.data_resources.data_availability.l1_data_gas,
        ),
        _ => unreachable!("Expected L1Handler type for TransactionTrace"),
    };

    let paid_fee_on_l1 = match (l1_gas, l1_data_gas) {
        // There are the cases where both these values are zero and that means no matter what we multiply,
        // we will get a value of 0.
        // Having the fee as 0 for L1 handler will fail on the blockifier execution
        // Learn more:
        // https://github.com/starkware-libs/sequencer/blob/b5a877719dc2ce5b1ca833f14d9473c1f1c27059/crates/blockifier/src/transaction/transaction_execution.rs#L166
        // https://github.com/eqlabs/pathfinder/blob/eb81bf149fe516c3542a90a5c1715c5a3a141d0b/crates/rpc/src/executor.rs#L548
        // The comment(which is not very helpful) on the line above is:
        // // For now, assert only that any amount of fee was paid.
        // More investigations are recommended
        (0, 0) => Fee(1_000_000_000_000u128),
        (0, l1_data_gas) => {
            gas_prices.get_l1_data_gas_price_by_fee_type(&FeeType::Eth).saturating_mul(GasAmount(l1_data_gas))
        }
        (l1_gas, 0) => gas_prices.get_l1_gas_price_by_fee_type(&FeeType::Eth).saturating_mul(GasAmount(l1_gas)),
        _ => unreachable!("At least l1_gas or l1_data_gas must be zero"),
    };

    let l1_handler = starknet_api::executable_transaction::L1HandlerTransaction { tx: api_tx, tx_hash, paid_fee_on_l1 };

    Ok(blockifier::transaction::transaction_execution::Transaction::L1Handler(l1_handler))
}

/// Calculates a contract address for deploy transaction
fn recalculate_contract_address(
    api_tx: &starknet_api::transaction::DeployAccountTransaction,
) -> Result<ContractAddress, StarknetApiError> {
    calculate_contract_address(
        api_tx.contract_address_salt(),
        api_tx.class_hash(),
        &api_tx.constructor_calldata(),
        // When the contract is deployed via a DEPLOY_ACCOUNT transaction: 0
        ContractAddress::from(0_u8),
    )
}

fn deploy_account_v1_to_blockifier(
    tx: &DeployAccountTransactionV1,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);

    let (max_fee, signature, nonce, class_hash, constructor_calldata, contract_address_salt) = (
        Fee(felt_to_u128(&tx.max_fee)?),
        starknet_api::transaction::fields::TransactionSignature(tx.signature.to_vec()),
        starknet_api::core::Nonce(tx.nonce),
        starknet_api::core::ClassHash(tx.class_hash),
        starknet_api::transaction::fields::Calldata(Arc::new(tx.constructor_calldata.to_vec())),
        starknet_api::transaction::fields::ContractAddressSalt(tx.contract_address_salt),
    );
    let contract_address = calculate_contract_address(
        contract_address_salt,
        class_hash,
        &constructor_calldata,
        ContractAddress::default(),
    )?;

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

    let deploy = blockifier::transaction::transactions::DeployAccountTransaction {
        tx: starknet_api::executable_transaction::DeployAccountTransaction { tx: api_tx, tx_hash, contract_address },
        only_query: false,
    };

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::DeployAccount(deploy)))
}

fn deploy_account_v3_to_blockifier(
    tx: &DeployAccountTransactionV3,
) -> Result<blockifier::transaction::transaction_execution::Transaction, StarknetApiError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeployAccountTransaction::V3(
        starknet_api::transaction::DeployAccountTransactionV3 {
            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
            tip: starknet_api::transaction::fields::Tip(tx.tip),
            signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            contract_address_salt: starknet_api::transaction::fields::ContractAddressSalt(tx.contract_address_salt),
            constructor_calldata: starknet_api::transaction::fields::Calldata(Arc::new(
                tx.constructor_calldata.clone(),
            )),
            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
            paymaster_data: starknet_api::transaction::fields::PaymasterData(tx.paymaster_data.clone()),
        },
    );
    let contract_address = recalculate_contract_address(&api_tx)?;
    let deploy_account = blockifier::transaction::transactions::DeployAccountTransaction {
        tx: starknet_api::executable_transaction::DeployAccountTransaction { tx: api_tx, tx_hash, contract_address },
        only_query: false,
    };

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction::DeployAccount(
        deploy_account,
    )))
}

/// Maps starknet-core transactions to Blockifier-compatible types.
pub async fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let blockifier_tx = match sn_core_tx {
        Transaction::Invoke(tx) => match tx {
            InvokeTransaction::V0(_) => unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0"),
            InvokeTransaction::V1(tx) => invoke_v1_to_blockifier(tx)?,
            InvokeTransaction::V3(tx) => invoke_v3_to_blockifier(tx)?,
        },
        Transaction::Declare(tx) => match tx {
            DeclareTransaction::V0(_) => unimplemented!("starknet_rs_to_blockifier with DeclareTransaction::V0"),
            DeclareTransaction::V1(tx) => declare_v1_to_blockifier(tx, client, block_number).await?,
            DeclareTransaction::V2(tx) => declare_v2_to_blockifier(tx, client, block_number).await?,
            DeclareTransaction::V3(tx) => declare_v3_to_blockifier(tx, client, block_number).await?,
        },
        Transaction::L1Handler(tx) => l1_handler_to_blockifier(tx, trace, gas_prices)?,
        Transaction::DeployAccount(tx) => match tx {
            DeployAccountTransaction::V1(tx) => deploy_account_v1_to_blockifier(tx)?,
            DeployAccountTransaction::V3(tx) => deploy_account_v3_to_blockifier(tx)?,
        },

        Transaction::Deploy(_) => {
            unimplemented!("we do not plan to support deprecated deploy txs, only deploy_account")
        }
    };

    Ok(blockifier_tx)
}
