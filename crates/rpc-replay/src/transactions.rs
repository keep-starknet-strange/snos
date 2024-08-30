use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use blockifier::execution::contract_class::ClassInfo;
use blockifier::transaction::account_transaction::AccountTransaction;
use starknet::core::types::{
    BlockId, DeclareTransaction, DeclareTransactionV1, DeclareTransactionV2, DeclareTransactionV3,
    DeployAccountTransaction, DeployAccountTransactionV1, DeployAccountTransactionV3, Felt, InvokeTransaction,
    InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction, ResourceBoundsMapping, Transaction,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_api::core::{calculate_contract_address, ContractAddress, PatriciaKey};
use starknet_api::transaction::{Fee, TransactionHash};
use starknet_api::StarknetApiError;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

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
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V1(starknet_api::transaction::InvokeTransactionV1 {
        max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
        signature: starknet_api::transaction::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.to_vec())),
    });

    let invoke = blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };
    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Invoke(
        invoke,
    )))
}

fn invoke_v3_to_blockifier(
    tx: &InvokeTransactionV3,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V3(starknet_api::transaction::InvokeTransactionV3 {
        resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
        tip: starknet_api::transaction::Tip(tx.tip),
        signature: starknet_api::transaction::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.to_vec())),
        nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
        fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
        paymaster_data: starknet_api::transaction::PaymasterData(tx.paymaster_data.to_vec()),
        account_deployment_data: starknet_api::transaction::AccountDeploymentData(tx.account_deployment_data.to_vec()),
    });

    let invoke = blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };
    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Invoke(
        invoke,
    )))
}

fn create_contract_address(
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
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeployAccountTransaction::V1(
        starknet_api::transaction::DeployAccountTransactionV1 {
            max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
            signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            contract_address_salt: starknet_api::transaction::ContractAddressSalt(tx.contract_address_salt),
            constructor_calldata: starknet_api::transaction::Calldata(Arc::new(tx.constructor_calldata.clone())),
        },
    );
    let contract_address = create_contract_address(&api_tx)?;
    let deploy_account = blockifier::transaction::transactions::DeployAccountTransaction {
        tx: api_tx,
        tx_hash,
        contract_address,
        only_query: false,
    };

    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(
        AccountTransaction::DeployAccount(deploy_account),
    ))
}

fn deploy_account_v3_to_blockifier(
    tx: &DeployAccountTransactionV3,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeployAccountTransaction::V3(
        starknet_api::transaction::DeployAccountTransactionV3 {
            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
            tip: starknet_api::transaction::Tip(tx.tip),
            signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            contract_address_salt: starknet_api::transaction::ContractAddressSalt(tx.contract_address_salt),
            constructor_calldata: starknet_api::transaction::Calldata(Arc::new(tx.constructor_calldata.clone())),
            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
            paymaster_data: starknet_api::transaction::PaymasterData(tx.paymaster_data.clone()),
        },
    );
    let contract_address = create_contract_address(&api_tx)?;
    let deploy_account = blockifier::transaction::transactions::DeployAccountTransaction {
        tx: api_tx,
        tx_hash,
        contract_address,
        only_query: false,
    };

    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(
        AccountTransaction::DeployAccount(deploy_account),
    ))
}

async fn create_class_info(
    class_hash: Felt,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<ClassInfo, Box<dyn Error>> {
    // TODO: improve this to avoid retrieving this twice. Already done in main.rs from prove_block
    let starknet_contract_class: starknet::core::types::ContractClass =
        provider.get_class(BlockId::Number(block_number), class_hash).await?;

    let (blockifier_contract_class, program_length, abi_length) = match starknet_contract_class {
        starknet::core::types::ContractClass::Sierra(sierra) => {
            let generic_sierra = GenericSierraContractClass::from(sierra);
            let flattened_sierra = generic_sierra.clone().to_starknet_core_contract_class()?;
            let contract_class = blockifier::execution::contract_class::ContractClass::V1(
                generic_sierra.compile()?.to_blockifier_contract_class()?,
            );

            (contract_class, flattened_sierra.sierra_program.len(), flattened_sierra.abi.len())
        }

        starknet::core::types::ContractClass::Legacy(legacy) => {
            let generic_legacy = GenericDeprecatedCompiledClass::try_from(legacy)?;
            let contract_class = blockifier::execution::contract_class::ContractClass::V0(
                generic_legacy.to_blockifier_contract_class()?,
            );

            (contract_class, 0, 0)
        }
    };

    Ok(ClassInfo::new(&blockifier_contract_class, program_length, abi_length)?)
}

async fn declare_v1_to_blockifier(
    tx: &DeclareTransactionV1,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V1(starknet_api::transaction::DeclareTransactionV0V1 {
        max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
        signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
    });
    let class_info = create_class_info(tx.class_hash, provider, block_number).await?;
    let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Declare(
        declare,
    )))
}

async fn declare_v2_to_blockifier(
    tx: &DeclareTransactionV2,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V2(starknet_api::transaction::DeclareTransactionV2 {
        max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
        signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
    });
    let class_info = create_class_info(tx.class_hash, provider, block_number).await?;
    let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Declare(
        declare,
    )))
}

async fn declare_v3_to_blockifier(
    tx: &DeclareTransactionV3,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V3(starknet_api::transaction::DeclareTransactionV3 {
        resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
        tip: starknet_api::transaction::Tip(tx.tip),
        signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
        fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
        paymaster_data: starknet_api::transaction::PaymasterData(tx.paymaster_data.clone()),
        account_deployment_data: starknet_api::transaction::AccountDeploymentData(tx.account_deployment_data.clone()),
    });
    let class_info = create_class_info(tx.class_hash, provider, block_number).await?;
    let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Declare(
        declare,
    )))
}

fn l1_handler_to_blockifier(
    tx: &L1HandlerTransaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::L1HandlerTransaction {
        version: starknet_api::transaction::TransactionVersion(tx.version),
        nonce: starknet_api::core::Nonce(Felt::from(tx.nonce)),
        contract_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.contract_address)?),
        entry_point_selector: starknet_api::core::EntryPointSelector(tx.entry_point_selector),
        calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.clone())),
    };
    // Fees are 0 for L1Handler transactions
    let fee = Fee(0);
    let l1_handler =
        blockifier::transaction::transactions::L1HandlerTransaction { tx: api_tx, tx_hash, paid_fee_on_l1: fee };

    Ok(blockifier::transaction::transaction_execution::Transaction::L1HandlerTransaction(l1_handler))
}

/// Maps starknet-core transactions to Blockifier-compatible types.
pub async fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let blockifier_tx = match sn_core_tx {
        // Transaction::Invoke(tx) => invoke_txn_to_blockifier(tx)?,
        Transaction::Invoke(tx) => match tx {
            InvokeTransaction::V0(_) => unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0"),
            InvokeTransaction::V1(tx) => invoke_v1_to_blockifier(tx)?,
            InvokeTransaction::V3(tx) => invoke_v3_to_blockifier(tx)?,
        },
        Transaction::DeployAccount(tx) => match tx {
            DeployAccountTransaction::V1(tx) => deploy_account_v1_to_blockifier(tx)?,
            DeployAccountTransaction::V3(tx) => deploy_account_v3_to_blockifier(tx)?,
        },
        // Transaction::Declare(tx) => declare_to_blockifier(tx, provider, block_number).await?,
        Transaction::Declare(tx) => match tx {
            DeclareTransaction::V0(_) => unimplemented!("starknet_rs_to_blockifier with DeclareTransaction::V0"),
            DeclareTransaction::V1(tx) => declare_v1_to_blockifier(tx, provider, block_number).await?,
            DeclareTransaction::V2(tx) => declare_v2_to_blockifier(tx, provider, block_number).await?,
            DeclareTransaction::V3(tx) => declare_v3_to_blockifier(tx, provider, block_number).await?,
        },
        Transaction::L1Handler(tx) => l1_handler_to_blockifier(tx)?,
        _ => unimplemented!(),
    };

    Ok(blockifier_tx)
}
