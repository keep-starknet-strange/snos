use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use blockifier::execution::contract_class::{self, ClassInfo};
use blockifier::transaction::account_transaction::AccountTransaction;
use starknet::core::types::{
    BlockId, DeclareTransaction, DeployAccountTransaction, Felt, InvokeTransaction, L1HandlerTransaction,
    ResourceBoundsMapping, Transaction,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_api::core::{calculate_contract_address, ContractAddress, PatriciaKey};
use starknet_api::transaction::{Fee, TransactionHash};
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

fn invoke_txn_to_blockifier(
    tx: &InvokeTransaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(*tx.transaction_hash());

    let api_tx = match tx {
        InvokeTransaction::V0(_tx) => {
            unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0");
        }
        InvokeTransaction::V1(tx) => {
            let api_tx =
                starknet_api::transaction::InvokeTransaction::V1(starknet_api::transaction::InvokeTransactionV1 {
                    max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                    signature: starknet_api::transaction::TransactionSignature(tx.signature.to_vec()),
                    nonce: starknet_api::core::Nonce(tx.nonce),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address).unwrap(),
                    ),
                    calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.to_vec())),
                });
            api_tx
        }
        InvokeTransaction::V3(tx) => {
            let api_tx =
                starknet_api::transaction::InvokeTransaction::V3(starknet_api::transaction::InvokeTransactionV3 {
                    resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
                    tip: starknet_api::transaction::Tip(tx.tip),
                    signature: starknet_api::transaction::TransactionSignature(tx.signature.to_vec()),
                    nonce: starknet_api::core::Nonce(tx.nonce),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address).unwrap(),
                    ),
                    calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.to_vec())),
                    nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
                    fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
                    paymaster_data: starknet_api::transaction::PaymasterData(tx.paymaster_data.to_vec()),
                    account_deployment_data: starknet_api::transaction::AccountDeploymentData(
                        tx.account_deployment_data.to_vec(),
                    ),
                });
            api_tx
        }
    };

    let invoke = blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };
    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Invoke(
        invoke,
    )))
}

fn deploy_account_to_blockifier(
    tx: &DeployAccountTransaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(*tx.transaction_hash());

    let api_tx = match tx {
        DeployAccountTransaction::V1(tx) => {
            let api_tx = starknet_api::transaction::DeployAccountTransaction::V1(
                starknet_api::transaction::DeployAccountTransactionV1 {
                    max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                    signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
                    nonce: starknet_api::core::Nonce(tx.nonce),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash),
                    contract_address_salt: starknet_api::transaction::ContractAddressSalt(tx.contract_address_salt),
                    constructor_calldata: starknet_api::transaction::Calldata(Arc::new(
                        tx.constructor_calldata.clone(),
                    )),
                },
            );
            api_tx
        }
        DeployAccountTransaction::V3(tx) => {
            let api_tx = starknet_api::transaction::DeployAccountTransaction::V3(
                starknet_api::transaction::DeployAccountTransactionV3 {
                    resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
                    tip: starknet_api::transaction::Tip(tx.tip),
                    signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
                    nonce: starknet_api::core::Nonce(tx.nonce),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash),
                    contract_address_salt: starknet_api::transaction::ContractAddressSalt(tx.contract_address_salt),
                    constructor_calldata: starknet_api::transaction::Calldata(Arc::new(
                        tx.constructor_calldata.clone(),
                    )),
                    nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
                    fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
                    paymaster_data: starknet_api::transaction::PaymasterData(tx.paymaster_data.clone()),
                },
            );
            api_tx
        }
    };

    let contract_address = calculate_contract_address(
        api_tx.contract_address_salt(),
        api_tx.class_hash(),
        &api_tx.constructor_calldata(),
        // When the contract is deployed via a DEPLOY_ACCOUNT transaction: 0
        ContractAddress::from(0_u8),
    )?;

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
    let starknet_contract_class = provider.get_class(BlockId::Number(block_number), class_hash).await?;
    let generic_sierra_cc = match starknet_contract_class {
        starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
            GenericSierraContractClass::from(flattened_sierra_cc)
        }
        starknet::core::types::ContractClass::Legacy(_) => {
            unimplemented!("Fixme: Support legacy contract class")
        }
    };

    let flattened_sierra = generic_sierra_cc.clone().to_starknet_core_contract_class()?;
    let contract_class = generic_sierra_cc.compile()?.to_blockifier_contract_class()?;

    Ok(ClassInfo::new(&contract_class.into(), flattened_sierra.sierra_program.len(), flattened_sierra.abi.len())?)
}

async fn declare_to_blockifier(
    tx: &DeclareTransaction,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let tx_hash = TransactionHash(*tx.transaction_hash());

    let (api_tx, class_hash) = match tx {
        DeclareTransaction::V1(tx) => {
            let api_tx =
                starknet_api::transaction::DeclareTransaction::V1(starknet_api::transaction::DeclareTransactionV0V1 {
                    max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                    signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
                    nonce: starknet_api::core::Nonce(tx.nonce),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash),
                    sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
                });

            (api_tx, tx.class_hash)
        }
        DeclareTransaction::V2(tx) => {
            let api_tx =
                starknet_api::transaction::DeclareTransaction::V2(starknet_api::transaction::DeclareTransactionV2 {
                    max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                    signature: starknet_api::transaction::TransactionSignature(tx.signature.clone()),
                    nonce: starknet_api::core::Nonce(tx.nonce),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash),
                    compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
                    sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
                });

            (api_tx, tx.class_hash)
        }
        DeclareTransaction::V3(tx) => {
            let api_tx =
                starknet_api::transaction::DeclareTransaction::V3(starknet_api::transaction::DeclareTransactionV3 {
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
                    account_deployment_data: starknet_api::transaction::AccountDeploymentData(
                        tx.account_deployment_data.clone(),
                    ),
                });

            (api_tx, tx.class_hash)
        }
        _ => unimplemented!("DeclareTransaction V0 not supported"),
    };

    let class_info = create_class_info(class_hash, provider, block_number).await?;
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
        contract_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.contract_address).unwrap()),
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
        Transaction::Invoke(tx) => invoke_txn_to_blockifier(tx)?,
        Transaction::DeployAccount(tx) => deploy_account_to_blockifier(tx)?,
        Transaction::Declare(tx) => declare_to_blockifier(tx, provider, block_number).await?,
        Transaction::L1Handler(tx) => l1_handler_to_blockifier(tx)?,
        _ => unimplemented!(),
    };

    Ok(blockifier_tx)
}
