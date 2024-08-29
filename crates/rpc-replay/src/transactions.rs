use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use blockifier::execution::contract_class::ClassInfo;
use blockifier::transaction::account_transaction::AccountTransaction;
use starknet::core::types::{
    BlockId, DeclareTransaction, DeployAccountTransaction, InvokeTransaction, ResourceBoundsMapping, Transaction,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_api::core::{calculate_contract_address, ContractAddress, PatriciaKey};
use starknet_api::hash::StarkFelt;
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

/// Maps starknet-core transactions to Blockifier-compatible types.
pub async fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let blockifier_tx = match sn_core_tx {
        Transaction::Invoke(tx) => {
            let (tx_hash, api_tx) = match tx {
                InvokeTransaction::V0(tx) => {
                    let _tx_hash = TransactionHash(tx.transaction_hash);
                    unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0");
                }
                InvokeTransaction::V1(tx) => {
                    let tx_hash = TransactionHash(tx.transaction_hash);
                    let api_tx = starknet_api::transaction::InvokeTransaction::V1(
                        starknet_api::transaction::InvokeTransactionV1 {
                            max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().collect(),
                            ),
                            nonce: starknet_api::core::Nonce(tx.nonce),
                            sender_address: starknet_api::core::ContractAddress(
                                PatriciaKey::try_from(tx.sender_address).unwrap(),
                            ),
                            calldata: starknet_api::transaction::Calldata(Arc::new(
                                tx.calldata.clone().into_iter().collect(),
                            )),
                        },
                    );
                    (tx_hash, api_tx)
                }
                InvokeTransaction::V3(tx) => {
                    let tx_hash = TransactionHash(tx.transaction_hash);
                    let api_tx = starknet_api::transaction::InvokeTransaction::V3(
                        starknet_api::transaction::InvokeTransactionV3 {
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
                        },
                    );
                    (tx_hash, api_tx)
                }
            };

            let invoke =
                blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };

            blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Invoke(
                invoke,
            ))
        }
        Transaction::DeployAccount(tx) => {
            let (tx_hash, api_tx, contract_address) = match tx {
                DeployAccountTransaction::V1(tx) => {
                    let tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    let api_tx = starknet_api::transaction::DeployAccountTransaction::V1(
                        starknet_api::transaction::DeployAccountTransactionV1 {
                            max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().map(felt_vm2api).collect(),
                            ),
                            nonce: starknet_api::core::Nonce(felt_vm2api(tx.nonce)),
                            class_hash: starknet_api::core::ClassHash(felt_vm2api(tx.class_hash)),
                            contract_address_salt: starknet_api::transaction::ContractAddressSalt(felt_vm2api(
                                tx.contract_address_salt,
                            )),
                            constructor_calldata: starknet_api::transaction::Calldata(Arc::new(
                                tx.constructor_calldata.iter().copied().map(felt_vm2api).collect(),
                            )),
                        },
                    );
                    let contract_address = calculate_contract_address(
                        api_tx.contract_address_salt(),
                        api_tx.class_hash(),
                        &api_tx.constructor_calldata(),
                        ContractAddress::from(0_u8),
                    )?;

                    (tx_hash, api_tx, contract_address)
                }
                DeployAccountTransaction::V3(tx) => {
                    let tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    let api_tx = starknet_api::transaction::DeployAccountTransaction::V3(
                        starknet_api::transaction::DeployAccountTransactionV3 {
                            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
                            tip: starknet_api::transaction::Tip(tx.tip),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().map(felt_vm2api).collect(),
                            ),
                            nonce: starknet_api::core::Nonce(felt_vm2api(tx.nonce)),
                            class_hash: starknet_api::core::ClassHash(felt_vm2api(tx.class_hash)),
                            contract_address_salt: starknet_api::transaction::ContractAddressSalt(felt_vm2api(
                                tx.contract_address_salt,
                            )),
                            constructor_calldata: starknet_api::transaction::Calldata(Arc::new(
                                tx.constructor_calldata.iter().copied().map(felt_vm2api).collect(),
                            )),
                            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
                            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
                            paymaster_data: starknet_api::transaction::PaymasterData(
                                tx.paymaster_data.iter().copied().map(felt_vm2api).collect(),
                            ),
                        },
                    );
                    let contract_address = calculate_contract_address(
                        api_tx.contract_address_salt(),
                        api_tx.class_hash(),
                        &api_tx.constructor_calldata(),
                        ContractAddress::from(0_u8),
                    )?;

                    (tx_hash, api_tx, contract_address)
                }
            };

            let deploy_account = blockifier::transaction::transactions::DeployAccountTransaction {
                tx: api_tx,
                tx_hash,
                contract_address,
                only_query: false,
            };

            blockifier::transaction::transaction_execution::Transaction::AccountTransaction(
                AccountTransaction::DeployAccount(deploy_account),
            )
        }
        Transaction::Declare(tx) => {
            let (tx_hash, api_tx, class_hash) = match tx {
                DeclareTransaction::V1(tx) => {
                    let tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    let api_tx = starknet_api::transaction::DeclareTransaction::V1(
                        starknet_api::transaction::DeclareTransactionV0V1 {
                            max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().map(felt_vm2api).collect(),
                            ),
                            nonce: starknet_api::core::Nonce(felt_vm2api(tx.nonce)),
                            class_hash: starknet_api::core::ClassHash(felt_vm2api(tx.class_hash)),
                            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(felt_vm2api(
                                tx.sender_address,
                            ))?),
                        },
                    );

                    (tx_hash, api_tx, tx.class_hash)
                }
                DeclareTransaction::V2(tx) => {
                    let tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    let api_tx = starknet_api::transaction::DeclareTransaction::V2(
                        starknet_api::transaction::DeclareTransactionV2 {
                            max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().map(felt_vm2api).collect(),
                            ),
                            nonce: starknet_api::core::Nonce(felt_vm2api(tx.nonce)),
                            class_hash: starknet_api::core::ClassHash(felt_vm2api(tx.class_hash)),
                            compiled_class_hash: starknet_api::core::CompiledClassHash(felt_vm2api(
                                tx.compiled_class_hash,
                            )),
                            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(felt_vm2api(
                                tx.sender_address,
                            ))?),
                        },
                    );

                    (tx_hash, api_tx, tx.class_hash)
                }
                DeclareTransaction::V3(tx) => {
                    let tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    let api_tx = starknet_api::transaction::DeclareTransaction::V3(
                        starknet_api::transaction::DeclareTransactionV3 {
                            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
                            tip: starknet_api::transaction::Tip(tx.tip),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().map(felt_vm2api).collect(),
                            ),
                            nonce: starknet_api::core::Nonce(felt_vm2api(tx.nonce)),
                            class_hash: starknet_api::core::ClassHash(felt_vm2api(tx.class_hash)),
                            compiled_class_hash: starknet_api::core::CompiledClassHash(felt_vm2api(
                                tx.compiled_class_hash,
                            )),
                            sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(felt_vm2api(
                                tx.sender_address,
                            ))?),
                            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
                            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
                            paymaster_data: starknet_api::transaction::PaymasterData(
                                tx.paymaster_data.iter().copied().map(felt_vm2api).collect(),
                            ),
                            account_deployment_data: starknet_api::transaction::AccountDeploymentData(
                                tx.account_deployment_data.iter().copied().map(felt_vm2api).collect(),
                            ),
                        },
                    );

                    (tx_hash, api_tx, tx.class_hash)
                }

                _ => unimplemented!("DeclareTransaction V0 not supported"),
            };

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
            let contract_class = generic_sierra_cc.compile()?.get_blockifier_contract_class()?.clone();

            let class_info = ClassInfo::new(
                &contract_class.into(),
                flattened_sierra.sierra_program.len(),
                flattened_sierra.abi.len(),
            )?;

            let declare = blockifier::transaction::transactions::DeclareTransaction::new(api_tx, tx_hash, class_info)?;

            blockifier::transaction::transaction_execution::Transaction::AccountTransaction(
                AccountTransaction::Declare(declare),
            )
        }
        Transaction::L1Handler(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with L1Handler txn");
        }
        _ => unimplemented!(),
    };

    Ok(blockifier_tx)
}
