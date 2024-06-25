use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::account_transaction::AccountTransaction::{Declare, DeployAccount, Invoke};
use blockifier::transaction::objects::{TransactionInfo, TransactionInfoCreator};
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use snos::config::{BLOCK_HASH_CONTRACT_ADDRESS, SN_GOERLI, STORED_BLOCK_HASH_BUFFER};
use snos::crypto::pedersen::PedersenHash;
use snos::crypto::poseidon::poseidon_hash_many_bytes;
use snos::error::SnOsError;
use snos::error::SnOsError::Runner;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use snos::io::output::StarknetOsOutput;
use snos::io::InternalTransaction;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::storage::dict_storage::DictStorage;
use snos::utils::felt_api2vm;
use snos::{config, run_os};
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    DeclareTransactionV2, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3, Resource,
    ResourceBoundsMapping,
};
use starknet_crypto::{pedersen_hash, FieldElement};

use crate::common::block_utils::os_hints;

pub fn to_felt252(stark_felt: &StarkFelt) -> Felt252 {
    Felt252::from_bytes_be_slice(stark_felt.bytes())
}

const DECLARE_PREFIX: &[u8] = b"declare";
// const DEPLOY_ACCOUNT_PREFIX: &[u8] = b"deploy_account";
const INVOKE_PREFIX: &[u8] = b"invoke";
// const L1_HANDLER_PREFIX: &[u8] = b"l1_handler";

const MAX_AMOUNT_BITS: usize = 64;
const MAX_PRICE_PER_UNIT_BITS: usize = 128;

const DATA_AVAILABILITY_MODE_BITS: usize = 32;

/// Calculates the hash of the fee related fields of a transaction:
/// 1. The transaction's tip.
/// 2. A concatenation of the resource name, max amount and max price per unit - for each entry in
///    the resource bounds, in the following order: L1_gas, L2_gas.
fn hash_fee_related_fields(tip: Felt252, resource_bounds: &ResourceBoundsMapping) -> Felt252 {
    let mut data_to_hash = vec![tip];
    let resource_value_offset = MAX_AMOUNT_BITS + MAX_PRICE_PER_UNIT_BITS;

    for (resource, resource_value) in [
        (Resource::L1Gas, Felt252::from_bytes_be_slice(b"L1_GAS").to_biguint()),
        (Resource::L2Gas, Felt252::from_bytes_be_slice(b"L2_GAS").to_biguint()),
    ] {
        let bounds = resource_bounds.0.get(&resource).unwrap();
        let value = (resource_value << resource_value_offset)
            + (BigUint::from(bounds.max_amount) << MAX_PRICE_PER_UNIT_BITS)
            + BigUint::from(bounds.max_price_per_unit);
        data_to_hash.push(Felt252::from(value));
    }

    poseidon_hash_on_elements(&data_to_hash)
}

/// Calculates the transaction hash in the StarkNet network - a unique identifier of the
/// transaction.
/// The transaction hash is a hash of the following information:
///     1. A prefix that depends on the transaction type.
///     2. The transaction's version.
///     3. Sender address.
///     4. A hash of the fee-related fields (see `_hash_fee_related_fields()`'s docstring).
///     5. A hash of the paymaster data.
///     6. The network's chain ID.
///     7. The transaction's nonce.
///     8. A concatenation of the nonce and fee data availability modes.
///     9. Transaction-specific additional data.
fn calculate_transaction_v3_hash_common(
    tx_hash_prefix: &[u8],
    version: Felt252,
    sender_address: Felt252,
    chain_id: Felt252,
    nonce: Felt252,
    tx_type_specific_data: &[Felt252],
    tip: Felt252,
    paymaster_data: &[Felt252],
    nonce_data_availability_mode: Felt252,
    fee_data_availability_mode: Felt252,
    resource_bounds: &ResourceBoundsMapping,
) -> Felt252 {
    let fee_fields_hash = hash_fee_related_fields(tip, resource_bounds);
    let da_mode_concatenation = Felt252::from(
        (nonce_data_availability_mode.to_biguint() << DATA_AVAILABILITY_MODE_BITS)
            + fee_data_availability_mode.to_biguint(),
    );

    let data_to_hash = [
        &[
            Felt252::from_bytes_be_slice(tx_hash_prefix),
            version,
            sender_address,
            fee_fields_hash,
            poseidon_hash_on_elements(paymaster_data),
            chain_id,
            nonce,
            da_mode_concatenation,
        ],
        tx_type_specific_data,
    ]
    .concat();

    poseidon_hash_on_elements(&data_to_hash)
}

pub fn hash_on_elements(data: Vec<Felt252>) -> Felt252 {
    let mut current_hash = Felt252::ZERO;

    for item in data.iter() {
        current_hash = hash(&current_hash, item);
    }

    let data_len = Felt252::from(data.len());

    let result = hash(&current_hash, &data_len);

    result
}

fn poseidon_hash_on_elements(data: &[Felt252]) -> Felt252 {
    let data_as_bytes: Vec<_> = data.iter().map(|felt| felt.to_bytes_be().to_vec()).collect();
    let data_ref: Vec<&[u8]> = data_as_bytes.iter().map(|bytes| bytes.as_slice()).collect();
    Felt252::from_bytes_be_slice(&(*poseidon_hash_many_bytes(&data_ref).unwrap()))
}

pub fn hash(a: &Felt252, b: &Felt252) -> Felt252 {
    let a_be_bytes = a.to_bytes_be();
    let b_be_bytes = b.to_bytes_be();
    let (x, y) = (FieldElement::from_bytes_be(&a_be_bytes).unwrap(), FieldElement::from_bytes_be(&b_be_bytes).unwrap());

    let result = pedersen_hash(&x, &y);
    Felt252::from_bytes_be(&result.to_bytes_be())
}

/// Produce a hash for an Invoke V0 TXN with the provided elements
fn tx_hash_invoke_v0(
    contract_address: Felt252,
    entry_point_selector: Felt252,
    calldata: Vec<Felt252>,
    max_fee: Felt252,
) -> Felt252 {
    hash_on_elements(vec![
        Felt252::from_bytes_be_slice(INVOKE_PREFIX),
        Felt252::ZERO,
        contract_address,
        entry_point_selector,
        hash_on_elements(calldata),
        Felt252::from(max_fee),
        Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap()),
    ])
}

/// Produce a hash for an Invoke V1 TXN with the provided elements
fn tx_hash_invoke_v1(contract_address: Felt252, calldata: Vec<Felt252>, max_fee: Felt252, nonce: Felt252) -> Felt252 {
    hash_on_elements(vec![
        Felt252::from_bytes_be_slice(INVOKE_PREFIX),
        Felt252::ONE,
        contract_address,
        Felt252::ZERO,
        hash_on_elements(calldata),
        Felt252::from(max_fee),
        Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap()),
        nonce,
    ])
}

/// Produce a hash for an Invoke V3 TXN with the provided elements
fn tx_hash_invoke_v3(
    nonce: Felt252,
    sender_address: Felt252,
    nonce_data_availability_mode: Felt252,
    fee_data_availability_mode: Felt252,
    resource_bounds: &ResourceBoundsMapping,
    tip: Felt252,
    paymaster_data: &[Felt252],
    calldata: &[Felt252],
    account_deployment_data: &[Felt252],
) -> Felt252 {
    let tx_specific_fields = [poseidon_hash_on_elements(account_deployment_data), poseidon_hash_on_elements(calldata)];
    let chain_id = Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap());

    calculate_transaction_v3_hash_common(
        INVOKE_PREFIX,
        Felt252::THREE,
        sender_address,
        chain_id,
        nonce,
        &tx_specific_fields,
        tip,
        paymaster_data,
        nonce_data_availability_mode,
        fee_data_availability_mode,
        resource_bounds,
    )
}

/// Produce a hash for a Declare V2 TXN with the provided elements
fn tx_hash_declare_v2(
    sender_address: Felt252,
    max_fee: Felt252,
    class_hash: Felt252,
    compiled_class_hash: Felt252,
    nonce: Felt252,
) -> Felt252 {
    hash_on_elements(vec![
        Felt252::from_bytes_be_slice(DECLARE_PREFIX),
        Felt252::TWO, // declare version
        sender_address,
        Felt252::ZERO, // placeholder
        hash_on_elements(vec![class_hash]),
        Felt252::from(max_fee),
        Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap()),
        nonce,
        compiled_class_hash,
    ])
}

/// Convert an AccountTransaction to a SNOS InternalTransaction
pub fn to_internal_tx(account_tx: &AccountTransaction) -> InternalTransaction {
    return match account_tx {
        Declare(declare_tx) => {
            match &declare_tx.tx() {
                starknet_api::transaction::DeclareTransaction::V0(_) => {
                    // explicitly not supported
                    panic!("Declare V0 is not supported");
                }
                starknet_api::transaction::DeclareTransaction::V2(tx) => to_internal_declare_v2_tx(account_tx, tx),
                _ => unimplemented!("Declare txn version not yet supported"),
            }
        }
        DeployAccount(_) => unimplemented!("Deploy txns not yet supported"),
        Invoke(invoke_tx) => match &invoke_tx.tx {
            starknet_api::transaction::InvokeTransaction::V0(tx) => to_internal_invoke_v0_tx(tx),
            starknet_api::transaction::InvokeTransaction::V1(tx) => to_internal_invoke_v1_tx(tx),
            starknet_api::transaction::InvokeTransaction::V3(tx) => to_internal_invoke_v3_tx(tx),
        },
    };
}

/// Convert a DeclareTransactionV2 to a SNOS InternalTransaction
pub fn to_internal_declare_v2_tx(account_tx: &AccountTransaction, tx: &DeclareTransactionV2) -> InternalTransaction {
    let hash_value;
    let sender_address;
    let class_hash;
    let max_fee = tx.max_fee.0.into();
    let signature = tx.signature.0.iter().map(|x| to_felt252(x)).collect();
    let nonce = felt_api2vm(tx.nonce.0);

    match account_tx.create_tx_info() {
        TransactionInfo::Current(_) => panic!("Not implemented"),
        TransactionInfo::Deprecated(context) => {
            sender_address = felt_api2vm(*context.common_fields.sender_address.0.key());
            class_hash = felt_api2vm(tx.class_hash.0);

            hash_value =
                tx_hash_declare_v2(sender_address, max_fee, class_hash, felt_api2vm(tx.compiled_class_hash.0), nonce);
        }
    }

    InternalTransaction {
        hash_value,
        version: Some(Felt252::TWO),
        nonce: Some(nonce),
        sender_address: Some(sender_address),
        entry_point_type: Some("EXTERNAL".to_string()),
        signature: Some(signature),
        class_hash: Some(class_hash),
        compiled_class_hash: Some(felt_api2vm(tx.compiled_class_hash.0)),
        r#type: "DECLARE".to_string(),
        max_fee: Some(max_fee),
        ..Default::default()
    }
}

/// Convert a InvokeTransactionV0 to a SNOS InternalTransaction
pub fn to_internal_invoke_v0_tx(tx: &InvokeTransactionV0) -> InternalTransaction {
    let max_fee = tx.max_fee.0.into();
    let signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
    let entry_point_selector = Some(to_felt252(&tx.entry_point_selector.0));
    let calldata = Some(tx.calldata.0.iter().map(|x| to_felt252(x.into())).collect());
    let contract_address = to_felt252(tx.contract_address.0.key());
    let hash_value =
        tx_hash_invoke_v0(contract_address, entry_point_selector.unwrap(), calldata.clone().unwrap(), max_fee);

    return InternalTransaction {
        hash_value,
        version: Some(Felt252::ZERO),
        contract_address: Some(contract_address),
        nonce: None, // TODO: this can't be right...
        sender_address: Some(contract_address),
        entry_point_selector,
        entry_point_type: Some("EXTERNAL".to_string()),
        signature,
        calldata,
        r#type: "INVOKE_FUNCTION".to_string(),
        max_fee: Some(max_fee),
        ..Default::default()
    };
}

/// Convert a InvokeTransactionV1 to a SNOS InternalTransaction
pub fn to_internal_invoke_v1_tx(tx: &InvokeTransactionV1) -> InternalTransaction {
    let max_fee = tx.max_fee.0.into();
    let signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
    let entry_point_selector = Some(to_felt252(&selector_from_name("__execute__").0));
    let calldata = Some(tx.calldata.0.iter().map(|x| to_felt252(x.into())).collect());
    let contract_address = to_felt252(tx.sender_address.0.key());
    let nonce = felt_api2vm(tx.nonce.0);
    let hash_value = tx_hash_invoke_v1(contract_address, calldata.clone().unwrap(), max_fee, nonce);

    return InternalTransaction {
        hash_value,
        version: Some(Felt252::ONE),
        contract_address: Some(contract_address),
        nonce: Some(nonce),
        sender_address: Some(contract_address),
        entry_point_selector,
        entry_point_type: Some("EXTERNAL".to_string()),
        signature,
        calldata,
        r#type: "INVOKE_FUNCTION".to_string(),
        max_fee: Some(max_fee),
        ..Default::default()
    };
}

/// Convert a InvokeTransactionV3 to a SNOS InternalTransaction
pub fn to_internal_invoke_v3_tx(tx: &InvokeTransactionV3) -> InternalTransaction {
    let signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
    let entry_point_selector = to_felt252(&selector_from_name("__execute__").0);
    let calldata: Vec<_> = tx.calldata.0.iter().map(|x| to_felt252(x.into())).collect();
    let sender_address = to_felt252(tx.sender_address.0.key());
    let nonce = felt_api2vm(tx.nonce.0);
    let tip = felt_api2vm(tx.tip.0.into());

    let nonce_data_availability_mode = Felt252::from(tx.nonce_data_availability_mode as u64);
    let fee_data_availability_mode = Felt252::from(tx.fee_data_availability_mode as u64);
    let resource_bounds = &tx.resource_bounds;

    let paymaster_data: Vec<Felt252> = tx.paymaster_data.0.iter().map(|x| to_felt252(x.into())).collect();
    let account_deployment_data: Vec<Felt252> =
        tx.account_deployment_data.0.iter().map(|x| to_felt252(x.into())).collect();
    let hash_value = tx_hash_invoke_v3(
        nonce,
        sender_address,
        nonce_data_availability_mode,
        fee_data_availability_mode,
        resource_bounds,
        tip,
        &paymaster_data,
        &calldata,
        &account_deployment_data,
    );

    return InternalTransaction {
        hash_value,
        version: Some(Felt252::THREE),
        nonce: Some(nonce),
        sender_address: Some(sender_address),
        entry_point_selector: Some(entry_point_selector),
        entry_point_type: Some("EXTERNAL".to_string()),
        signature,
        calldata: Some(calldata),
        r#type: "INVOKE_FUNCTION".to_string(),
        resource_bounds: Some(tx.resource_bounds.clone()),
        paymaster_data: Some(paymaster_data),
        account_deployment_data: Some(account_deployment_data),
        tip: Some(tip),
        fee_data_availability_mode: Some(fee_data_availability_mode),
        nonce_data_availability_mode: Some(nonce_data_availability_mode),
        ..Default::default()
    };
}

async fn execute_txs(
    mut state: CachedState<SharedState<DictStorage, PedersenHash>>,
    block_context: &BlockContext,
    txs: Vec<AccountTransaction>,
    deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
    contract_classes: HashMap<ClassHash, CasmContractClass>,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let upper_bound_block_number = block_context.block_info().block_number.0 - STORED_BLOCK_HASH_BUFFER;
    let block_number = StorageKey::from(upper_bound_block_number);
    let block_hash = stark_felt!(66_u64);

    let block_hash_contract_address = ContractAddress::try_from(stark_felt!(BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();

    state.set_storage_at(block_hash_contract_address, block_number, block_hash).unwrap();
    let internal_txs: Vec<_> = txs.iter().map(to_internal_tx).collect();
    let execution_infos =
        txs.into_iter().map(|tx| tx.execute(&mut state, block_context, true, true).unwrap()).collect();
    os_hints(&block_context, state, internal_txs, execution_infos, deprecated_contract_classes, contract_classes).await
}

pub async fn execute_txs_and_run_os(
    state: CachedState<SharedState<DictStorage, PedersenHash>>,
    block_context: BlockContext,
    txs: Vec<AccountTransaction>,
    deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
    contract_classes: HashMap<ClassHash, CasmContractClass>,
) -> Result<(CairoPie, StarknetOsOutput), SnOsError> {
    let (os_input, execution_helper) =
        execute_txs(state, &block_context, txs, deprecated_contract_classes, contract_classes).await;

    let layout = config::default_layout();
    let result = run_os(config::DEFAULT_COMPILED_OS.to_string(), layout, os_input, block_context, execution_helper);

    match &result {
        Err(Runner(VmException(vme))) => {
            if let Some(traceback) = vme.traceback.as_ref() {
                log::error!("traceback:\n{}", traceback);
            }
            if let Some(inst_location) = &vme.inst_location {
                log::error!("died at: {}:{}", inst_location.input_file.filename, inst_location.start_line);
                log::error!("inst_location:\n{:?}", inst_location);
            }
        }
        Err(_) => {
            println!("exception:\n{:#?}", result);
        }
        _ => {}
    }

    result
}
