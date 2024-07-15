use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::account_transaction::AccountTransaction::{Declare, DeployAccount, Invoke};
use blockifier::transaction::objects::{TransactionInfo, TransactionInfoCreator};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::{ExecutableTransaction, L1HandlerTransaction};
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use rstest::rstest;
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
use snos::starknet::core::os::transaction_hash::{L1_GAS, L2_GAS};
use snos::storage::dict_storage::DictStorage;
use snos::utils::felt_api2vm;
use snos::{config, run_os};
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    DeclareTransactionV0V1, DeclareTransactionV2, DeclareTransactionV3, DeployAccountTransactionV1,
    DeployAccountTransactionV3, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3, Resource,
    ResourceBoundsMapping,
};
use starknet_api::{contract_address, patricia_key, stark_felt};
use starknet_crypto::{pedersen_hash, FieldElement};

use crate::common::block_utils::os_hints;

pub fn to_felt252(stark_felt: &StarkFelt) -> Felt252 {
    Felt252::from_bytes_be_slice(stark_felt.bytes())
}

const DECLARE_PREFIX: &[u8] = b"declare";
const DEPLOY_ACCOUNT_PREFIX: &[u8] = b"deploy_account";
const INVOKE_PREFIX: &[u8] = b"invoke";
const L1_HANDLER_PREFIX: &[u8] = b"l1_handler";

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
        (Resource::L1Gas, Felt252::from_bytes_be_slice(L1_GAS.as_bytes()).to_biguint()),
        (Resource::L2Gas, Felt252::from_bytes_be_slice(L2_GAS.as_bytes()).to_biguint()),
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

/// Produce a hash for an Deploy V3 TXN with the provided elements
fn tx_hash_deploy_v3(
    nonce: Felt252,
    contract_address: Felt252,
    nonce_data_availability_mode: Felt252,
    fee_data_availability_mode: Felt252,
    resource_bounds: &ResourceBoundsMapping,
    tip: Felt252,
    paymaster_data: &[Felt252],
    contract_address_salt: Felt252,
    class_hash: Felt252,
    constructor_calldata: &[Felt252],
) -> Felt252 {
    let tx_specific_fields = [poseidon_hash_on_elements(constructor_calldata), class_hash, contract_address_salt];
    let chain_id = Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap());

    calculate_transaction_v3_hash_common(
        DEPLOY_ACCOUNT_PREFIX,
        Felt252::THREE,
        contract_address,
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

/// Produce a hash for a Declare V1 TXN with the provided elements
fn tx_hash_declare_v1(sender_address: Felt252, max_fee: Felt252, class_hash: Felt252, nonce: Felt252) -> Felt252 {
    hash_on_elements(vec![
        Felt252::from_bytes_be_slice(DECLARE_PREFIX),
        Felt252::ONE, // declare version
        sender_address,
        Felt252::ZERO,
        hash_on_elements(vec![class_hash]),
        Felt252::from(max_fee),
        Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap()),
        nonce,
    ])
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

/// Produce a hash for an Declare V3 TXN with the provided elements
fn tx_hash_declare_v3(
    nonce: Felt252,
    sender_address: Felt252,
    nonce_data_availability_mode: Felt252,
    fee_data_availability_mode: Felt252,
    resource_bounds: &ResourceBoundsMapping,
    tip: Felt252,
    paymaster_data: &[Felt252],
    account_deployment_data: &[Felt252],
    class_hash: Felt252,
    compiled_class_hash: Felt252,
) -> Felt252 {
    let tx_specific_fields = [poseidon_hash_on_elements(account_deployment_data), class_hash, compiled_class_hash];
    let chain_id = Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap());

    calculate_transaction_v3_hash_common(
        DECLARE_PREFIX,
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

/// Produce a hash for a Deploy V1 TXN with the provided elements.
///
/// Based on the spec here:
/// https://docs.starknet.io/architecture-and-concepts/network-architecture/transactions/#v1_deprecated_hash_calculation_3
fn tx_hash_deploy_account_v1(
    contract_address: Felt252,
    max_fee: Felt252,
    class_hash: Felt252,
    contract_address_salt: Felt252,
    constructor_calldata: Vec<Felt252>,
    chain_id: Felt252,
    nonce: Felt252,
) -> Felt252 {
    let entrypoint_selector = Felt252::ZERO;

    let class_hash_salt_calldata_hash =
        hash_on_elements([vec![class_hash, contract_address_salt], constructor_calldata].concat());

    hash_on_elements(vec![
        Felt252::from_bytes_be_slice(DEPLOY_ACCOUNT_PREFIX),
        Felt252::ONE, // deploy tx version
        contract_address,
        entrypoint_selector,
        class_hash_salt_calldata_hash,
        max_fee,
        chain_id,
        nonce,
    ])
}

pub fn l1_tx_compute_hash(
    contract_address: Felt252,
    entry_point_selector: Felt252,
    calldata: &[Felt252],
    fee: Felt252,
    chain_id: Felt252,
    nonce: Felt252,
) -> Felt252 {
    hash_on_elements(vec![
        Felt252::from_bytes_be_slice(L1_HANDLER_PREFIX),
        Felt252::ZERO, // tx version
        contract_address,
        entry_point_selector,
        hash_on_elements(calldata.to_vec()),
        fee,
        chain_id,
        nonce,
    ])
    .into()
}

/// Convert an Transaction to a SNOS InternalTransaction
pub fn to_internal_tx(tx: &Transaction) -> InternalTransaction {
    match tx {
        Transaction::AccountTransaction(account_tx) => account_tx_to_internal_tx(account_tx),
        Transaction::L1HandlerTransaction(l1_tx) => to_internal_l1_handler_tx(l1_tx),
    }
}
fn account_tx_to_internal_tx(account_tx: &AccountTransaction) -> InternalTransaction {
    match account_tx {
        Declare(declare_tx) => {
            match &declare_tx.tx() {
                starknet_api::transaction::DeclareTransaction::V0(_) => {
                    // explicitly not supported
                    panic!("Declare V0 is not supported");
                }
                starknet_api::transaction::DeclareTransaction::V1(tx) => to_internal_declare_v1_tx(account_tx, tx),
                starknet_api::transaction::DeclareTransaction::V2(tx) => to_internal_declare_v2_tx(account_tx, tx),
                starknet_api::transaction::DeclareTransaction::V3(tx) => to_internal_declare_v3_tx(tx),
            }
        }
        DeployAccount(deploy_tx) => match deploy_tx.tx() {
            starknet_api::transaction::DeployAccountTransaction::V1(tx) => to_internal_deploy_v1_tx(account_tx, tx),
            starknet_api::transaction::DeployAccountTransaction::V3(tx) => to_internal_deploy_v3_tx(account_tx, tx),
        },
        Invoke(invoke_tx) => match &invoke_tx.tx {
            starknet_api::transaction::InvokeTransaction::V0(tx) => to_internal_invoke_v0_tx(tx),
            starknet_api::transaction::InvokeTransaction::V1(tx) => to_internal_invoke_v1_tx(tx),
            starknet_api::transaction::InvokeTransaction::V3(tx) => to_internal_invoke_v3_tx(tx),
        },
    }
}
fn to_internal_l1_handler_tx(l1_tx: &L1HandlerTransaction) -> InternalTransaction {
    let contract_address = felt_api2vm(*l1_tx.tx.contract_address.0);
    let entry_point_selector = felt_api2vm(l1_tx.tx.entry_point_selector.0);
    let txinfo = l1_tx.create_tx_info();
    let signature = match txinfo {
        TransactionInfo::Deprecated(tx) => tx.common_fields.signature,
        TransactionInfo::Current(tx) => tx.common_fields.signature,
    };
    let signature = signature.0.iter().map(|x| to_felt252(x)).collect();
    let calldata: Vec<_> = l1_tx.tx.calldata.0.iter().map(|x| to_felt252(x)).collect();
    let chain_id = Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap());
    let nonce = felt_api2vm(l1_tx.tx.nonce.0);
    let fee = Felt252::ZERO;
    let hash_value = l1_tx_compute_hash(contract_address, entry_point_selector, &calldata, fee, chain_id, nonce);

    InternalTransaction {
        hash_value,
        version: Some(Felt252::ZERO),
        contract_address: Some(contract_address),
        calldata: Some(calldata),
        nonce: Some(nonce),
        entry_point_selector: Some(entry_point_selector),
        entry_point_type: Some("EXTERNAL".to_string()),
        r#type: "L1_HANDLER".into(),
        max_fee: Some(fee), //
        signature: Some(signature),
        ..Default::default()
    }
}

/// Convert a DeclareTransactionV1 to a SNOS InternalTransaction
pub fn to_internal_declare_v1_tx(account_tx: &AccountTransaction, tx: &DeclareTransactionV0V1) -> InternalTransaction {
    let hash_value;
    let sender_address;
    let class_hash;
    let max_fee = tx.max_fee.0.into();
    let signature = tx.signature.0.iter().map(|x| to_felt252(x)).collect();
    let nonce = felt_api2vm(tx.nonce.0);

    match account_tx.create_tx_info() {
        TransactionInfo::Current(_) => unreachable!("v1 transactions can only contain a `Deprecated` variant"),
        TransactionInfo::Deprecated(context) => {
            sender_address = felt_api2vm(*context.common_fields.sender_address.0.key());
            class_hash = felt_api2vm(tx.class_hash.0);

            hash_value = tx_hash_declare_v1(sender_address, max_fee, class_hash, nonce);
        }
    }

    InternalTransaction {
        hash_value,
        version: Some(Felt252::ONE),
        nonce: Some(nonce),
        sender_address: Some(sender_address),
        entry_point_type: Some("EXTERNAL".to_string()),
        signature: Some(signature),
        class_hash: Some(class_hash),
        r#type: "DECLARE".to_string(),
        max_fee: Some(max_fee),
        ..Default::default()
    }
}

fn to_internal_deploy_v1_tx(account_tx: &AccountTransaction, tx: &DeployAccountTransactionV1) -> InternalTransaction {
    let sender_address = match account_tx.create_tx_info() {
        TransactionInfo::Current(_) => unreachable!("TxV1 can only have deprecated variant"),
        TransactionInfo::Deprecated(context) => context.common_fields.sender_address,
    };
    let sender_address_felt = felt_api2vm(*sender_address.key());

    let contract_address = felt_api2vm(
        *calculate_contract_address(
            tx.contract_address_salt,
            tx.class_hash,
            &tx.constructor_calldata,
            contract_address!("0x0"),
        )
        .unwrap()
        .key(),
    );

    let max_fee: Felt252 = tx.max_fee.0.into();
    let signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
    let entry_point_selector = Some(Felt252::ZERO);
    let chain_id = Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap());
    let nonce = felt_api2vm(tx.nonce.0);

    let class_hash = felt_api2vm(tx.class_hash.0);

    let constructor_calldata: Vec<_> = tx.constructor_calldata.0.iter().map(|x| to_felt252(x.into())).collect();
    let contract_address_salt = felt_api2vm(tx.contract_address_salt.0);

    let hash_value = tx_hash_deploy_account_v1(
        contract_address,
        max_fee,
        class_hash,
        contract_address_salt,
        constructor_calldata.clone(),
        chain_id,
        nonce,
    );

    return InternalTransaction {
        hash_value,
        version: Some(Felt252::ONE),
        contract_address_salt: Some(contract_address_salt),
        nonce: Some(nonce),
        sender_address: Some(sender_address_felt),
        entry_point_selector,
        entry_point_type: Some("EXTERNAL".to_string()),
        signature,
        r#type: "DEPLOY_ACCOUNT".to_string(),
        max_fee: Some(max_fee),
        class_hash: Some(class_hash),
        constructor_calldata: Some(constructor_calldata),
        ..Default::default()
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

/// Convert a DeclareTransactionV2 to a SNOS InternalTransaction
pub fn to_internal_declare_v3_tx(tx: &DeclareTransactionV3) -> InternalTransaction {
    let signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
    let entry_point_selector = to_felt252(&selector_from_name("__execute__").0);
    let sender_address = to_felt252(tx.sender_address.0.key());
    let nonce = felt_api2vm(tx.nonce.0);
    let tip = felt_api2vm(tx.tip.0.into());

    let nonce_data_availability_mode = Felt252::from(tx.nonce_data_availability_mode as u64);
    let fee_data_availability_mode = Felt252::from(tx.fee_data_availability_mode as u64);
    let resource_bounds = &tx.resource_bounds;

    let paymaster_data: Vec<Felt252> = tx.paymaster_data.0.iter().map(|x| to_felt252(x.into())).collect();
    let account_deployment_data: Vec<Felt252> =
        tx.account_deployment_data.0.iter().map(|x| to_felt252(x.into())).collect();
    let class_hash = felt_api2vm(tx.class_hash.0);
    let compiled_class_hash = felt_api2vm(tx.compiled_class_hash.0);
    let hash_value = tx_hash_declare_v3(
        nonce,
        sender_address,
        nonce_data_availability_mode,
        fee_data_availability_mode,
        resource_bounds,
        tip,
        &paymaster_data,
        &account_deployment_data,
        class_hash,
        compiled_class_hash,
    );

    return InternalTransaction {
        hash_value,
        version: Some(Felt252::THREE),
        nonce: Some(nonce),
        sender_address: Some(sender_address),
        entry_point_selector: Some(entry_point_selector),
        entry_point_type: Some("EXTERNAL".to_string()),
        signature,
        r#type: "DECLARE".to_string(),
        resource_bounds: Some(tx.resource_bounds.clone()),
        paymaster_data: Some(paymaster_data),
        account_deployment_data: Some(account_deployment_data),
        tip: Some(tip),
        fee_data_availability_mode: Some(fee_data_availability_mode),
        nonce_data_availability_mode: Some(nonce_data_availability_mode),
        class_hash: Some(class_hash),
        compiled_class_hash: Some(compiled_class_hash),
        ..Default::default()
    };
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

/// Convert a InvokeTransactionV3 to a SNOS InternalTransaction
pub fn to_internal_deploy_v3_tx(
    account_tx: &AccountTransaction,
    tx: &DeployAccountTransactionV3,
) -> InternalTransaction {
    let sender_address = match account_tx {
        AccountTransaction::DeployAccount(a) => a.contract_address,
        _ => unreachable!(),
    };
    let signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
    let entry_point_selector = Some(Felt252::ZERO);
    let calldata: Vec<_> = tx.constructor_calldata.0.iter().map(|x| to_felt252(x.into())).collect();

    let nonce = felt_api2vm(tx.nonce.0);
    let tip = felt_api2vm(tx.tip.0.into());

    let nonce_data_availability_mode = Felt252::from(tx.nonce_data_availability_mode as u64);
    let fee_data_availability_mode = Felt252::from(tx.fee_data_availability_mode as u64);
    let resource_bounds = &tx.resource_bounds;

    let paymaster_data: Vec<Felt252> = tx.paymaster_data.0.iter().map(|x| to_felt252(x.into())).collect();
    let contract_address_salt = felt_api2vm(tx.contract_address_salt.0);
    let class_hash = to_felt252(&tx.class_hash.0);

    let contract_address = calculate_contract_address(
        tx.contract_address_salt,
        tx.class_hash,
        &tx.constructor_calldata,
        ContractAddress::from(0_u8),
    )
    .unwrap();
    let contract_address = felt_api2vm(*contract_address.0);

    let hash_value = tx_hash_deploy_v3(
        nonce,
        contract_address,
        nonce_data_availability_mode,
        fee_data_availability_mode,
        resource_bounds,
        tip,
        &paymaster_data,
        contract_address_salt,
        class_hash,
        &calldata,
    );

    return InternalTransaction {
        hash_value,
        version: Some(Felt252::THREE),
        nonce: Some(nonce),
        sender_address: Some(to_felt252(&sender_address.0)),
        contract_address: Some(contract_address),
        entry_point_selector,
        entry_point_type: Some("CONSTRUCTOR".to_string()),
        r#type: "DEPLOY_ACCOUNT".to_string(),
        resource_bounds: Some(tx.resource_bounds.clone()),
        paymaster_data: Some(paymaster_data),
        class_hash: Some(class_hash),
        constructor_calldata: Some(calldata),
        tip: Some(tip),
        fee_data_availability_mode: Some(fee_data_availability_mode),
        nonce_data_availability_mode: Some(nonce_data_availability_mode),
        contract_address_salt: Some(contract_address_salt),
        signature,
        account_deployment_data: Some(vec![]),
        ..Default::default()
    };
}

async fn execute_txs(
    mut state: CachedState<SharedState<DictStorage, PedersenHash>>,
    block_context: &BlockContext,
    txs: Vec<Transaction>,
    deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
    contract_classes: HashMap<ClassHash, CasmContractClass>,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let upper_bound_block_number = block_context.block_info().block_number.0 - STORED_BLOCK_HASH_BUFFER;
    let block_number = StorageKey::from(upper_bound_block_number);
    let block_hash = stark_felt!(66_u64);

    let block_hash_contract_address = ContractAddress::try_from(stark_felt!(BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();

    state.set_storage_at(block_hash_contract_address, block_number, block_hash).unwrap();
    let internal_txs: Vec<_> = txs.iter().map(to_internal_tx).collect();
    let execution_infos = txs
        .into_iter()
        .map(|tx| {
            let tx_result = tx.execute(&mut state, block_context, true, true);
            return match tx_result {
                Err(e) => {
                    log::error!("Transaction failed in blockifier: {}", e);
                    panic!("A transaction failed during execution");
                }
                Ok(info) => {
                    if info.is_reverted() {
                        log::error!("Transaction reverted: {:?}", info.revert_error);
                        log::warn!("TransactionExecutionInfo: {:?}", info);
                        panic!("A transaction reverted during execution");
                    }
                    info
                }
            };
        })
        .collect();
    os_hints(&block_context, state, internal_txs, execution_infos, deprecated_contract_classes, contract_classes).await
}

pub async fn execute_txs_and_run_os(
    state: CachedState<SharedState<DictStorage, PedersenHash>>,
    block_context: BlockContext,
    txs: Vec<Transaction>,
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

#[rstest]
#[case::no_calldata(vec![])]
#[case::with_calldata(vec![Felt252::from(539), Felt252::from(337)])]
fn test_deploy_account_tx_hash(#[case] constructor_calldata: Vec<Felt252>) {
    let entrypoint_selector = Felt252::ZERO;

    let version = Felt252::ONE;
    let salt = Felt252::ZERO;
    let contract_address = Felt252::from(19911991);
    let max_fee = Felt252::ONE;
    let chain_id = Felt252::TWO;
    let nonce = Felt252::ZERO;

    let class_hash = Felt252::from_hex_unchecked("0x067605bc345e925118dd60e09888a600e338047aa61e66361d48604ea670b709");
    let calldata = [vec![class_hash, salt], constructor_calldata.clone()].concat();

    let expected_hash = hash_on_elements(vec![
        Felt252::from_bytes_be_slice(DEPLOY_ACCOUNT_PREFIX),
        version,
        contract_address,
        entrypoint_selector,
        hash_on_elements(calldata),
        max_fee,
        chain_id,
        nonce,
    ]);

    let computed_hash =
        tx_hash_deploy_account_v1(contract_address, max_fee, class_hash, salt, constructor_calldata, chain_id, nonce);

    assert_eq!(computed_hash, expected_hash);
}
