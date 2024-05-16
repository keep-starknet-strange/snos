use std::collections::HashMap;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::account_transaction::AccountTransaction::{Declare, DeployAccount, Invoke};
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::Felt252;
use snos::config::{BLOCK_HASH_CONTRACT_ADDRESS, SN_GOERLI, STORED_BLOCK_HASH_BUFFER};
use snos::error::SnOsError;
use snos::error::SnOsError::Runner;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use snos::io::InternalTransaction;
use snos::{config, run_os};
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::state::StorageKey;
use starknet_crypto::{pedersen_hash, FieldElement};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use crate::common::block_utils::os_hints;

pub fn to_felt252(stark_felt: &StarkFelt) -> Felt252 {
    Felt252::from_bytes_be_slice(stark_felt.bytes())
}

// const DECLARE_PREFIX: &[u8] = b"declare";
// const DEPLOY_ACCOUNT_PREFIX: &[u8] = b"deploy_account";
const INVOKE_PREFIX: &[u8] = b"invoke";
// const L1_HANDLER_PREFIX: &[u8] = b"l1_handler";

pub fn hash_on_elements(data: Vec<Felt252>) -> Felt252 {
    let mut current_hash = Felt252::ZERO;

    for item in data.iter() {
        current_hash = hash(&current_hash, item);
    }

    let data_len = Felt252::from(data.len());

    let result = hash(&current_hash, &data_len);

    result
}

pub fn hash(a: &Felt252, b: &Felt252) -> Felt252 {
    let a_be_bytes = a.to_bytes_be();
    let b_be_bytes = b.to_bytes_be();
    let (x, y) = (FieldElement::from_bytes_be(&a_be_bytes).unwrap(), FieldElement::from_bytes_be(&b_be_bytes).unwrap());

    let result = pedersen_hash(&x, &y);
    Felt252::from_bytes_be(&result.to_bytes_be())
}

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

pub fn to_internal_tx(account_tx: &AccountTransaction) -> InternalTransaction {
    let hash_value: Felt252;
    let version: Option<Felt252>;
    let contract_address: Option<Felt252>;
    let contract_address_salt: Option<Felt252> = None;
    let contract_hash: Option<Felt252> = None;
    let constructor_calldata: Option<Vec<Felt252>> = None;
    let nonce: Option<Felt252> = None;
    let sender_address: Option<Felt252>;
    let entry_point_selector: Option<Felt252>;
    let entry_point_type: Option<String> = Some("EXTERNAL".to_string());
    let signature: Option<Vec<Felt252>>;
    let class_hash: Option<Felt252> = None;
    let compiled_class_hash: Option<Felt252> = None;
    let calldata: Option<Vec<Felt252>>;
    let paid_on_l1: Option<bool> = None;
    let r#type: String = "INVOKE_FUNCTION".to_string();
    let max_fee: Option<Felt252>;

    match account_tx {
        Declare(_) => panic!("Not implemented"),
        DeployAccount(_) => panic!("Not implemented"),
        Invoke(invoke_tx) => match &invoke_tx.tx {
            starknet_api::transaction::InvokeTransaction::V0(tx) => {
                version = Some(Felt252::ZERO);
                max_fee = Some(tx.max_fee.0.into());
                signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
                entry_point_selector = Some(to_felt252(&tx.entry_point_selector.0));
                calldata = Some(tx.calldata.0.iter().map(|x| to_felt252(x.into())).collect());
                contract_address = Some(to_felt252(tx.contract_address.0.key()));
                sender_address = contract_address;
                hash_value = tx_hash_invoke_v0(
                    contract_address.unwrap(),
                    entry_point_selector.unwrap(),
                    calldata.clone().unwrap(),
                    max_fee.unwrap(),
                );
            }
            starknet_api::transaction::InvokeTransaction::V1(_) => panic!("Not implemented"),
            starknet_api::transaction::InvokeTransaction::V3(_) => panic!("Not implemented"),
        },
    }

    return InternalTransaction {
        hash_value,
        version,
        contract_address,
        contract_address_salt,
        contract_hash,
        constructor_calldata,
        nonce,
        sender_address,
        entry_point_selector,
        entry_point_type,
        signature,
        class_hash,
        compiled_class_hash,
        calldata,
        paid_on_l1,
        r#type,
        max_fee,
    };
}

async fn execute_txs(
    mut state: CachedState<DictStateReader>,
    block_context: &BlockContext,
    txs: Vec<AccountTransaction>,
    deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let upper_bound_block_number = block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER;
    let block_number = StorageKey::from(upper_bound_block_number);
    let block_hash = stark_felt!(66_u64);

    let block_hash_contract_address = ContractAddress::try_from(stark_felt!(BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();

    state.set_storage_at(block_hash_contract_address, block_number, block_hash).unwrap();

    let internal_txs: Vec<_> = txs.iter().map(to_internal_tx).collect();
    let execution_infos =
        txs.into_iter().map(|tx| tx.execute(&mut state, block_context, true, true).unwrap()).collect();
    os_hints(&block_context, state, internal_txs, execution_infos, deprecated_contract_classes).await
}

pub async fn execute_txs_and_run_os(
    state: CachedState<DictStateReader>,
    block_context: BlockContext,
    txs: Vec<AccountTransaction>,
    deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
) -> Result<CairoPie, SnOsError> {
    let (os_input, execution_helper) = execute_txs(state, &block_context, txs, deprecated_contract_classes).await;

    let layout = config::default_layout();
    let result = run_os(config::DEFAULT_COMPILED_OS.to_string(), layout, os_input, block_context, execution_helper);

    match &result {
        Err(Runner(VmException(vme))) => {
            if let Some(traceback) = vme.traceback.as_ref() {
                println!("traceback:\n{}", traceback);
            }
            if let Some(inst_location) = &vme.inst_location {
                println!("died at: {}:{}", inst_location.input_file.filename, inst_location.start_line);
                println!("inst_location:\n{:?}", inst_location);
            }
        }
        _ => {}
    }
    println!("exception:\n{:#?}", result);

    result
}
