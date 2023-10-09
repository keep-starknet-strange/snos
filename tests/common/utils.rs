use cairo_felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::{errors::hint_errors::HintError, vm_core::VirtualMachine};

use starknet_api::core::ContractAddress;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use blockifier::execution::contract_class::{ContractClass, ContractClassV0};

use std::collections::HashMap;
use std::fs;
use std::path;

use super::*;

pub fn load_class_v0(path: &str) -> ContractClass {
    ContractClassV0::try_from_json_string(&load_class_raw(path))
        .unwrap()
        .into()
}

#[allow(unused)]
pub fn load_deprecated_class(path: &str) -> DeprecatedContractClass {
    serde_json::from_str(&load_class_raw(path)).unwrap()
}

pub fn load_class_raw(path: &str) -> String {
    fs::read_to_string(path::PathBuf::from(path)).unwrap()
}

#[allow(unused)]
pub fn check_output_vs_python(program: &str, mut vm: VirtualMachine) {
    let mut rs_output = String::new();
    vm.write_output(&mut rs_output).unwrap();
    let rs_output = rs_output.split('\n').filter(|&x| !x.is_empty());
    let python_output = std::process::Command::new("cairo-run")
        .arg("--layout=small")
        .arg(format!("--program={program:}"))
        .arg("--print_output")
        .output()
        .expect("failed to run python vm");
    let python_output = unsafe { std::str::from_utf8_unchecked(&python_output.stdout) }.to_string();
    let python_output = python_output
        .split('\n')
        .into_iter()
        .skip_while(|&x| x != "Program output:")
        .skip(1)
        .filter(|&x| !x.trim().is_empty())
        .into_iter();
    for (i, (rs, py)) in rs_output.zip(python_output).enumerate() {
        let py = py.to_string().trim().to_string();
        pretty_assertions::assert_eq!(*rs, py, "Output #{i:} is different");
    }
}

// Create the function that implements the custom hint
#[allow(unused)]
pub fn print_a_hint(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let a = get_integer_from_var_name("a", vm, ids_data, ap_tracking)?;
    println!("{}", a);
    Ok(())
}

pub fn deploy_with_syscall(
    shared_state: &mut SharedState<DictStateReader>,
    nonce_manager: &mut NonceManager,
    sender_addr: ContractAddress,
    class_hash: ClassHash,
    test_calldata: (u32, u32),
    salt: u32,
) -> ContractAddress {
    let contract_addr = calculate_contract_address(
        ContractAddressSalt(stark_felt!(salt)),
        class_hash,
        &calldata![
            stark_felt!(test_calldata.0), // Calldata: address.
            stark_felt!(test_calldata.1)  // Calldata: value.
        ],
        contract_address!(0_u32),
    )
    .unwrap();

    let account_tx = invoke_tx(invoke_tx_args! {
        max_fee: Fee(TESTING_FEE),
        nonce: nonce_manager.next(sender_addr),
        sender_address: sender_addr,
        calldata: calldata![
            *sender_addr.0.key(),
            selector_from_name("deploy_contract").0,
            stark_felt!(5_u32),
            class_hash.0,
            stark_felt!(salt),
            stark_felt!(2_u32),
            stark_felt!(test_calldata.0),
            stark_felt!(test_calldata.0)
        ],
        version: TransactionVersion::ONE,
    });
    AccountTransaction::Invoke(account_tx.into())
        .execute(
            &mut shared_state.cache,
            &mut shared_state.block_context,
            false,
            true,
        )
        .unwrap();

    contract_addr
}
