// A dummy account contract to replicate a get_tx_info bug.
// This is added to specifically check `get_tx_info` call that had a buggy implementation
%lang starknet

from starkware.cairo.common.bool import FALSE
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    call_contract,
    deploy,
    emit_event,
    get_block_number,
    get_block_timestamp,
    get_caller_address,
    get_contract_address,
    get_tx_info,
    get_tx_signature,
    library_call,
    library_call_l1_handler,
    replace_class,
    storage_read,
    storage_write,
)
 
func check_all{syscall_ptr: felt*}() {
    let (tx_info) = get_tx_info();
    with_attr error_message("tx_info.signature_len failed") {
        assert tx_info.signature_len = 0;
    }

    let (block_number) = get_block_number();
    assert block_number = 2000;

    let (block_timestamp) = get_block_timestamp();
    assert block_timestamp = 1069200;

    let (contract_address) = get_contract_address();

    let (caller_address) = get_caller_address();
    assert caller_address = 0;

    let (prev_value) = storage_read(address=contract_address);
    storage_write(contract_address, value=prev_value + 1);


    let (signature_len: felt, signature: felt*) = get_tx_signature();
    assert signature_len = 0;

    storage_write(address=contract_address, value=1);

    let (res) = storage_read(address=contract_address);
    assert res = 1;

    return ();
}

@external
func __validate_declare__{syscall_ptr: felt*}(class_hash: felt) {
    check_all();
    return ();
}

// The hint implementation was using get_relocatable_from_var_name instead of get_ptr_from_var_name
@external
func __validate_deploy__{syscall_ptr: felt*}(class_hash: felt, contract_address_salt: felt) {
    check_all();
    return ();
}

@external
func __validate__{syscall_ptr: felt*}(contract_address, selector: felt, calldata_len: felt, calldata: felt*) {
    check_all();
    return ();
}

@external
@raw_output
func __execute__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    contract_address, selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    check_all();
    let (retdata_size: felt, retdata: felt*) = call_contract(
        contract_address=contract_address,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}
