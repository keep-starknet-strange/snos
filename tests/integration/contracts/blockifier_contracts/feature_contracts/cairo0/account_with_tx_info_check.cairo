// A dummy account contract to replicate a get_tx_info bug.
// This is added to specifically check `get_tx_info` call that had a buggy implementation
%lang starknet

from starkware.cairo.common.bool import FALSE
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    call_contract,
    get_tx_info
)

@external
func __validate_declare__(class_hash: felt) {
    return ();
}

// The hint implementation was using get_relocatable_from_var_name instead of get_ptr_from_var_name
@external
func __validate_deploy__{syscall_ptr: felt*}(class_hash: felt, contract_address_salt: felt) {
    let (tx_info) = get_tx_info();
    with_attr error_message("assertion failed") {
        assert tx_info.signature_len = 0;
    }
    return ();
}

@external
func __validate__(contract_address, selector: felt, calldata_len: felt, calldata: felt*) {
    return ();
}

@external
@raw_output
func __execute__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    contract_address, selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (retdata_size: felt, retdata: felt*) = call_contract(
        contract_address=contract_address,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}
