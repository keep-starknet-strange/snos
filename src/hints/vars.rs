pub mod scopes {
    pub const BYTECODE_SEGMENT_STRUCTURE: &str = "bytecode_segment_structure";
    pub const BYTECODE_SEGMENTS: &str = "bytecode_segments";
    pub const CASE: &str = "case";
    pub const COMMITMENT_INFO: &str = "commitment_info";
    pub const COMMITMENT_INFO_BY_ADDRESS: &str = "commitment_info_by_address";
    pub const COMPILED_CLASS_HASH: &str = "compiled_class_hash";
    pub const DESCEND: &str = "descend";

    pub const DESCENT_MAP: &str = "descent_map";
    #[allow(unused)]
    pub const DICT_MANAGER: &str = "dict_manager";
    pub const EXECUTION_HELPER: &str = "execution_helper";
    pub const NODE: &str = "node";
    pub const LEFT_CHILD: &str = "left_child";
    pub const OS_INPUT: &str = "os_input";
    pub const PATRICIA_SKIP_VALIDATION_RUNNER: &str = "__patricia_skip_validation_runner";
    pub const PREIMAGE: &str = "preimage";
    pub const RIGHT_CHILD: &str = "right_child";
    pub const SYSCALL_HANDLER: &str = "syscall_handler";
    pub const TX: &str = "tx";
    pub const VALUE: &str = "value";
}

pub mod ids {
    pub const ADDITIONAL_DATA: &str = "additional_data";
    pub const BIT: &str = "bit";
    pub const CALL_RESPONSE: &str = "call_response";
    pub const CALLDATA: &str = "calldata";
    pub const CHILD_BIT: &str = "CHILD_BIT";
    pub const CLASS_HASH_PTR: &str = "class_hash_ptr";
    pub const COMPILED_CLASS: &str = "compiled_class";
    pub const COMPILED_CLASS_FACT: &str = "compiled_class_fact";
    pub const COMPILED_CLASS_HASH: &str = "compiled_class_hash";
    pub const CONTRACT_ADDRESS: &str = "contract_address";
    pub const CONTRACT_STATE_CHANGES: &str = "contract_state_changes";
    pub const CURRENT_BLOCK_NUMBER: &str = "current_block_number";
    pub const CURRENT_HASH: &str = "current_hash";
    pub const DA_START: &str = "da_start";
    pub const DATA_TO_HASH: &str = "data_to_hash";
    pub const DEPRECATED_TX_INFO: &str = "deprecated_tx_info";
    pub const DESCEND: &str = "descend";
    pub const DEST_PTR: &str = "dest_ptr";
    pub const EDGE: &str = "edge";
    pub const ENTRY_POINT_RETURN_VALUES: &str = "entry_point_return_values";
    pub const EXECUTION_CONTEXT: &str = "execution_context";
    pub const FINAL_CONTRACT_STATE_ROOT: &str = "final_contract_state_root";
    pub const FINAL_ROOT: &str = "final_root";
    pub const HASH_PTR: &str = "hash_ptr";
    pub const INITIAL_GAS: &str = "initial_gas";
    pub const HEIGHT: &str = "height";
    pub const INITIAL_CONTRACT_STATE_ROOT: &str = "initial_contract_state_root";
    pub const INITIAL_ROOT: &str = "initial_root";
    pub const IS_ON_CURVE: &str = "is_on_curve";
    pub const USE_KZG_DA: &str = "use_kzg_da";
    pub const LENGTH: &str = "length";
    pub const LOW: &str = "low";
    pub const MAX_FEE: &str = "max_fee";
    pub const N: &str = "n";
    pub const N_UPDATES: &str = "n_updates";
    pub const NEW_LENGTH: &str = "new_length";
    pub const NEW_ROOT: &str = "new_root";
    pub const NEW_STATE_ENTRY: &str = "new_state_entry";
    pub const NODE: &str = "node";
    pub const OLD_BLOCK_HASH: &str = "old_block_hash";
    pub const OLD_BLOCK_NUMBER: &str = "old_block_number";
    pub const OS_CONTEXT: &str = "os_context";
    pub const REQUIRED_GAS: &str = "required_gas";
    pub const OUTPUT_PTR: &str = "output_ptr";
    pub const REQUEST_BLOCK_NUMBER: &str = "request_block_number";
    pub const PATH: &str = "path";
    pub const PREV_ROOT: &str = "prev_root";
    pub const PREV_VALUE: &str = "prev_value";
    pub const REQUEST: &str = "request";
    pub const RES: &str = "res";
    pub const RESPONSE: &str = "response";
    pub const RETDATA: &str = "retdata";
    pub const RETDATA_SIZE: &str = "retdata_size";
    pub const SECP_P: &str = "SECP_P";
    pub const SELECTOR: &str = "selector";
    pub const SENDER_ADDRESS: &str = "sender_address";
    pub const SIBLINGS: &str = "siblings";
    pub const SIGNATURE_LEN: &str = "signature_len";
    pub const SIGNATURE_START: &str = "signature_start";
    pub const SRC_PTR: &str = "src_ptr";
    pub const STATE_ENTRY: &str = "state_entry";
    pub const STATE_UPDATES_START: &str = "state_updates_start";
    pub const SYSCALL_PTR: &str = "syscall_ptr";
    pub const TX_INFO: &str = "tx_info";
    pub const TX_VERSION: &str = "tx_version";
    pub const UPDATE_PTR: &str = "update_ptr";
    pub const VALIDATE_DECLARE_EXECUTION_CONTEXT: &str = "validate_declare_execution_context";
    pub const VALUE: &str = "value";
    pub const WORD: &str = "word";
    pub const Y: &str = "y";
    pub const Y_SQUARE_INT: &str = "y_square_int";
}

pub mod constants {
    pub const BASE: &str = "starkware.starknet.core.os.data_availability.bls_field.BASE";
    pub const BLOCK_HASH_CONTRACT_ADDRESS: &str = "starkware.starknet.core.os.constants.BLOCK_HASH_CONTRACT_ADDRESS";
    pub const MERKLE_HEIGHT: &str = "starkware.starknet.core.os.state.commitment.MERKLE_HEIGHT";
    pub const STORED_BLOCK_HASH_BUFFER: &str = "starkware.starknet.core.os.constants.STORED_BLOCK_HASH_BUFFER";
    pub const VALIDATED: &str = "starkware.starknet.core.os.constants.VALIDATED";
}
