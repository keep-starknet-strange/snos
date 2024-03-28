pub mod scopes {
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
    pub const BLOCK_HASH_CONTRACT_ADDRESS: &str = "BLOCK_HASH_CONTRACT_ADDRESS";
    pub const CALLDATA: &str = "calldata";
    pub const CHILD_BIT: &str = "CHILD_BIT";
    pub const COMPILED_CLASS: &str = "compiled_class";
    pub const COMPILED_CLASS_FACT: &str = "compiled_class_fact";
    pub const CONTRACT_ADDRESS: &str = "contract_address";
    pub const CONTRACT_STATE_CHANGES: &str = "contract_state_changes";
    pub const DA_START: &str = "da_start";
    pub const DEPRECATED_TX_INFO: &str = "deprecated_tx_info";
    pub const DEST_PTR: &str = "dest_ptr";
    pub const EDGE: &str = "edge";
    pub const FINAL_ROOT: &str = "final_root";
    pub const HASH_PTR: &str = "hash_ptr";
    pub const INITIAL_ROOT: &str = "initial_root";
    pub const IS_ON_CURVE: &str = "is_on_curve";
    pub const MAX_FEE: &str = "max_fee";
    pub const MERKLE_HEIGHT: &str = "MERKLE_HEIGHT";
    pub const N: &str = "n";
    pub const NEW_STATE_ENTRY: &str = "new_state_entry";
    pub const NODE: &str = "node";
    pub const OS_CONTEXT: &str = "os_context";
    pub const OUTPUT_PTR: &str = "output_ptr";
    pub const PREV_VALUE: &str = "prev_value";
    pub const REQUEST: &str = "request";
    pub const SECP_P: &str = "SECP_P";
    pub const SENDER_ADDRESS: &str = "sender_address";
    pub const SIBLINGS: &str = "siblings";
    pub const SIGNATURE_LEN: &str = "signature_len";
    pub const SIGNATURE_START: &str = "signature_start";
    pub const SRC_PTR: &str = "src_ptr";
    pub const STATE_ENTRY: &str = "state_entry";
    pub const SYSCALL_PTR: &str = "syscall_ptr";
    pub const TX_VERSION: &str = "tx_version";

    pub const VALUE: &str = "value";
    pub const WORD: &str = "word";
    pub const Y: &str = "y";
    pub const Y_SQUARE_INT: &str = "y_square_int";
}
