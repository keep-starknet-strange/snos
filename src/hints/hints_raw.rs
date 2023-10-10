pub const SN_INPUT_RAW: &str = r#"from starkware.starknet.core.os.os_input import StarknetOsInput

os_input = StarknetOsInput.load(data=program_input)

ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()"#;

pub const LOAD_COMPILED_CLASS_FACTS: &str = r#"ids.compiled_class_facts = segments.add()
ids.n_compiled_class_facts = len(os_input.compiled_classes)
vm_enter_scope({
    'compiled_class_facts': iter(os_input.compiled_classes.items()),
})"#;

pub const _VM_ENTER_SCOPE: &str = "
# This hint shouldn't be whitelisted.
vm_enter_scope(dict(
    commitment_info_by_address=execution_helper.compute_storage_commitments(),
    os_input=os_input,
))
ids.initial_state_updates_ptr = segments.add_temp_segment()
";

pub const _VM_EXIT_SCOPE: &str = "vm_exit_scope()";

pub const _INITIAL_DICT_INIT: &str = "
from starkware.python.utils import from_bytes

initial_dict = {
    address: segments.gen_arg(
        (from_bytes(contract.contract_hash), segments.add(), contract.nonce))
    for address, contract in os_input.contracts.items()
}
";

pub const _INITIAL_DICT_APPEND_CLASS_HASH: &str =
    "initial_dict = os_input.class_hash_to_compiled_class_hash";

pub const _MAP_CONTRACT_STATE: &str = "
ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
    ids.BLOCK_HASH_CONTRACT_ADDRESS
]
";

pub const _MAP_BLOCK_HASH: &str = r#"
(
    old_block_number, old_block_hash
) = execution_helper.get_old_block_number_and_hash()
assert old_block_number == ids.old_block_number,(
    "Inconsistent block number. "
    "The constant STORED_BLOCK_HASH_BUFFER is probably out of sync."
)
ids.old_block_hash = old_block_hash
"#;

pub const _UPDATE_MAPPING: &str = "
storage = execution_helper.storage_by_address[ids.BLOCK_HASH_CONTRACT_ADDRESS]
storage.write(key=ids.old_block_number, value=ids.old_block_hash)
";
