use indoc::indoc;

#[allow(unused)]
const HAS_ENOUGH_GAS: &str = "memory[ap] = to_felt_or_relocatable(ids.initial_gas >= ids.required_gas)";

#[allow(unused)]
const CACHE_CONTRACT_STORAGE_2: &str = indoc! {r#"
	# Make sure the value is cached (by reading it), to be used later on for the
	# commitment computation.
	value = execution_helper.storage_by_address[ids.contract_address].read(
	    key=ids.syscall_ptr.request.address
	)
	assert ids.value == value, "Inconsistent storage value.""#
};

#[allow(unused)]
const VALIDATE_AND_DISCARD_SYSCALL_PTR: &str = indoc! {r#"
	syscall_handler.validate_and_discard_syscall_ptr(
	    syscall_ptr_end=ids.entry_point_return_values.syscall_ptr
	)
	execution_helper.exit_call()"#
};

#[allow(unused)]
const GET_OLD_BLOCK_NUMBER_AND_HASH: &str = indoc! {r#"
	(
	    old_block_number, old_block_hash
	) = execution_helper.get_old_block_number_and_hash()
	assert old_block_number == ids.old_block_number,(
	    "Inconsistent block number. "
	    "The constant STORED_BLOCK_HASH_BUFFER is probably out of sync."
	)
	ids.old_block_hash = old_block_hash"#
};

#[allow(unused)]
const ASSERT_CASE_IS_RIGHT: &str = "assert case == 'right'";

#[allow(unused)]
const WRITE_OLD_BLOCK_TO_STORAGE: &str = indoc! {r#"
	storage = execution_helper.storage_by_address[ids.BLOCK_HASH_CONTRACT_ADDRESS]
	storage.write(key=ids.old_block_number, value=ids.old_block_hash)"#
};

#[allow(unused)]
const PREPARE_PREIMAGE_VALIDATION_BOTTOM: &str = indoc! {r#"
	ids.hash_ptr.x, ids.hash_ptr.y = preimage[ids.edge.bottom]
	if __patricia_skip_validation_runner:
	    # Skip validation of the preimage dict to speed up the VM. When this flag is
	    # set, mistakes in the preimage dict will be discovered only in the prover.
	    __patricia_skip_validation_runner.verified_addresses.add(
	        ids.hash_ptr + ids.HashBuiltin.result)"#
};

#[allow(unused)]
const HEIGHT_IS_ZERO_OR_LEN_NODE_PREIMAGE_IS_TWO: &str =
    "memory[ap] = 1 if ids.height == 0 or len(preimage[ids.node]) == 2 else 0";

#[allow(unused)]
const SET_AP_TO_NONCE_OR_ZERO: &str = "memory[ap] = to_felt_or_relocatable(0 if tx.nonce is None else tx.nonce)";

#[allow(unused)]
const PREPARE_PREIMAGE_VALIDATION_NON_DETERMINISTIC_HASHES: &str = indoc! {r#"
	from starkware.python.merkle_tree import decode_node
	left_child, right_child, case = decode_node(node)
	left_hash, right_hash = preimage[ids.node]

	# Fill non deterministic hashes.
	hash_ptr = ids.current_hash.address_
	memory[hash_ptr + ids.HashBuiltin.x] = left_hash
	memory[hash_ptr + ids.HashBuiltin.y] = right_hash

	if __patricia_skip_validation_runner:
	    # Skip validation of the preimage dict to speed up the VM. When this flag is set,
	    # mistakes in the preimage dict will be discovered only in the prover.
	    __patricia_skip_validation_runner.verified_addresses.add(
	        hash_ptr + ids.HashBuiltin.result)

	memory[ap] = int(case != 'both')"#
};

#[allow(unused)]
const GET_COMPILED_CLASS_STRUCT: &str = indoc! {r#"
	from starkware.starknet.core.os.contract_class.compiled_class_hash import (
	    get_compiled_class_struct,
	)

	compiled_class_hash, compiled_class = next(compiled_class_facts)

	cairo_contract = get_compiled_class_struct(
	    identifiers=ids._context.identifiers, compiled_class=compiled_class)
	ids.compiled_class = segments.gen_arg(cairo_contract)"#
};

#[allow(unused)]
const BUILD_DESCENT_MAP: &str = indoc! {r#"
	from starkware.cairo.common.patricia_utils import canonic, patricia_guess_descents
	from starkware.python.merkle_tree import build_update_tree

	# Build modifications list.
	modifications = []
	DictAccess_key = ids.DictAccess.key
	DictAccess_new_value = ids.DictAccess.new_value
	DictAccess_SIZE = ids.DictAccess.SIZE
	for i in range(ids.n_updates):
	    curr_update_ptr = ids.update_ptr.address_ + i * DictAccess_SIZE
	    modifications.append((
	        memory[curr_update_ptr + DictAccess_key],
	        memory[curr_update_ptr + DictAccess_new_value]))

	node = build_update_tree(ids.height, modifications)
	descent_map = patricia_guess_descents(
	    ids.height, node, preimage, ids.prev_root, ids.new_root)
	del modifications
	__patricia_skip_validation_runner = globals().get(
	    '__patricia_skip_validation_runner')

	common_args = dict(
	    preimage=preimage, descent_map=descent_map,
	    __patricia_skip_validation_runner=__patricia_skip_validation_runner)
	common_args['common_args'] = common_args"#
};

#[allow(unused)]
const IS_N_GE_TEN: &str = "memory[ap] = to_felt_or_relocatable(ids.n >= 10)";

#[allow(unused)]
const VM_LOAD_PROGRAM: &str = indoc! {r#"
	computed_hash = ids.compiled_class_fact.hash
	expected_hash = compiled_class_hash
	assert computed_hash == expected_hash, (
	    "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
	    f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")

	vm_load_program(
	    compiled_class.get_runnable_program(entrypoint_builtins=[]),
	    ids.compiled_class.bytecode_ptr
	)"#
};

#[allow(unused)]
const IS_BLOCK_NUMBER_IN_BLOCK_HASH_BUFFER: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(ids.request_block_number > \
               ids.current_block_number - ids.STORED_BLOCK_HASH_BUFFER)"#
};

#[allow(unused)]
const START_TX_2: &str = indoc! {r#"
	execution_helper.start_tx(
	    tx_info_ptr=ids.validate_declare_execution_context.deprecated_tx_info.address_
	)"#
};

#[allow(unused)]
const GET_SEQUENCER_ADDRESS: &str =
    "syscall_handler.get_sequencer_address(segments=segments, syscall_ptr=ids.syscall_ptr)";

#[allow(unused)]
const WRITE_REQUEST: &str = indoc! {r#"
	storage = execution_helper.storage_by_address[ids.contract_address]
	ids.prev_value = storage.read(key=ids.request.key)
	storage.write(key=ids.request.key, value=ids.request.value)

	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
	ids.new_state_entry = segments.add()"#
};

#[allow(unused)]
const IS_CASE_NOT_LEFT: &str = "memory[ap] = int(case != 'left')";

#[allow(unused)]
const SET_CONTRACT_STATE_UPDATES_START: &str = "ids.contract_state_updates_start = segments.add_temp_segment()";
