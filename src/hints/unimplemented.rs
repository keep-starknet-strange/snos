use indoc::indoc;

#[allow(unused)]
const IS_ON_CURVE: &str = "ids.is_on_curve = (y * y) % SECP_P == y_square_int";

#[allow(unused)]
const CACHE_CONTRACT_STORAGE: &str = indoc! {r#"
	# Make sure the value is cached (by reading it), to be used later on for the
	# commitment computation.
	value = execution_helper.storage_by_address[ids.contract_address].read(key=ids.request.key)
	assert ids.value == value, "Inconsistent storage value.""#
};

#[allow(unused)]
const FETCH_STATE_ENTRY: &str = indoc! {r#"
	# Fetch a state_entry in this hint. Validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
	    ids.BLOCK_HASH_CONTRACT_ADDRESS]
	ids.new_state_entry = segments.add()"#
};

#[allow(unused)]
const SET_INITIAL_STATE_UPDATES_PTR: &str = indoc! {r#"
	# This hint shouldn't be whitelisted.
	vm_enter_scope(dict(
	    commitment_info_by_address=execution_helper.compute_storage_commitments(),
	    os_input=os_input,
	))
	ids.initial_state_updates_ptr = segments.add_temp_segment()"#
};

#[allow(unused)]
const ENTER_SCOPE_NEW_NODE: &str = indoc! {r#"
	ids.child_bit = 0 if case == 'left' else 1
	new_node = left_child if case == 'left' else right_child
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

#[allow(unused)]
const SET_AP_TO_CALLDATA_LEN: &str = "memory[ap] = to_felt_or_relocatable(len(tx.calldata))";

#[allow(unused)]
const ADD_RELOCATION_RULE: &str = "memory.add_relocation_rule(src_ptr=ids.src_ptr, dest_ptr=ids.dest_ptr)";

#[allow(unused)]
const SET_AP_TO_NONCE: &str = "memory[ap] = to_felt_or_relocatable(tx.nonce)";

#[allow(unused)]
const DECODE_NODE: &str = indoc! {r#"
	from starkware.python.merkle_tree import decode_node
	left_child, right_child, case = decode_node(node)
	memory[ap] = int(case != 'both')"#
};

#[allow(unused)]
const GEN_SIGNATURE_ARG: &str = indoc! {r#"
	ids.signature_start = segments.gen_arg(arg=tx.signature)
	ids.signature_len = len(tx.signature)"#
};

#[allow(unused)]
const GEN_CALLDATA_ARG: &str = "memory[ap] = to_felt_or_relocatable(segments.gen_arg(tx.calldata))";

#[allow(unused)]
const SET_AP_TO_ENTRY_POINT_SELECTOR: &str = "memory[ap] = to_felt_or_relocatable(tx.entry_point_selector)";

#[allow(unused)]
const SET_TREE_STRUCTURE: &str = indoc! {r#"
	from starkware.python.math_utils import div_ceil
	onchain_data_start = ids.da_start
	onchain_data_size = ids.output_ptr - onchain_data_start

	max_page_size = 3800
	n_pages = div_ceil(onchain_data_size, max_page_size)
	for i in range(n_pages):
	    start_offset = i * max_page_size
	    output_builtin.add_page(
	        page_id=1 + i,
	        page_start=onchain_data_start + start_offset,
	        page_size=min(onchain_data_size - start_offset, max_page_size),
	    )
	# Set the tree structure to a root with two children:
	# * A leaf which represents the main part
	# * An inner node for the onchain data part (which contains n_pages children).
	#
	# This is encoded using the following sequence:
	output_builtin.add_attribute('gps_fact_topology', [
	    # Push 1 + n_pages pages (all of the pages).
	    1 + n_pages,
	    # Create a parent node for the last n_pages.
	    n_pages,
	    # Don't push additional pages.
	    0,
	    # Take the first page (the main part) and the node that was created (onchain data)
	    # and use them to construct the root of the fact tree.
	    2,
	])"#
};

#[allow(unused)]
const SET_AP_TO_ACTUAL_FEE: &str = "memory[ap] = to_felt_or_relocatable(execution_helper.tx_execution_info.actual_fee)";

#[allow(unused)]
const SPLIT_OUTPUT1: &str = indoc! {r#"
	tmp, ids.output1_low = divmod(ids.output1, 256 ** 7)
	ids.output1_high, ids.output1_mid = divmod(tmp, 2 ** 128)"#
};

#[allow(unused)]
const WRITE_SYSCALL_RESULT: &str = indoc! {r#"
	storage = execution_helper.storage_by_address[ids.contract_address]
	ids.prev_value = storage.read(key=ids.syscall_ptr.address)
	storage.write(key=ids.syscall_ptr.address, value=ids.syscall_ptr.value)

	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]

	ids.new_state_entry = segments.add()"#
};

#[allow(unused)]
const SET_SIBLINGS: &str = "memory[ids.siblings], ids.word = descend";

#[allow(unused)]
const SPLIT_OUTPUT0: &str = indoc! {r#"
	ids.output0_low = ids.output0 & ((1 << 128) - 1)
	ids.output0_high = ids.output0 >> 128"#
};

#[allow(unused)]
const ENTER_SCOPE_SYSCALL_HANDLER: &str = "vm_enter_scope({'syscall_handler': syscall_handler})";

#[allow(unused)]
const GEN_NONCE_ARG: &str = indoc! {r#"
	ids.tx_version = tx.version
	ids.max_fee = tx.max_fee
	ids.sender_address = tx.sender_address
	ids.calldata = segments.gen_arg([tx.class_hash])

	if tx.version <= 1:
	    assert tx.compiled_class_hash is None, (
	        "Deprecated declare must not have compiled_class_hash."
	    )
	    ids.additional_data = segments.gen_arg([tx.nonce])
	else:
	    assert tx.compiled_class_hash is not None, (
	        "Declare must have a concrete compiled_class_hash."
	    )
	    ids.additional_data = segments.gen_arg([tx.nonce, tx.compiled_class_hash])"#
};

#[allow(unused)]
const HAS_ENOUGH_GAS: &str = "memory[ap] = to_felt_or_relocatable(ids.initial_gas >= ids.required_gas)";

#[allow(unused)]
const IS_CASE_RIGHT: &str = "memory[ap] = int(case == 'right') ^ ids.bit";

#[allow(unused)]
const PREPARE_PREIMAGE_VALIDATION: &str = indoc! {r#"
	ids.edge = segments.add()
	ids.edge.length, ids.edge.path, ids.edge.bottom = preimage[ids.node]
	ids.hash_ptr.result = ids.node - ids.edge.length
	if __patricia_skip_validation_runner is not None:
	    # Skip validation of the preimage dict to speed up the VM. When this flag is set,
	    # mistakes in the preimage dict will be discovered only in the prover.
	    __patricia_skip_validation_runner.verified_addresses.add(
	        ids.hash_ptr + ids.HashBuiltin.result)"#
};

#[allow(unused)]
const SPLIT_INPUTS_3: &str = "ids.high3, ids.low3 = divmod(memory[ids.inputs + 3], 256)";

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
const SKIP_CALL: &str = "execution_helper.skip_call()";

#[allow(unused)]
const SET_BIT: &str = "ids.bit = (ids.edge.path >> ids.new_length) & 1";

#[allow(unused)]
const SET_AP_TO_BLOCK_HASH: &str = "memory[ap] = to_felt_or_relocatable(os_input.block_hash)";

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
const SET_AP_TO_MAX_FEE: &str = "memory[ap] = to_felt_or_relocatable(tx.max_fee)";

#[allow(unused)]
const ENTER_SCOPE_NEXT_NODE: &str = indoc! {r#"
	new_node = left_child if ids.bit == 0 else right_child
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

#[allow(unused)]
const ASSERT_CASE_IS_RIGHT: &str = "assert case == 'right'";

#[allow(unused)]
const SET_TX_INFO_PTR: &str = indoc! {r#"
	tx_info_ptr = ids.tx_execution_context.deprecated_tx_info.address_
	execution_helper.start_tx(tx_info_ptr=tx_info_ptr)"#
};

#[allow(unused)]
const SPLIT_INPUTS_12: &str = "ids.high12, ids.low12 = divmod(memory[ids.inputs + 12], 256 ** 4)";

#[allow(unused)]
const SKIP_TX: &str = "execution_helper.skip_tx()";

#[allow(unused)]
const SET_AP_TO_IS_REVERTED: &str =
    "memory[ap] = to_felt_or_relocatable(execution_helper.tx_execution_info.is_reverted)";

#[allow(unused)]
const ENTER_SCOPE_NEXT_NODE_2: &str = indoc! {r#"
	new_node = left_child if ids.bit == 1 else right_child
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

#[allow(unused)]
const START_TX: &str = "execution_helper.start_tx(tx_info_ptr=ids.deprecated_tx_info.address_)";

#[allow(unused)]
const WRITE_OLD_BLOCK_TO_STORAGE: &str = indoc! {r#"
	storage = execution_helper.storage_by_address[ids.BLOCK_HASH_CONTRACT_ADDRESS]
	storage.write(key=ids.old_block_number, value=ids.old_block_hash)"#
};

#[allow(unused)]
const DECODE_NODE_2: &str = indoc! {r#"
	from starkware.python.merkle_tree import decode_node
	left_child, right_child, case = decode_node(node)
	memory[ap] = 1 if case != 'both' else 0"#
};

#[allow(unused)]
const SET_AP_TO_NOT_DESCEND: &str = indoc! {r#"
	descend = descent_map.get((ids.height, ids.path))
	memory[ap] = 0 if descend is None else 1"#
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
const SET_CONTRACT_ADDRESS: &str = indoc! {r#"
	from starkware.starknet.business_logic.transaction.objects import InternalL1Handler
	ids.contract_address = (
	    tx.contract_address if isinstance(tx, InternalL1Handler) else tx.sender_address
	)"#
};

#[allow(unused)]
const SET_AP_TO_NONCE_ARG_SEGMENT: &str = "memory[ap] = to_felt_or_relocatable(segments.gen_arg([tx.nonce]))";

#[allow(unused)]
const COMPARE_RETURN_VALUE: &str = indoc! {r#"
	# Check that the actual return value matches the expected one.
	expected = memory.get_range(
	    addr=ids.call_response.retdata, size=ids.call_response.retdata_size
	)
	actual = memory.get_range(addr=ids.retdata, size=ids.retdata_size)

	assert expected == actual, f'Return value mismatch expected={expected}, actual={actual}.'"#
};

#[allow(unused)]
const SPLIT_DESCEND: &str = "ids.length, ids.word = descend";

#[allow(unused)]
const HEIGHT_IS_ZERO_OR_LEN_NODE_PREIMAGE_IS_TWO: &str =
    "memory[ap] = 1 if ids.height == 0 or len(preimage[ids.node]) == 2 else 0";

#[allow(unused)]
const FETCH_STATE_ENTRY_3: &str = indoc! {r#"
	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
	    ids.contract_address
	]"#
};

#[allow(unused)]
const ENTER_SCOPE_NEW_TREE: &str = indoc! {r#"
	new_node = node
	for i in range(ids.length - 1, -1, -1):
	    new_node = new_node[(ids.word >> i) & 1]
	vm_enter_scope(dict(node=new_node, **common_args))"#
};

#[allow(unused)]
const SPLIT_INPUTS_15: &str = "ids.high15, ids.low15 = divmod(memory[ids.inputs + 15], 256 ** 5)";

#[allow(unused)]
const SET_PREIMAGE: &str = indoc! {r#"
	ids.initial_root = os_input.contract_class_commitment_info.previous_root
	ids.final_root = os_input.contract_class_commitment_info.updated_root
	preimage = {
	    int(root): children
	    for root, children in os_input.contract_class_commitment_info.commitment_facts.items()
	}
	assert os_input.contract_class_commitment_info.tree_height == ids.MERKLE_HEIGHT"#
};

#[allow(unused)]
const SET_PREIMAGE_COMMITMENT_INFO: &str = indoc! {r#"
	commitment_info = commitment_info_by_address[ids.state_changes.key]
	ids.initial_contract_state_root = commitment_info.previous_root
	ids.final_contract_state_root = commitment_info.updated_root
	preimage = {
	    int(root): children
	    for root, children in commitment_info.commitment_facts.items()
	}
	assert commitment_info.tree_height == ids.MERKLE_HEIGHT"#
};

#[allow(unused)]
const SPLIT_INPUTS_9: &str = "ids.high9, ids.low9 = divmod(memory[ids.inputs + 9], 256 ** 3)";

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
const SPLIT_INPUTS_6: &str = "ids.high6, ids.low6 = divmod(memory[ids.inputs + 6], 256 ** 2)";

#[allow(unused)]
const CHECK_RETURN_VALUE_2: &str = indoc! {r#"
	# Check that the actual return value matches the expected one.
	expected = memory.get_range(
	    addr=ids.response.retdata_start,
	    size=ids.response.retdata_end - ids.response.retdata_start,
	)
	actual = memory.get_range(addr=ids.retdata, size=ids.retdata_size)

	assert expected == actual, f'Return value mismatch; expected={expected}, actual={actual}.'"#
};

#[allow(unused)]
const FETCH_STATE_ENTRY_4: &str = indoc! {r#"
	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
	ids.new_state_entry = segments.add()"#
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
const SET_PREIMAGE_2: &str = indoc! {r#"
	ids.initial_root = os_input.contract_state_commitment_info.previous_root
	ids.final_root = os_input.contract_state_commitment_info.updated_root
	preimage = {
	    int(root): children
	    for root, children in os_input.contract_state_commitment_info.commitment_facts.items()
	}
	assert os_input.contract_state_commitment_info.tree_height == ids.MERKLE_HEIGHT"#
};

#[allow(unused)]
const IS_N_GE_TEN: &str = "memory[ap] = to_felt_or_relocatable(ids.n >= 10)";

#[allow(unused)]
const ENTER_SCOPE_LEFT_CHILD: &str = "vm_enter_scope(dict(node=left_child, **common_args))";

#[allow(unused)]
const ENTER_SCOPE_NODE: &str = "vm_enter_scope(dict(node=node, **common_args))";

#[allow(unused)]
const CHECK_RETURN_VALUE_3: &str = indoc! {r#"
	# Check that the actual return value matches the expected one.
	expected = memory.get_range(
	    addr=ids.response.constructor_retdata_start,
	    size=ids.response.constructor_retdata_end - ids.response.constructor_retdata_start,
	)
	actual = memory.get_range(addr=ids.retdata, size=ids.retdata_size)
	assert expected == actual, f'Return value mismatch; expected={expected}, actual={actual}.'"#
};

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
const FETCH_STATE_ENTRY_5: &str = indoc! {r#"
	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
	    ids.contract_address
	]

	ids.new_state_entry = segments.add()"#
};

#[allow(unused)]
const ENTER_SCOPE_RIGHT_CHILD: &str = "vm_enter_scope(dict(node=right_child, **common_args))";

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
