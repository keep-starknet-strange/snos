pub const STARKNET_OS_INPUT: &str = "from starkware.starknet.core.os.os_input import StarknetOsInput\n\nos_input = \
     StarknetOsInput.load(data=program_input)\n\nids.initial_carried_outputs.messages_to_l1 = \
     segments.add_temp_segment()\nids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()";

pub const LOAD_CLASS_FACTS: &str = "ids.compiled_class_facts = segments.add()\nids.n_compiled_class_facts = \
                                    len(os_input.compiled_classes)\nvm_enter_scope({\n    'compiled_class_facts': \
                                    iter(os_input.compiled_classes.items()),\n})";

pub const LOAD_DEPRECATED_CLASS_FACTS: &str =
    "# Creates a set of deprecated class hashes to distinguish calls to deprecated entry \
     points.\n__deprecated_class_hashes=set(os_input.deprecated_compiled_classes.keys())\nids.compiled_class_facts = \
     segments.add()\nids.n_compiled_class_facts = len(os_input.deprecated_compiled_classes)\nvm_enter_scope({\n    \
     'compiled_class_facts': iter(os_input.deprecated_compiled_classes.items()),\n})";

pub const LOAD_DEPRECATED_CLASS_INNER: &str =
    "from starkware.starknet.core.os.contract_class.deprecated_class_hash import (\n    \
     get_deprecated_contract_class_struct,\n)\n\ncompiled_class_hash, compiled_class = \
     next(compiled_class_facts)\n\ncairo_contract = get_deprecated_contract_class_struct(\n    \
     identifiers=ids._context.identifiers, contract_class=compiled_class)\nids.compiled_class = \
     segments.gen_arg(cairo_contract)";

pub const CHECK_DEPRECATED_CLASS_HASH: &str =
    "from starkware.python.utils import from_bytes\n\ncomputed_hash = ids.compiled_class_fact.hash\nexpected_hash = \
     compiled_class_hash\nassert computed_hash == expected_hash, (\n    \"Computed compiled_class_hash is \
     inconsistent with the hash in the os_input. \"\n    f\"Computed hash = {computed_hash}, Expected hash = \
     {expected_hash}.\")\n\nvm_load_program(compiled_class.program, ids.compiled_class.bytecode_ptr)";

/// This is the equivalent of nondet %{ os_input.general_config.sequencer_address %}
pub const SEQUENCER_ADDRESS: &str = "memory[ap] = to_felt_or_relocatable(os_input.general_config.sequencer_address)";

pub const DEPRECATED_BLOCK_NUMBER: &str =
    "memory[ap] = to_felt_or_relocatable(deprecated_syscall_handler.block_info.block_number)";

pub const DEPRECATED_BLOCK_TIMESTAMP: &str =
    "memory[ap] = to_felt_or_relocatable(deprecated_syscall_handler.block_info.block_timestamp)";

pub const CHAIN_ID: &str = "memory[ap] = to_felt_or_relocatable(os_input.general_config.chain_id.value)";

pub const FEE_TOKEN_ADDRESS: &str = "memory[ap] = to_felt_or_relocatable(os_input.general_config.fee_token_address)";

pub const INITIALIZE_STATE_CHANGES: &str = "from starkware.python.utils import from_bytes\n\ninitial_dict = {\n    \
                                            address: segments.gen_arg(\n        (from_bytes(contract.contract_hash), \
                                            segments.add(), contract.nonce))\n    for address, contract in \
                                            os_input.contracts.items()\n}";

pub const INITIALIZE_CLASS_HASHES: &str = "initial_dict = os_input.class_hash_to_compiled_class_hash";

pub const GET_BLOCK_MAPPING: &str =
    "ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[\n    ids.BLOCK_HASH_CONTRACT_ADDRESS\n]";

pub const SEGMENTS_ADD: &str = "memory[ap] = to_felt_or_relocatable(segments.add())";

pub const SEGMENTS_ADD_TEMP: &str = "memory[ap] = to_felt_or_relocatable(segments.add_temp_segment())";

pub const TRANSACTIONS_LEN: &str = "memory[ap] = to_felt_or_relocatable(len(os_input.transactions))";

pub const ENTER_SYSCALL_SCOPES: &str =
    "vm_enter_scope({\n    '__deprecated_class_hashes': __deprecated_class_hashes,\n    'transactions': \
     iter(os_input.transactions),\n    'execution_helper': execution_helper,\n    'deprecated_syscall_handler': \
     deprecated_syscall_handler,\n    'syscall_handler': syscall_handler,\n     '__dict_manager': __dict_manager,\n})";

pub const LOAD_NEXT_TX: &str = "tx = next(transactions)\ntx_type_bytes = \
                                tx.tx_type.name.encode(\"ascii\")\nids.tx_type = int.from_bytes(tx_type_bytes, \
                                \"big\")";

pub const LOAD_CONTRACT_ADDRESS: &str = "from starkware.starknet.business_logic.transaction.objects import \
                                         InternalL1Handler\nids.contract_address = (\ntx.contract_address if \
                                         isinstance(tx, InternalL1Handler) else tx.sender_address\n)";

pub const PREPARE_CONSTRUCTOR_EXECUTION: &str = "ids.contract_address_salt = tx.contract_address_salt\nids.class_hash = \
                       tx.class_hash\nids.constructor_calldata_size = len(tx.constructor_calldata)\nids.constructor_calldata \
                       = segments.gen_arg(arg=tx.constructor_calldata)";

pub const TRANSACTION_VERSION: &str = "memory[ap] = to_felt_or_relocatable(tx.version)";

pub const ASSERT_TRANSACTION_HASH: &str = "assert ids.transaction_hash == tx.hash_value, (\n    \"Computed transaction_hash \
                        is inconsistent with the hash in the transaction. \"\n    f\"Computed hash = {ids.transaction_hash}, \
                        Expected hash = {tx.hash_value}.\")";
