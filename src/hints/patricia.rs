use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
    insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::cairo_types::builtins::HashBuiltin;
use crate::cairo_types::dict_access::DictAccess;
use crate::cairo_types::trie::NodeEdge;
use crate::hints::types::{skip_verification_if_configured, PatriciaSkipValidationRunner, Preimage};
use crate::hints::vars;
use crate::starknet::starknet_storage::StorageLeaf;
use crate::starkware_utils::commitment_tree::base_types::{DescentMap, DescentPath, DescentStart, Height, NodePath};
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_guess_descents::patricia_guess_descents;
use crate::starkware_utils::commitment_tree::update_tree::{
    build_update_tree, decode_node, DecodeNodeCase, DecodedNode, UpdateTree,
};

pub const SET_SIBLINGS: &str = "memory[ids.siblings], ids.word = descend";

pub fn set_siblings(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let descend: DescentPath = exec_scopes.get(vars::scopes::DESCEND)?;

    let length = descend.0;
    let relative_path = descend.1;

    let siblings = get_ptr_from_var_name(vars::ids::SIBLINGS, vm, ids_data, ap_tracking)?;
    vm.insert_value(siblings, Felt252::from(length.0))?;

    insert_value_from_var_name(vars::ids::WORD, Felt252::from(relative_path.0), vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const IS_CASE_RIGHT: &str = "memory[ap] = int(case == 'right') ^ ids.bit";

pub fn is_case_right(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let case: DecodeNodeCase = exec_scopes.get(vars::scopes::CASE)?;
    let bit = get_integer_from_var_name(vars::ids::BIT, vm, ids_data, ap_tracking)?;

    let case_felt = match case {
        DecodeNodeCase::Right => Felt252::ONE,
        _ => Felt252::ZERO,
    };

    // Felts do not support XOR, perform the computation on biguints.
    let value = bit.to_biguint() ^ case_felt.to_biguint();
    let value_felt = Felt252::from(&value);
    insert_value_into_ap(vm, value_felt)?;

    Ok(())
}

pub const SET_BIT: &str = "ids.bit = (ids.edge.path >> ids.new_length) & 1";

pub fn set_bit(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let edge_ptr = get_relocatable_from_var_name(vars::ids::EDGE, vm, ids_data, ap_tracking)?;
    let edge_path = vm.get_integer((edge_ptr + NodeEdge::path_offset())?)?.into_owned();
    let new_length = {
        let new_length = get_integer_from_var_name(vars::ids::NEW_LENGTH, vm, ids_data, ap_tracking)?;
        new_length.to_u64().ok_or(MathError::Felt252ToU64Conversion(Box::new(new_length)))?
    };

    let bit = (edge_path.to_biguint() >> new_length) & BigUint::from(1u64);
    let bit_felt = Felt252::from(&bit);
    insert_value_from_var_name(vars::ids::BIT, bit_felt, vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const SET_AP_TO_DESCEND: &str = indoc! {r#"
	descend = descent_map.get((ids.height, ids.path))
	memory[ap] = 0 if descend is None else 1"#
};

pub fn set_ap_to_descend(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let descent_map: DescentMap = exec_scopes.get(vars::scopes::DESCENT_MAP)?;

    let height = get_integer_from_var_name(vars::ids::HEIGHT, vm, ids_data, ap_tracking)?;
    let path = get_integer_from_var_name(vars::ids::PATH, vm, ids_data, ap_tracking)?;

    let height = height.try_into()?;
    let path = NodePath(path.to_biguint());

    let descent_start = DescentStart(height, path);
    let ap = match descent_map.get(&descent_start) {
        None => Felt252::ZERO,
        Some(value) => {
            exec_scopes.insert_value(vars::ids::DESCEND, value.clone());
            Felt252::ONE
        }
    };

    insert_value_into_ap(vm, ap)?;

    Ok(())
}

pub const ASSERT_CASE_IS_RIGHT: &str = "assert case == 'right'";

pub fn assert_case_is_right(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let case: DecodeNodeCase = exec_scopes.get(vars::scopes::CASE)?;
    match case {
        DecodeNodeCase::Right => Ok(()),
        _ => Err(HintError::AssertionFailed("case != 'right".to_string().into_boxed_str())),
    }
}

pub const WRITE_CASE_NOT_LEFT_TO_AP: &str = indoc! {r#"
    memory[ap] = int(case != 'left')"#
};
pub fn write_case_not_left_to_ap(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let case: DecodeNodeCase = exec_scopes.get(vars::scopes::CASE)?;
    let value = Felt252::from(case != DecodeNodeCase::Left);
    insert_value_into_ap(vm, value)?;
    Ok(())
}

pub const SPLIT_DESCEND: &str = "ids.length, ids.word = descend";

pub fn split_descend(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let descend: DescentPath = exec_scopes.get(vars::scopes::DESCEND)?;

    let length = descend.0;
    let word = descend.1;

    insert_value_from_var_name(vars::ids::LENGTH, Felt252::from(length.0), vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(vars::ids::WORD, Felt252::from(word.0), vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const HEIGHT_IS_ZERO_OR_LEN_NODE_PREIMAGE_IS_TWO: &str =
    "memory[ap] = 1 if ids.height == 0 or len(preimage[ids.node]) == 2 else 0";

pub fn height_is_zero_or_len_node_preimage_is_two(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let height = get_integer_from_var_name(vars::ids::HEIGHT, vm, ids_data, ap_tracking)?;
    let node = get_integer_from_var_name(vars::ids::NODE, vm, ids_data, ap_tracking)?;

    let ap = if height == Felt252::ZERO {
        Felt252::ONE
    } else {
        let preimage: Preimage = exec_scopes.get(vars::scopes::PREIMAGE)?;
        let preimage_value = preimage
            .get(node.as_ref())
            .ok_or(HintError::CustomHint("No preimage found for node".to_string().into_boxed_str()))?;
        Felt252::from(preimage_value.len() == 2)
    };

    insert_value_into_ap(vm, ap)?;

    Ok(())
}

pub const PREPARE_PREIMAGE_VALIDATION_NON_DETERMINISTIC_HASHES: &str = indoc! {r#"
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

pub fn prepare_preimage_validation_non_deterministic_hashes(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let node: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::NODE)?;
    let node = node.ok_or(HintError::AssertionFailed("'node' should not be None".to_string().into_boxed_str()))?;

    let preimage: Preimage = exec_scopes.get(vars::scopes::PREIMAGE)?;

    let ids_node = get_integer_from_var_name(vars::ids::NODE, vm, ids_data, ap_tracking)?;

    let DecodedNode { left_child, right_child, case } = decode_node(&node)?;

    exec_scopes.insert_value(vars::scopes::LEFT_CHILD, left_child.clone());
    exec_scopes.insert_value(vars::scopes::RIGHT_CHILD, right_child.clone());
    exec_scopes.insert_value(vars::scopes::CASE, case.clone());

    let node_preimage =
        preimage.get(&ids_node).ok_or(HintError::CustomHint("Node preimage not found".to_string().into_boxed_str()))?;
    let left_hash = node_preimage[0];
    let right_hash = node_preimage[1];

    // Fill non deterministic hashes.
    let hash_ptr = get_ptr_from_var_name(vars::ids::CURRENT_HASH, vm, ids_data, ap_tracking)?;
    // memory[hash_ptr + ids.HashBuiltin.x] = left_hash
    vm.insert_value((hash_ptr + HashBuiltin::x_offset())?, left_hash)?;
    // memory[hash_ptr + ids.HashBuiltin.y] = right_hash
    vm.insert_value((hash_ptr + HashBuiltin::y_offset())?, right_hash)?;

    let hash_result_address = (hash_ptr + HashBuiltin::result_offset())?;
    skip_verification_if_configured(exec_scopes, hash_result_address)?;

    // memory[ap] = int(case != 'both')"#
    let ap = match case {
        DecodeNodeCase::Both => Felt252::ZERO,
        _ => Felt252::ONE,
    };
    insert_value_into_ap(vm, ap)?;

    Ok(())
}

pub const BUILD_DESCENT_MAP: &str = indoc! {r#"
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

pub fn build_descent_map(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // Build modifications list.
    let n_updates = get_integer_from_var_name(vars::ids::N_UPDATES, vm, ids_data, ap_tracking)?;
    let n_updates = felt_to_usize(&n_updates)?;
    let update_ptr_address = get_ptr_from_var_name(vars::ids::UPDATE_PTR, vm, ids_data, ap_tracking)?;

    let modifications = {
        let mut modifications = vec![];
        for i in 0..n_updates {
            let curr_update_ptr = (update_ptr_address + i * DictAccess::cairo_size())?;
            let tree_index = vm.get_integer((curr_update_ptr + DictAccess::key_offset())?)?;
            let new_value = vm.get_integer((curr_update_ptr + DictAccess::new_value_offset())?)?;

            modifications.push((tree_index.into_owned().to_biguint(), StorageLeaf::new(new_value.into_owned())));
        }
        modifications
    };

    // Build the descent map.
    let height: Height = get_integer_from_var_name(vars::ids::HEIGHT, vm, ids_data, ap_tracking)?.try_into()?;
    let prev_root = get_integer_from_var_name(vars::ids::PREV_ROOT, vm, ids_data, ap_tracking)?.to_biguint();
    let new_root = get_integer_from_var_name(vars::ids::NEW_ROOT, vm, ids_data, ap_tracking)?.to_biguint();

    let preimage: &Preimage = exec_scopes.get_ref(vars::scopes::PREIMAGE)?;

    let node: UpdateTree<StorageLeaf> = build_update_tree(height, modifications);
    let descent_map = patricia_guess_descents::<StorageLeaf>(height, node.clone(), preimage, prev_root, new_root)?;

    exec_scopes.insert_value(vars::scopes::NODE, node.clone());
    // Notes:
    // 1. We do not build `common_args` as it seems to be a Python trick to enter new scopes with a dict
    //    destructuring one-liner as the dict references itself. Neat trick that does not translate too
    //    well in Rust. We just make sure that `descent_map`, `__patricia_skip_validation_runner` and
    //    `preimage` are in the scope.
    // 2. The Rust VM has no `globals()`, `__patricia_skip_validation_runner` should already be in
    //    `exec_scopes.data[0]`.
    // 3. `preimage` is guaranteed to be present as we fetch it earlier. Conclusion: we only need to
    //    insert `__patricia_skip_validation_runner` and `descent_map`.
    exec_scopes.insert_value(vars::scopes::DESCENT_MAP, descent_map);

    let patricia_skip_validation_runner = exec_scopes.data[0]
        .get(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER)
        .map(|var| var.downcast_ref::<PatriciaSkipValidationRunner>().cloned())
        .ok_or(HintError::VariableNotInScopeError(
            vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER.to_string().into_boxed_str(),
        ))?;
    exec_scopes.insert_value(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER, patricia_skip_validation_runner);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
    use cairo_vm::hint_processor::hint_processor_definition::HintReference;
    use cairo_vm::serde::deserialize_program::ApTracking;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use cairo_vm::types::relocatable::Relocatable;
    use cairo_vm::vm::vm_core::VirtualMachine;
    use cairo_vm::Felt252;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(DecodeNodeCase::Left, 0, 0)]
    #[case(DecodeNodeCase::Left, 1, 1)]
    #[case(DecodeNodeCase::Right, 0, 1)]
    #[case(DecodeNodeCase::Right, 1, 0)]
    fn test_is_case_right(#[case] case: DecodeNodeCase, #[case] bit: u64, #[case] expected: u64) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_ap(1);
        vm.set_fp(1);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([(vars::ids::BIT.to_string(), HintReference::new_simple(-1))]);

        insert_value_from_var_name(vars::ids::BIT, Felt252::from(bit), &mut vm, &ids_data, &ap_tracking).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::CASE, case);

        // Just make sure that the hint goes through, all meaningful assertions are
        // in the implementation of the hint
        is_case_right(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).expect("Hint should succeed");

        assert_eq!(vm.get_integer(vm.get_ap()).unwrap().into_owned(), Felt252::from(expected));
    }

    #[test]
    fn test_set_bit() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(5);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::EDGE.to_string(), HintReference::new_simple(-5)),
            (vars::ids::NEW_LENGTH.to_string(), HintReference::new_simple(-2)),
            (vars::ids::BIT.to_string(), HintReference::new_simple(-1)),
        ]);

        let new_length = Felt252::from(3);
        let edge_path = Felt252::from(0x8);

        // edge.path is at offset 1
        vm.insert_value(Relocatable::from((1, 1)), edge_path).unwrap();
        insert_value_from_var_name(vars::ids::NEW_LENGTH, new_length, &mut vm, &ids_data, &ap_tracking).unwrap();

        let mut exec_scopes = ExecutionScopes::default();

        // Just make sure that the hint goes through, all meaningful assertions are
        // in the implementation of the hint
        set_bit(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).expect("Hint should succeed");

        let bit = get_integer_from_var_name(vars::ids::BIT, &mut vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(bit, Felt252::from(1));
    }
}
