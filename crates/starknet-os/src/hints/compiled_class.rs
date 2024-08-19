use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;

use crate::hints::vars;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
    BytecodeSegment, BytecodeSegmentStructureImpl,
};

pub const ASSIGN_BYTECODE_SEGMENTS: &str = indoc! {r#"
    bytecode_segments = iter(bytecode_segment_structure.segments)"#
};

pub fn assign_bytecode_segments(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentStructureImpl =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    let bytecode_segments = match bytecode_segment_structure {
        BytecodeSegmentStructureImpl::SegmentedNode(segmented_node) => {
            log::info!("got seg");
            segmented_node.segments.into_iter()
        }
        BytecodeSegmentStructureImpl::Leaf(_) => {
            return Err(HintError::AssertionFailed("Expected SegmentedNode".to_string().into_boxed_str()));
        }
    };

    exec_scopes.insert_value(vars::scopes::BYTECODE_SEGMENTS, bytecode_segments);

    Ok(())
}

pub const ASSERT_END_OF_BYTECODE_SEGMENTS: &str = indoc! {r#"
    assert next(bytecode_segments, None) is None"#
};
pub fn assert_end_of_bytecode_segments(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segments =
        exec_scopes.get_mut_ref::<<Vec<BytecodeSegment> as IntoIterator>::IntoIter>(vars::scopes::BYTECODE_SEGMENTS)?;
    // ensure the iter is exhausted. note that this consumes next() if it is not
    if bytecode_segments.next().is_some() {
        return Err(HintError::AssertionFailed("bytecode_segments is not exhausted".to_string().into_boxed_str()));
    }

    Ok(())
}

pub const ITER_CURRENT_SEGMENT_INFO: &str = indoc! {r#"
    current_segment_info = next(bytecode_segments)

    is_used = current_segment_info.is_used
    ids.is_segment_used = 1 if is_used else 0

    is_used_leaf = is_used and isinstance(current_segment_info.inner_structure, BytecodeLeaf)
    ids.is_used_leaf = 1 if is_used_leaf else 0

    ids.segment_length = current_segment_info.segment_length
    vm_enter_scope(new_scope_locals={
        "bytecode_segment_structure": current_segment_info.inner_structure,
    })"#
};
pub fn iter_current_segment_info(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segments =
        exec_scopes.get_mut_ref::<<Vec<BytecodeSegment> as IntoIterator>::IntoIter>(vars::scopes::BYTECODE_SEGMENTS)?;

    let current_segment_info =
        bytecode_segments.next().expect("Expected more bytecode segments (asserted in previous hint)");

    let is_used = current_segment_info.is_used;
    let is_used_felt = if is_used { Felt252::ONE } else { Felt252::ZERO };
    insert_value_from_var_name(vars::ids::IS_SEGMENT_USED, is_used_felt, vm, ids_data, ap_tracking)?;

    let is_leaf = matches!(current_segment_info.inner_structure, BytecodeSegmentStructureImpl::Leaf(_));
    let is_used_leaf = is_used && is_leaf;
    let is_used_leaf_felt = if is_used_leaf { Felt252::ONE } else { Felt252::ZERO };
    insert_value_from_var_name(vars::ids::IS_USED_LEAF, is_used_leaf_felt, vm, ids_data, ap_tracking)?;

    let segment_length: Felt252 = current_segment_info.segment_length.0.into();
    insert_value_from_var_name(vars::ids::SEGMENT_LENGTH, segment_length, vm, ids_data, ap_tracking)?;

    exec_scopes.enter_scope(HashMap::from([(
        vars::scopes::BYTECODE_SEGMENT_STRUCTURE.to_string(),
        any_box!(current_segment_info.inner_structure),
    )]));

    Ok(())
}

#[cfg(test)]
mod tests {
    use cairo_vm::any_box;

    use super::*;
    use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
        BytecodeLeaf, BytecodeSegmentStructureImpl, BytecodeSegmentedNode,
    };
    use crate::starkware_utils::commitment_tree::base_types::Length;

    #[test]
    fn test_bytecode_segment_hints() {
        // tests both ASSIGN_BYTECODE_SEGMENTS and ASSERT_END_OF_BYTECODE_SEGMENTS. The first
        // should prepare an iterater and put it in ExecutionScopes, the second should ensure that
        // the iterator is exhausted.

        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::new();

        let mut exec_scopes: ExecutionScopes = Default::default();

        // execution scopes must have a BytecodeSegmentStructureImpl inserted. We insert one that has one
        // segment which lets us test both success and failure of ASSERT_END_OF_BYTECODE_SEGMENTS.
        let segments = vec![BytecodeSegment {
            segment_length: Length(0),
            is_used: false,
            inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: Default::default() }),
        }];
        let segment_structure = BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode { segments });
        exec_scopes.insert_box(vars::scopes::BYTECODE_SEGMENT_STRUCTURE, any_box!(segment_structure));

        assign_bytecode_segments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        // iter is not empty, so the next call should fail. notice that it will consume next(),
        // though.
        let res = assert_end_of_bytecode_segments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants);
        assert!(res.is_err());
        match res.unwrap_err() {
            HintError::AssertionFailed(msg) => {
                assert_eq!(msg, "bytecode_segments is not exhausted".to_string().into_boxed_str())
            }
            _ => panic!("Unexpected error returned"),
        }

        // should succeed this time because iter as exhausted
        let res = assert_end_of_bytecode_segments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants);
        assert!(res.is_ok());
    }
}
