use std::collections::HashMap;

use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{BytecodeSegment, BytecodeSegmentedNode};

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
    let bytecode_segment_structure: BytecodeSegmentedNode =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    let bytecode_segments = bytecode_segment_structure.segments.into_iter();
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

#[cfg(test)]
mod tests {
    use cairo_vm::any_box;

    use super::*;
    use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
        BytecodeLeaf, BytecodeSegmentStructureImpl,
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

        // execution scopes must have a BytecodeSegmentNode inserted. We insert one that has one
        // segment which lets us test both success and failure of ASSERT_END_OF_BYTECODE_SEGMENTS.
        let node = BytecodeSegmentedNode {
            segments: vec![BytecodeSegment {
                segment_length: Length(0),
                is_used: false,
                inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: Default::default() }),
            }],
        };
        exec_scopes.insert_box(vars::scopes::BYTECODE_SEGMENT_STRUCTURE, any_box!(node));

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
