use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{insert_value_from_var_name, insert_value_into_ap};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;
use starknet_os_types::hash::Hash;

use crate::hints::vars;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
    BytecodeSegment, BytecodeSegmentStructureImpl, BytecodeSegmentedNode,
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
    log::debug!("iter_current_segment_info()");

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

pub const SET_AP_TO_SEGMENT_HASH: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(bytecode_segment_structure.hash())"#
};

pub fn set_ap_to_segment_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentStructureImpl =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    // Calc hash
    let hash =
        bytecode_segment_structure.hash().map_err(|err| HintError::CustomHint(err.to_string().into_boxed_str()))?;

    // Insert to ap
    insert_value_into_ap(vm, Felt252::from(Hash::from_bytes_be(hash.to_bytes_be())))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use cairo_vm::any_box;
    use num_bigint::BigUint;
    use pathfinder_crypto::hash::poseidon_hash_many;
    use pathfinder_crypto::Felt;

    use super::*;
    use crate::crypto::poseidon::poseidon_hash_many_bytes;
    use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
        BytecodeLeaf, BytecodeSegmentStructureImpl, BytecodeSegmentedNode,
    };
    use crate::starkware_utils::commitment_tree::base_types::Length;
    use crate::starkware_utils::commitment_tree::binary_fact_tree::Leaf;

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

    #[test]
    fn test_set_ap_to_segment_hash() {
        use num_bigint::BigUint;

        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::new();

        let mut exec_scopes: ExecutionScopes = Default::default();

        // Execution scopes must have a BytecodeSegmentStructureImpl inserted. We insert one that has one
        let segments = vec![BytecodeSegment {
            segment_length: Length(1),
            is_used: false,
            inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: vec![BigUint::from(1u8)] }),
        }];
        let segment_structure = BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode { segments });
        exec_scopes.insert_box(vars::scopes::BYTECODE_SEGMENT_STRUCTURE, any_box!(segment_structure));

        set_ap_to_segment_hash(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        // Read hash and compare with expected hash
        let hash = vm.get_integer(vm.get_ap()).unwrap().into_owned();
        assert_eq!(hex::encode(hash.to_bytes_be()), "064b3967128647f5db91e107897e7e6d72f2a06f35d01d19055a7f85c85e65ba");
    }

    #[test]
    fn test_hash_bytecode_leaf() {
        // Reference hashes were taken from cairo-lang (compiled_class_hash_test.py)
        use num_bigint::BigUint;
        let leaf = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: vec![BigUint::from(0x01u8)] });
        assert_eq!(
            hex::encode(leaf.hash().unwrap().to_bytes_be()),
            "00579e8877c7755365d5ec1ec7d3a94a457eff5d1f40482bbe9729c064cdead2"
        );

        let leaf = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
            data: vec![BigUint::from(0x01u8), BigUint::from(0x02u8), BigUint::from(0x03u8)],
        });
        assert_eq!(
            hex::encode(leaf.hash().unwrap().to_bytes_be()),
            "02f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad082"
        );

        let leaf = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
            data: vec![
                BigUint::from(1u8),
                BigUint::from(2u8),
                BigUint::from(3u8),
                BigUint::from(100u8),
                BigUint::from(500u16),
                BigUint::from(1000u16),
                BigUint::from(123456789u64),
            ],
        });
        assert_eq!(
            hex::encode(leaf.hash().unwrap().to_bytes_be()),
            "0061992871ada0f904463047841a564ad8ed8f4fae20e9e68a0debee876cfdb3"
        );
    }

    #[test]
    fn test_hash_bytecode_node() {
        // Reference hashes were taken from cairo-lang (compiled_class_hash_test.py)
        let inner_struct = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: vec![BigUint::from(0x01u8)] });
        let seg = vec![BytecodeSegment { segment_length: Length(1), is_used: false, inner_structure: inner_struct }];
        let node = BytecodeSegmentedNode { segments: seg };
        assert_eq!(
            hex::encode(node.hash().unwrap().to_bytes_be()),
            "064b3967128647f5db91e107897e7e6d72f2a06f35d01d19055a7f85c85e65ba"
        );

        let inner_struct = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
            data: vec![BigUint::from(0x01u8), BigUint::from(0x02u8)],
        });
        let seg = vec![BytecodeSegment { segment_length: Length(2), is_used: false, inner_structure: inner_struct }];
        let node = BytecodeSegmentedNode { segments: seg };
        assert_eq!(
            hex::encode(node.hash().unwrap().to_bytes_be()),
            "073542be7740dc970b59f6e05e7a065586a493b59932a3a88adc902a626da18d"
        );

        let node = BytecodeSegmentedNode {
            segments: vec![
                // 1st segment
                BytecodeSegment {
                    segment_length: Length(3),
                    is_used: false,
                    inner_structure: {
                        BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                            data: vec![BigUint::from(1u8), BigUint::from(2u8), BigUint::from(3u8)],
                        })
                    },
                },
                // 2nd segment
                BytecodeSegment {
                    segment_length: Length(3),
                    is_used: true,
                    inner_structure: {
                        BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode {
                            segments: vec![
                                BytecodeSegment {
                                    segment_length: Length(1),
                                    is_used: true,
                                    inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                                        data: vec![BigUint::from(4u8)],
                                    }),
                                },
                                BytecodeSegment {
                                    segment_length: Length(1),
                                    is_used: false,
                                    inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                                        data: vec![BigUint::from(5u8)],
                                    }),
                                },
                                BytecodeSegment {
                                    segment_length: Length(1),
                                    is_used: true,
                                    inner_structure: BytecodeSegmentStructureImpl::SegmentedNode(
                                        BytecodeSegmentedNode {
                                            segments: vec![BytecodeSegment {
                                                segment_length: Length(1),
                                                is_used: true,
                                                inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                                                    data: vec![BigUint::from(6u8)],
                                                }),
                                            }],
                                        },
                                    ),
                                },
                            ],
                        })
                    },
                },
                // 3rd segment
                BytecodeSegment {
                    segment_length: Length(4),
                    is_used: false,
                    inner_structure: {
                        BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                            data: vec![BigUint::from(7u8), BigUint::from(8u8), BigUint::from(9u8), BigUint::from(10u8)],
                        })
                    },
                },
            ],
        };

        assert_eq!(
            hex::encode(node.hash().unwrap().to_bytes_be()),
            "06dc9a5436f10ef82ff99457f4af9dd5a5794713c1ed272b4e82e9a8d9ccb32e"
        );
    }
}
