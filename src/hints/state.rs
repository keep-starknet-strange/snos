use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::io::input::{CommitmentInfo, StarknetOsInput};

fn assert_tree_height_eq_merkle_height(tree_height: Felt252, merkle_height: Felt252) -> Result<(), HintError> {
    if tree_height != merkle_height {
        return Err(HintError::AssertionFailed(
            "Tree height does not match Merkle height".to_string().into_boxed_str(),
        ));
    }

    Ok(())
}

pub const SET_PREIMAGE_FOR_STATE_COMMITMENTS: &str = indoc! {r#"
	ids.initial_root = os_input.contract_state_commitment_info.previous_root
	ids.final_root = os_input.contract_state_commitment_info.updated_root
	preimage = {
	    int(root): children
	    for root, children in os_input.contract_state_commitment_info.commitment_facts.items()
	}
	assert os_input.contract_state_commitment_info.tree_height == ids.MERKLE_HEIGHT"#
};

pub fn set_preimage_for_state_commitments(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;
    insert_value_from_var_name(
        vars::ids::INITIAL_ROOT,
        os_input.contract_state_commitment_info.previous_root,
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        vars::ids::FINAL_ROOT,
        os_input.contract_state_commitment_info.updated_root,
        vm,
        ids_data,
        ap_tracking,
    )?;

    let preimage = os_input.contract_state_commitment_info.commitment_facts;
    exec_scopes.insert_value(vars::scopes::PREIMAGE, preimage);

    let merkle_height = get_integer_from_var_name(vars::ids::MERKLE_HEIGHT, vm, ids_data, ap_tracking)?.into_owned();
    let tree_height: Felt252 = os_input.contract_state_commitment_info.tree_height.into();
    assert_tree_height_eq_merkle_height(tree_height, merkle_height)?;

    Ok(())
}

pub const SET_PREIMAGE_FOR_CLASS_COMMITMENTS: &str = indoc! {r#"
	ids.initial_root = os_input.contract_class_commitment_info.previous_root
	ids.final_root = os_input.contract_class_commitment_info.updated_root
	preimage = {
	    int(root): children
	    for root, children in os_input.contract_class_commitment_info.commitment_facts.items()
	}
	assert os_input.contract_class_commitment_info.tree_height == ids.MERKLE_HEIGHT"#
};

pub fn set_preimage_for_class_commitments(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;
    insert_value_from_var_name(
        vars::ids::INITIAL_ROOT,
        os_input.contract_class_commitment_info.previous_root,
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        vars::ids::FINAL_ROOT,
        os_input.contract_class_commitment_info.updated_root,
        vm,
        ids_data,
        ap_tracking,
    )?;

    let preimage = os_input.contract_class_commitment_info.commitment_facts;
    exec_scopes.insert_value(vars::scopes::PREIMAGE, preimage);

    let merkle_height = get_integer_from_var_name(vars::ids::MERKLE_HEIGHT, vm, ids_data, ap_tracking)?.into_owned();
    let tree_height: Felt252 = os_input.contract_class_commitment_info.tree_height.into();
    assert_tree_height_eq_merkle_height(tree_height, merkle_height)?;

    Ok(())
}

pub const SET_PREIMAGE_FOR_CURRENT_COMMITMENT_INFO: &str = indoc! {r#"
	commitment_info = commitment_info_by_address[ids.state_changes.key]
	ids.initial_contract_state_root = commitment_info.previous_root
	ids.final_contract_state_root = commitment_info.updated_root
	preimage = {
	    int(root): children
	    for root, children in commitment_info.commitment_facts.items()
	}
	assert commitment_info.tree_height == ids.MERKLE_HEIGHT"#
};

pub fn set_preimage_for_current_commitment_info(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let commitment_info = exec_scopes.get::<CommitmentInfo>(vars::scopes::COMMITMENT_INFO)?;
    insert_value_from_var_name(vars::ids::INITIAL_ROOT, commitment_info.previous_root, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(vars::ids::FINAL_ROOT, commitment_info.updated_root, vm, ids_data, ap_tracking)?;

    let preimage = commitment_info.commitment_facts;
    exec_scopes.insert_value(vars::scopes::PREIMAGE, preimage);

    let merkle_height = get_integer_from_var_name(vars::ids::MERKLE_HEIGHT, vm, ids_data, ap_tracking)?.into_owned();
    let tree_height: Felt252 = commitment_info.tree_height.into();
    assert_tree_height_eq_merkle_height(tree_height, merkle_height)?;

    Ok(())
}

pub const PREPARE_PREIMAGE_VALIDATION: &str = indoc! {r#"
	ids.edge = segments.add()
	ids.edge.length, ids.edge.path, ids.edge.bottom = preimage[ids.node]
	ids.hash_ptr.result = ids.node - ids.edge.length
	if __patricia_skip_validation_runner is not None:
	    # Skip validation of the preimage dict to speed up the VM. When this flag is set,
	    # mistakes in the preimage dict will be discovered only in the prover.
	    __patricia_skip_validation_runner.verified_addresses.add(
	        ids.hash_ptr + ids.HashBuiltin.result)"#
};

pub fn prepare_preimage_validation(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let new_segment_base = vm.add_memory_segment();
    insert_value_from_var_name(vars::ids::EDGE, new_segment_base, vm, ids_data, ap_tracking)?;

    let preimage: HashMap<Felt252, Vec<Felt252>> = exec_scopes.get(vars::scopes::PREIMAGE)?;
    let node = get_integer_from_var_name(vars::ids::NODE, vm, ids_data, ap_tracking)?.into_owned();
    let node_values = preimage
        .get(&node)
        .ok_or(HintError::CustomHint("preimage does not contain expected edge".to_string().into_boxed_str()))?;

    if node_values.len() != 3 {
        return Err(HintError::CustomHint(
            "preimage value does not appear to be a NodeEdge".to_string().into_boxed_str(),
        ));
    }

    let length_addr = new_segment_base;
    let path_addr: Relocatable = (new_segment_base + 1)?;
    let bottom_addr: Relocatable = (new_segment_base + 2)?;

    vm.insert_value(length_addr, node_values[0])?;
    vm.insert_value(path_addr, node_values[1])?;
    vm.insert_value(bottom_addr, node_values[2])?;

    // TODO: prevent underflow (original hint doesn't appear to care)?
    // compute `ids.hash_ptr.result = ids.node - ids.edge.length`
    let res = node - node_values[0];

    // ids.hash_ptr refers to SpongeHashBuiltin (see cairo-lang's sponge_as_hash.cairo)
    // it is a struct with 6 felts and `result` is the 4th
    let hash_ptr = get_relocatable_from_var_name(vars::ids::HASH_PTR, vm, ids_data, ap_tracking)?;
    let hash_ptr_result: Relocatable = (hash_ptr + 3)?;
    vm.insert_value(hash_ptr_result, res)?;

    // TODO: __patricia_skip_validation_runner

    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;
    use crate::io::input::CommitmentInfo;

    #[fixture]
    fn os_input() -> StarknetOsInput {
        StarknetOsInput {
            contract_state_commitment_info: CommitmentInfo {
                previous_root: 1_usize.into(),
                updated_root: 2_usize.into(),
                tree_height: 251_usize.into(),
                commitment_facts: Default::default(),
            },
            contract_class_commitment_info: CommitmentInfo {
                previous_root: 11_usize.into(),
                updated_root: 12_usize.into(),
                tree_height: 251_usize.into(),
                commitment_facts: Default::default(),
            },
            deprecated_compiled_classes: Default::default(),
            compiled_classes: Default::default(),
            contracts: Default::default(),
            class_hash_to_compiled_class_hash: Default::default(),
            general_config: Default::default(),
            transactions: Default::default(),
            block_hash: Default::default(),
            compiled_class_visited_pcs: Default::default(),
        }
    }

    #[rstest]
    fn test_set_preimage_for_state_commitments(os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::INITIAL_ROOT.to_string(), HintReference::new_simple(-3)),
            (vars::ids::FINAL_ROOT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::MERKLE_HEIGHT.to_string(), HintReference::new_simple(-1)),
        ]);
        insert_value_from_var_name(vars::ids::MERKLE_HEIGHT, 251_usize, &mut vm, &ids_data, &ap_tracking)
            .expect("Couldn't insert 252 into ids.MERKLE_HEIGHT");

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::OS_INPUT, os_input);

        set_preimage_for_state_commitments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        assert_eq!(
            get_integer_from_var_name(vars::ids::INITIAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap().into_owned(),
            1_usize.into()
        );
        assert_eq!(
            get_integer_from_var_name(vars::ids::FINAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap().into_owned(),
            2_usize.into()
        );
        // TODO: test preimage more thoroughly
        assert!(exec_scopes.get::<HashMap<Felt252, Vec<Felt252>>>(vars::scopes::PREIMAGE).is_ok());
    }

    #[rstest]
    fn test_set_preimage_for_class_commitments(os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::INITIAL_ROOT.to_string(), HintReference::new_simple(-3)),
            (vars::ids::FINAL_ROOT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::MERKLE_HEIGHT.to_string(), HintReference::new_simple(-1)),
        ]);
        insert_value_from_var_name(vars::ids::MERKLE_HEIGHT, 251_usize, &mut vm, &ids_data, &ap_tracking)
            .expect("Couldn't insert 252 into ids.MERKLE_HEIGHT");

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::OS_INPUT, os_input);

        set_preimage_for_class_commitments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        assert_eq!(
            get_integer_from_var_name(vars::ids::INITIAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap().into_owned(),
            11_usize.into()
        );
        assert_eq!(
            get_integer_from_var_name(vars::ids::FINAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap().into_owned(),
            12_usize.into()
        );
        // TODO: test preimage more thoroughly
        assert!(exec_scopes.get::<HashMap<Felt252, Vec<Felt252>>>(vars::scopes::PREIMAGE).is_ok());
    }

    #[rstest]
    fn test_set_preimage_for_current_commitment_info(os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::INITIAL_ROOT.to_string(), HintReference::new_simple(-3)),
            (vars::ids::FINAL_ROOT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::MERKLE_HEIGHT.to_string(), HintReference::new_simple(-1)),
        ]);
        insert_value_from_var_name(vars::ids::MERKLE_HEIGHT, 251_usize, &mut vm, &ids_data, &ap_tracking)
            .expect("Couldn't insert 252 into ids.MERKLE_HEIGHT");

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::COMMITMENT_INFO, os_input.contract_state_commitment_info);

        set_preimage_for_current_commitment_info(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .unwrap();

        assert_eq!(
            get_integer_from_var_name(vars::ids::INITIAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap().into_owned(),
            1_usize.into()
        );
        assert_eq!(
            get_integer_from_var_name(vars::ids::FINAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap().into_owned(),
            2_usize.into()
        );
        // TODO: test preimage more thoroughly
        assert!(exec_scopes.get::<HashMap<Felt252, Vec<Felt252>>>(vars::scopes::PREIMAGE).is_ok());
    }

    #[rstest]
    fn test_prepare_preimage_validation(_os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::EDGE.to_string(), HintReference::new_simple(-3)),
            (vars::ids::NODE.to_string(), HintReference::new_simple(-2)),
            (vars::ids::HASH_PTR.to_string(), HintReference::new_simple(-1)),
        ]);
        insert_value_from_var_name(vars::ids::NODE, 1_usize, &mut vm, &ids_data, &ap_tracking)
            .expect("Couldn't insert into ids.NODE");

        let mut exec_scopes: ExecutionScopes = Default::default();
        // TODO: insert meaningful values into preimage
        let mut preimage: HashMap<Felt252, Vec<Felt252>> = Default::default();
        preimage.insert(1_usize.into(), vec![2_usize.into(), 3_usize.into(), 4_usize.into()]);
        exec_scopes.insert_value(vars::scopes::PREIMAGE, preimage);

        prepare_preimage_validation(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        // TODO: test post-conditions:
        // * edge (edge.length, edge.path, edge.bottom)
        // * hash_ptr.result
    }
}
