use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
    insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;

use super::bls_utils::split;
use crate::cairo_types::builtins::HashBuiltin;
use crate::cairo_types::traits::CairoType;
use crate::cairo_types::trie::NodeEdge;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::hints::types::{skip_verification_if_configured, Preimage};
use crate::hints::vars;
use crate::io::input::StarknetOsInput;
use crate::starknet::starknet_storage::{execute_coroutine_threadsafe, CommitmentInfo, StorageLeaf};
use crate::starkware_utils::commitment_tree::update_tree::{decode_node, DecodeNodeCase, DecodedNode, UpdateTree};
use crate::utils::get_constant;

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
    constants: &HashMap<String, Felt252>,
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

    let merkle_height = get_constant(vars::constants::MERKLE_HEIGHT, constants)?;
    let tree_height: Felt252 = os_input.contract_state_commitment_info.tree_height.into();
    assert_tree_height_eq_merkle_height(tree_height, *merkle_height)?;

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
    constants: &HashMap<String, Felt252>,
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

    let merkle_height = get_constant(vars::constants::MERKLE_HEIGHT, constants)?;
    let tree_height: Felt252 = os_input.contract_class_commitment_info.tree_height.into();
    assert_tree_height_eq_merkle_height(tree_height, *merkle_height)?;

    Ok(())
}

pub const SET_PREIMAGE_FOR_CURRENT_COMMITMENT_INFO: &str = indoc! {r#"
	commitment_info = commitment_info_by_address[ids.contract_address]
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
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let commitment_info_by_address: &HashMap<Felt252, CommitmentInfo> =
        exec_scopes.get_ref(vars::scopes::COMMITMENT_INFO_BY_ADDRESS)?;
    let contract_address = get_integer_from_var_name(vars::ids::CONTRACT_ADDRESS, vm, ids_data, ap_tracking)?;
    let commitment_info = commitment_info_by_address.get(&contract_address).ok_or(HintError::CustomHint(
        format!("Could not find commitment info for contract {contract_address}").into_boxed_str(),
    ))?;

    insert_value_from_var_name(
        vars::ids::INITIAL_CONTRACT_STATE_ROOT,
        commitment_info.previous_root,
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        vars::ids::FINAL_CONTRACT_STATE_ROOT,
        commitment_info.updated_root,
        vm,
        ids_data,
        ap_tracking,
    )?;

    let preimage = commitment_info.commitment_facts.clone();

    let merkle_height = get_constant(vars::constants::MERKLE_HEIGHT, constants)?;
    let tree_height: Felt252 = commitment_info.tree_height.into();
    assert_tree_height_eq_merkle_height(tree_height, *merkle_height)?;

    // Insert preimage in scopes later than the Python VM to please the borrow checker
    exec_scopes.insert_value(vars::scopes::PREIMAGE, preimage);

    Ok(())
}

pub const LOAD_EDGE: &str = indoc! {r#"
	ids.edge = segments.add()
	ids.edge.length, ids.edge.path, ids.edge.bottom = preimage[ids.node]
	ids.hash_ptr.result = ids.node - ids.edge.length
	if __patricia_skip_validation_runner is not None:
	    # Skip validation of the preimage dict to speed up the VM. When this flag is set,
	    # mistakes in the preimage dict will be discovered only in the prover.
	    __patricia_skip_validation_runner.verified_addresses.add(
	        ids.hash_ptr + ids.HashBuiltin.result)"#
};

pub fn load_edge(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let new_segment_base = vm.add_memory_segment();
    insert_value_from_var_name(vars::ids::EDGE, new_segment_base, vm, ids_data, ap_tracking)?;

    let preimage: HashMap<Felt252, Vec<Felt252>> = exec_scopes.get(vars::scopes::PREIMAGE)?;
    let node = get_integer_from_var_name(vars::ids::NODE, vm, ids_data, ap_tracking)?;
    let node_values = preimage
        .get(&node)
        .ok_or(HintError::CustomHint("preimage does not contain expected edge".to_string().into_boxed_str()))?;

    if node_values.len() != 3 {
        return Err(HintError::CustomHint(
            "preimage value does not appear to be a NodeEdge".to_string().into_boxed_str(),
        ));
    }
    let edge = NodeEdge { length: node_values[0], path: node_values[1], bottom: node_values[2] };
    edge.to_memory(vm, new_segment_base)?;

    // TODO: prevent underflow (original hint doesn't appear to care)?
    // compute `ids.hash_ptr.result = ids.node - ids.edge.length`
    let res = node - edge.length;

    // ids.hash_ptr refers to SpongeHashBuiltin (see cairo-lang's sponge_as_hash.cairo)
    let hash_ptr = get_ptr_from_var_name(vars::ids::HASH_PTR, vm, ids_data, ap_tracking)?;
    let hash_result_ptr: Relocatable = (hash_ptr + HashBuiltin::result_offset())?;
    vm.insert_value(hash_result_ptr, res)?;

    skip_verification_if_configured(exec_scopes, hash_result_ptr)?;

    Ok(())
}

pub const LOAD_BOTTOM: &str = indoc! {r#"
	ids.hash_ptr.x, ids.hash_ptr.y = preimage[ids.edge.bottom]
	if __patricia_skip_validation_runner:
	    # Skip validation of the preimage dict to speed up the VM. When this flag is
	    # set, mistakes in the preimage dict will be discovered only in the prover.
	    __patricia_skip_validation_runner.verified_addresses.add(
	        ids.hash_ptr + ids.HashBuiltin.result)"#
};

pub fn load_bottom(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let edge = get_relocatable_from_var_name(vars::ids::EDGE, vm, ids_data, ap_tracking)?;
    let edge_bottom = vm.get_integer((edge + NodeEdge::bottom_offset())?)?;

    let preimage: Preimage = exec_scopes.get(vars::scopes::PREIMAGE)?;
    let preimage_vec = preimage
        .get(&edge_bottom)
        .ok_or(HintError::CustomHint("Edge bottom not found in preimage".to_string().into_boxed_str()))?;

    let x = preimage_vec[0];
    let y = preimage_vec[1];

    let hash_ptr = get_ptr_from_var_name(vars::ids::HASH_PTR, vm, ids_data, ap_tracking)?;
    vm.insert_value((hash_ptr + HashBuiltin::x_offset())?, x)?;
    vm.insert_value((hash_ptr + HashBuiltin::y_offset())?, y)?;

    let hash_result_address = (hash_ptr + HashBuiltin::result_offset())?;
    skip_verification_if_configured(exec_scopes, hash_result_address)?;

    Ok(())
}

pub const DECODE_NODE: &str = indoc! {r#"
	from starkware.python.merkle_tree import decode_node
	left_child, right_child, case = decode_node(node)
	memory[ap] = int(case != 'both')"#
};

pub const DECODE_NODE_2: &str = indoc! {r#"
	from starkware.python.merkle_tree import decode_node
	left_child, right_child, case = decode_node(node)
	memory[ap] = 1 if case != 'both' else 0"#
};

pub fn decode_node_hint(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let node: UpdateTree<StorageLeaf> = exec_scopes.get(vars::scopes::NODE)?;
    let node = node.ok_or(HintError::AssertionFailed("'node' should not be None".to_string().into_boxed_str()))?;
    let DecodedNode { left_child, right_child, case } = decode_node(&node)?;
    exec_scopes.insert_value(vars::scopes::LEFT_CHILD, left_child.clone());
    exec_scopes.insert_value(vars::scopes::RIGHT_CHILD, right_child.clone());
    exec_scopes.insert_value(vars::scopes::CASE, case.clone());

    // memory[ap] = 1 if case != 'both' else 0"#
    let ap = match case {
        DecodeNodeCase::Both => Felt252::ZERO,
        _ => Felt252::ONE,
    };
    insert_value_into_ap(vm, ap)?;

    Ok(())
}

pub const ENTER_SCOPE_COMMITMENT_INFO_BY_ADDRESS: &str = indoc! {r#"
	# This hint shouldn't be whitelisted.
	vm_enter_scope(dict(
	    commitment_info_by_address=execution_helper.compute_storage_commitments(),
	    os_input=os_input,
	))"#
};

pub fn enter_scope_commitment_info_by_address(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_helper: ExecutionHelperWrapper = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;
    let os_input: StarknetOsInput = exec_scopes.get(vars::scopes::OS_INPUT)?;

    let commitment_info_by_address = execute_coroutine_threadsafe(execution_helper.compute_storage_commitments())?;

    let new_scope = HashMap::from([
        (vars::scopes::COMMITMENT_INFO_BY_ADDRESS.to_string(), any_box!(commitment_info_by_address)),
        (vars::scopes::OS_INPUT.to_string(), any_box!(os_input)),
    ]);
    exec_scopes.enter_scope(new_scope);

    Ok(())
}

pub const WRITE_SPLIT_RESULT: &str = indoc! {r#"
    from starkware.starknet.core.os.data_availability.bls_utils import split

    segments.write_arg(ids.res.address_, split(ids.value))"#
};
pub fn write_split_result(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // this hint fills in a Cairo BigInt3 by taking a felt (ids.value) and passing it to a split fn
    let value = get_integer_from_var_name(vars::ids::VALUE, vm, ids_data, ap_tracking)?;
    let res_ptr = get_relocatable_from_var_name(vars::ids::RES, vm, ids_data, ap_tracking)?;

    let splits = split(value)?.into_iter().map(MaybeRelocatable::Int).collect::<Vec<MaybeRelocatable>>();
    vm.write_arg(res_ptr, &splits)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use blockifier::block_context::BlockContext;
    use num_bigint::BigUint;
    use rstest::{fixture, rstest};

    use super::*;
    use crate::config::STORED_BLOCK_HASH_BUFFER;
    use crate::crypto::pedersen::PedersenHash;
    use crate::execution::helper::ContractStorageMap;
    use crate::hints::types::PatriciaSkipValidationRunner;
    use crate::starknet::starknet_storage::{OsSingleStarknetStorage, StorageLeaf};
    use crate::starkware_utils::commitment_tree::base_types::Height;
    use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
    use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::FactFetchingContext;

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

    #[fixture]
    pub fn block_context() -> BlockContext {
        BlockContext::create_for_testing()
    }

    #[fixture]
    fn old_block_number_and_hash(block_context: BlockContext) -> (Felt252, Felt252) {
        (Felt252::from(block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64))
    }

    #[fixture]
    fn execution_helper(
        block_context: BlockContext,
        old_block_number_and_hash: (Felt252, Felt252),
    ) -> ExecutionHelperWrapper {
        ExecutionHelperWrapper::new(ContractStorageMap::default(), vec![], &block_context, old_block_number_and_hash)
    }

    #[fixture]
    fn contract_address() -> Felt252 {
        Felt252::from(1000)
    }

    #[fixture]
    fn execution_helper_with_storage(
        execution_helper: ExecutionHelperWrapper,
        contract_address: Felt252,
    ) -> ExecutionHelperWrapper {
        let storage = DictStorage::default();
        let mut ffc = FactFetchingContext::<_, PedersenHash>::new(storage);

        // Run async functions in a dedicated runtime to keep the test functions sync.
        // Otherwise, we run into "cannot spawn a runtime from another runtime" issues.
        let os_single_starknet_storage = execute_coroutine_threadsafe(async {
            let mut tree = PatriciaTree::empty_tree(&mut ffc, Height(251), StorageLeaf::empty()).await.unwrap();
            let modifications = vec![(BigUint::from(400u64), StorageLeaf::new(Felt252::from(160000)))];
            let mut facts = None;
            let tree = tree.update(&mut ffc, modifications, &mut facts).await.unwrap();
            // We pass the same tree as previous and updated tree as this is enough for the tests.
            OsSingleStarknetStorage::new(tree.clone(), tree, &vec![], ffc).await.unwrap()
        });

        {
            let storage_by_address = &mut execution_helper.execution_helper.as_ref().borrow_mut().storage_by_address;
            storage_by_address.insert(contract_address, os_single_starknet_storage);
        }

        execution_helper
    }

    #[rstest]
    fn test_set_preimage_for_state_commitments(os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::from([(vars::constants::MERKLE_HEIGHT.to_string(), Felt252::from(251))]);

        let ids_data = HashMap::from([
            (vars::ids::INITIAL_ROOT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::FINAL_ROOT.to_string(), HintReference::new_simple(-1)),
        ]);

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::OS_INPUT, os_input);

        set_preimage_for_state_commitments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        assert_eq!(
            get_integer_from_var_name(vars::ids::INITIAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap(),
            1_usize.into()
        );
        assert_eq!(
            get_integer_from_var_name(vars::ids::FINAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap(),
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
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::from([(vars::constants::MERKLE_HEIGHT.to_string(), Felt252::from(251))]);

        let ids_data = HashMap::from([
            (vars::ids::INITIAL_ROOT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::FINAL_ROOT.to_string(), HintReference::new_simple(-1)),
        ]);

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::OS_INPUT, os_input);

        set_preimage_for_class_commitments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        assert_eq!(
            get_integer_from_var_name(vars::ids::INITIAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap(),
            11_usize.into()
        );
        assert_eq!(
            get_integer_from_var_name(vars::ids::FINAL_ROOT, &vm, &ids_data, &ap_tracking).unwrap(),
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
        let constants = HashMap::from([(vars::constants::MERKLE_HEIGHT.to_string(), Felt252::from(251))]);

        let ids_data = HashMap::from([
            (vars::ids::INITIAL_CONTRACT_STATE_ROOT.to_string(), HintReference::new_simple(-3)),
            (vars::ids::FINAL_CONTRACT_STATE_ROOT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::CONTRACT_ADDRESS.to_string(), HintReference::new_simple(-1)),
        ]);
        let contract_address = Felt252::ONE;
        insert_value_from_var_name(vars::ids::CONTRACT_ADDRESS, contract_address, &mut vm, &ids_data, &ap_tracking)
            .unwrap();

        let commitment_info_by_address = HashMap::from([(contract_address, os_input.contract_state_commitment_info)]);

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::COMMITMENT_INFO_BY_ADDRESS, commitment_info_by_address);

        set_preimage_for_current_commitment_info(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .unwrap();

        assert_eq!(
            get_integer_from_var_name(vars::ids::INITIAL_CONTRACT_STATE_ROOT, &vm, &ids_data, &ap_tracking).unwrap(),
            1_usize.into()
        );
        assert_eq!(
            get_integer_from_var_name(vars::ids::FINAL_CONTRACT_STATE_ROOT, &vm, &ids_data, &ap_tracking).unwrap(),
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

        let hash_ptr = Relocatable::from((2, 0));
        insert_value_from_var_name(vars::ids::HASH_PTR, hash_ptr, &mut vm, &ids_data, &ap_tracking).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();
        // TODO: insert meaningful values into preimage
        let mut preimage: HashMap<Felt252, Vec<Felt252>> = Default::default();
        preimage.insert(1_usize.into(), vec![2_usize.into(), 3_usize.into(), 4_usize.into()]);
        exec_scopes.insert_value(vars::scopes::PREIMAGE, preimage);
        exec_scopes
            .insert_value::<Option<PatriciaSkipValidationRunner>>(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER, None);

        load_edge(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        // TODO: test post-conditions:
        // * edge (edge.length, edge.path, edge.bottom)
        // * hash_ptr.result
    }

    #[test]
    pub fn test_write_split_result() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::VALUE.to_string(), HintReference::new_simple(-2)),
            (vars::ids::RES.to_string(), HintReference::new_simple(-1)),
        ]);
        let mut exec_scopes: ExecutionScopes = Default::default();

        insert_value_from_var_name(vars::ids::VALUE, Felt252::ONE, &mut vm, &ids_data, &ap_tracking).unwrap();

        write_split_result(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();
        let res_ptr = get_relocatable_from_var_name(vars::ids::RES, &vm, &ids_data, &ap_tracking).unwrap();
        let splits = vm.get_range(res_ptr, 3);
        assert_eq!(
            splits,
            vec![
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::ONE))),
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::ZERO))),
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::ZERO))),
            ]
        );
    }
}
