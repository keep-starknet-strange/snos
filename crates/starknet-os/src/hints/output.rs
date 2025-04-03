use std::cmp::min;
use std::collections::HashMap;

use cairo_vm::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use indoc::indoc;
use num_integer::div_ceil;

use crate::hints::vars;
use crate::utils::{get_constant, get_variable_from_root_exec_scope};

const MAX_PAGE_SIZE: usize = 3800;

#[rustfmt::skip]
pub const SET_TREE_STRUCTURE: &str = indoc! {r#"from starkware.python.math_utils import div_ceil

if __serialize_data_availability_create_pages__:
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
    ])"#};

pub fn set_tree_structure(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let serialize_data_availability_create_pages: bool =
        get_variable_from_root_exec_scope(exec_scopes, vars::scopes::SERIALIZE_DATA_AVAILABILITY_CREATE_PAGES)?;

    if !serialize_data_availability_create_pages {
        return Ok(());
    }

    let onchain_data_start = get_ptr_from_var_name(vars::ids::DA_START, vm, ids_data, ap_tracking)?;
    let output_ptr = get_ptr_from_var_name(vars::ids::OUTPUT_PTR, vm, ids_data, ap_tracking)?;
    let onchain_data_size = (output_ptr - onchain_data_start)?;

    let output_builtin = vm.get_output_builtin_mut()?;

    let n_pages = div_ceil(onchain_data_size, MAX_PAGE_SIZE);
    for i in 0..n_pages {
        let start_offset = i * MAX_PAGE_SIZE;
        let page_id = i + 1;
        let page_start = (onchain_data_start + start_offset)?;
        let page_size = min(onchain_data_size - start_offset, MAX_PAGE_SIZE);
        output_builtin
            .add_page(page_id, page_start, page_size)
            .map_err(|e| HintError::CustomHint(e.to_string().into_boxed_str()))?;
    }

    // Set the tree structure to a root with two children:
    // * A leaf which represents the main part
    // * An inner node for the onchain data part (which contains n_pages children).
    //
    // This is encoded using the following sequence:
    output_builtin.add_attribute("gps_fact_topology".to_string(), vec![
        // Push 1 + n_pages pages (all of the pages).
        1 + n_pages,
        // Create a parent node for the last n_pages.
        n_pages,
        // Don't push additional pages.
        0,
        // Take the first page (the main part) and the node that was created (onchain data)
        // and use them to construct the root of the fact tree.
        2,
    ]);

    Ok(())
}

pub const SET_STATE_UPDATES_START: &str = indoc! {r#"# `use_kzg_da` is used in a hint in `process_data_availability`.
    use_kzg_da = ids.use_kzg_da
    if use_kzg_da or ids.compress_state_updates:
        ids.state_updates_start = segments.add()
    else:
        # Assign a temporary segment, to be relocated into the output segment.
        ids.state_updates_start = segments.add_temp_segment()"#};

pub fn set_state_updates_start(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let use_kzg_da_felt = get_integer_from_var_name(vars::ids::USE_KZG_DA, vm, ids_data, ap_tracking)?;

    // Set `use_kzg_da` in globals since it will be used in `process_data_availability`
    exec_scopes.insert_value(vars::scopes::USE_KZG_DA, use_kzg_da_felt);

    // Recompute `compress_state_updates` until this issue is fixed
    // https://github.com/lambdaclass/cairo-vm/issues/1897
    let full_output = get_integer_from_var_name(vars::ids::FULL_OUTPUT, vm, ids_data, ap_tracking)?;
    let compress_state_updates = Felt252::ONE - full_output;

    let use_kzg_da = match use_kzg_da_felt {
        x if x == Felt252::ONE => Ok(true),
        x if x == Felt252::ZERO => Ok(false),
        _ => Err(HintError::CustomHint("ids.use_kzg_da is not a boolean".to_string().into_boxed_str())),
    }?;

    let use_compress_state_updates = match compress_state_updates {
        x if x == Felt252::ONE => Ok(true),
        x if x == Felt252::ZERO => Ok(false),
        _ => Err(HintError::CustomHint("ids.compress_state_updates is not a boolean".to_string().into_boxed_str())),
    }?;

    if use_kzg_da || use_compress_state_updates {
        insert_value_from_var_name(vars::ids::STATE_UPDATES_START, vm.add_memory_segment(), vm, ids_data, ap_tracking)?;
    } else {
        // Assign a temporary segment, to be relocated into the output segment.
        insert_value_from_var_name(
            vars::ids::STATE_UPDATES_START,
            vm.add_temporary_segment(),
            vm,
            ids_data,
            ap_tracking,
        )?;
    }

    Ok(())
}

pub const SET_COMPRESSED_START: &str = indoc! {r#"if use_kzg_da:
    ids.compressed_start = segments.add()
else:
    # Assign a temporary segment, to be relocated into the output segment.
    ids.compressed_start = segments.add_temp_segment()"#};

pub fn set_compressed_start(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let use_kzg_da_felt = exec_scopes.get::<Felt252>(vars::scopes::USE_KZG_DA)?;

    let use_kzg_da = match use_kzg_da_felt {
        x if x == Felt252::ONE => Ok(true),
        x if x == Felt252::ZERO => Ok(false),
        _ => Err(HintError::CustomHint("ids.use_kzg_da is not a boolean".to_string().into_boxed_str())),
    }?;

    if use_kzg_da {
        insert_value_from_var_name(vars::ids::COMPRESSED_START, vm.add_memory_segment(), vm, ids_data, ap_tracking)?;
    } else {
        // Assign a temporary segment, to be relocated into the output segment.
        insert_value_from_var_name(vars::ids::COMPRESSED_START, vm.add_temporary_segment(), vm, ids_data, ap_tracking)?;
    }

    Ok(())
}

pub const SET_N_UPDATES_SMALL: &str =
    indoc! {r#"ids.is_n_updates_small = ids.n_actual_updates < ids.N_UPDATES_SMALL_PACKING_BOUND"#};

pub fn set_n_updates_small(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n_actual_updates = get_integer_from_var_name(vars::ids::N_ACTUAL_UPDATES, vm, ids_data, ap_tracking)?;
    let n_updates_small_packing_bound = get_constant(vars::ids::N_UPDATES_SMALL_PACKING_BOUND, constants)?;

    let is_n_updates_small =
        if n_actual_updates < *n_updates_small_packing_bound { Felt252::ONE } else { Felt252::ZERO };

    insert_value_from_var_name(vars::ids::IS_N_UPDATES_SMALL, is_n_updates_small, vm, ids_data, ap_tracking)
}

#[cfg(test)]
mod tests {
    use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
    use cairo_vm::types::relocatable::Relocatable;
    use cairo_vm::vm::runners::builtin_runner::{BuiltinRunner, OutputBuiltinRunner};
    use cairo_vm::vm::runners::cairo_pie::PublicMemoryPage;

    use super::*;

    #[test]
    fn test_set_tree_structure() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let mut output_builtin_runner = OutputBuiltinRunner::new(true);
        output_builtin_runner.initialize_segments(&mut vm.segments);
        let output_base = output_builtin_runner.base() as isize;
        vm.builtin_runners.push(BuiltinRunner::Output(output_builtin_runner));

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::DA_START.to_string(), HintReference::new_simple(-2)),
            (vars::ids::OUTPUT_PTR.to_string(), HintReference::new_simple(-1)),
        ]);
        insert_value_from_var_name(
            vars::ids::DA_START,
            Relocatable::from((output_base, 0)),
            &mut vm,
            &ids_data,
            &ap_tracking,
        )
        .unwrap();
        insert_value_from_var_name(
            vars::ids::OUTPUT_PTR,
            Relocatable::from((output_base, 10000)),
            &mut vm,
            &ids_data,
            &ap_tracking,
        )
        .unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::SERIALIZE_DATA_AVAILABILITY_CREATE_PAGES, true);

        set_tree_structure(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should succeed");

        let n_expected_pages: usize = 3;

        let output_builtin = vm.get_output_builtin_mut().unwrap();
        let builtin_state = output_builtin.get_state();

        let pages = builtin_state.pages;
        assert_eq!(pages.len(), n_expected_pages);
        assert_eq!(
            pages,
            HashMap::from([
                (1usize, PublicMemoryPage { start: 0, size: MAX_PAGE_SIZE }),
                (2usize, PublicMemoryPage { start: MAX_PAGE_SIZE, size: MAX_PAGE_SIZE }),
                (3usize, PublicMemoryPage { start: 2 * MAX_PAGE_SIZE, size: 2400 })
            ])
        );

        let attributes = builtin_state.attributes;
        let gps_fact_topology = attributes.get("gps_fact_topology").unwrap();
        assert_eq!(gps_fact_topology, &vec![1 + n_expected_pages, n_expected_pages, 0, 2]);
    }

    use rstest::rstest;

    #[rstest]
    // small updates
    #[case(10, 1)]
    #[case(255, 1)]
    // big updates
    #[case(256, 0)]
    #[case(1024, 0)]

    fn test_set_n_updates_small_parameterized(#[case] actual_updates: u64, #[case] expected_is_n_updates_small: u64) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);
        let ap_tracking = ApTracking::new();
        let constants =
            HashMap::from([(vars::ids::N_UPDATES_SMALL_PACKING_BOUND.to_string(), Felt252::from(1u128 << 8))]);
        let ids_data = HashMap::from([
            (vars::ids::N_ACTUAL_UPDATES.to_string(), HintReference::new_simple(-2)),
            (vars::ids::IS_N_UPDATES_SMALL.to_string(), HintReference::new_simple(-1)),
        ]);
        vm.insert_value(Relocatable::from((1, 0)), Felt252::from(actual_updates)).unwrap();
        let mut exec_scopes: ExecutionScopes = Default::default();

        set_n_updates_small(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();
        let is_n_updates_small =
            get_integer_from_var_name(vars::ids::IS_N_UPDATES_SMALL, &vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(Felt252::from(expected_is_n_updates_small), is_n_updates_small);
    }

    #[rstest]
    #[case(0, 0)]
    #[case(0, 1)]
    #[case(1, 0)]
    #[case(0, 1)]
    fn test_set_state_updates_start(#[case] use_kzg_da: u64, #[case] full_output: u64) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);
        let ap_tracking = ApTracking::new();
        let constants =
            HashMap::from([(vars::ids::N_UPDATES_SMALL_PACKING_BOUND.to_string(), Felt252::from(1u128 << 8))]);

        let ids_data = HashMap::from([
            (vars::ids::USE_KZG_DA.to_string(), HintReference::new_simple(-3)),
            (vars::ids::FULL_OUTPUT.to_string(), HintReference::new_simple(-2)),
            (vars::ids::STATE_UPDATES_START.to_string(), HintReference::new_simple(-1)),
        ]);

        insert_value_from_var_name(vars::ids::USE_KZG_DA, Felt252::from(use_kzg_da), &mut vm, &ids_data, &ap_tracking)
            .unwrap();

        insert_value_from_var_name(
            vars::ids::FULL_OUTPUT,
            Felt252::from(full_output),
            &mut vm,
            &ids_data,
            &ap_tracking,
        )
        .unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();

        set_state_updates_start(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        // Temp segment will be used only when full_output = 1 and use_kzg_da = 0
        if (use_kzg_da, full_output) == (0, 1) {
            assert_eq!(vm.segments.num_temp_segments(), 1);
        } else {
            assert_eq!(vm.segments.num_temp_segments(), 0);
        }
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    fn test_set_compressed_start(#[case] use_kzg_da: u64) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(1);
        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let mut exec_scopes: ExecutionScopes = Default::default();
        let ids_data = HashMap::from([(vars::ids::COMPRESSED_START.to_string(), HintReference::new_simple(-1))]);

        exec_scopes.insert_value(vars::scopes::USE_KZG_DA, Felt252::from(use_kzg_da));

        set_compressed_start(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        if use_kzg_da == 0 {
            assert_eq!(vm.segments.num_temp_segments(), 1);
        } else {
            assert_eq!(vm.segments.num_temp_segments(), 0);
        }
    }
}
