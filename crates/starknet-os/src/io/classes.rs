use cairo_lang_starknet_classes::casm_contract_class::CasmContractEntryPoint;
use cairo_lang_starknet_classes::NestedIntList;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use pathfinder_gateway_types::class_hash::{compute_cairo_hinted_class_hash, json};
use starknet_api::deprecated_contract_class::{ContractClass as DeprecatedContractClass, EntryPointType};
use starknet_os_types::casm_contract_class::GenericCasmContractClass;

use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
    BytecodeLeaf, BytecodeSegment, BytecodeSegmentStructureImpl, BytecodeSegmentedNode,
};
use crate::starkware_utils::commitment_tree::base_types::Length;
use crate::utils::{custom_hint_error, felt_api2vm};

/// Returns the serialization of a contract as a list of field elements.
pub fn get_deprecated_contract_class_struct(
    vm: &mut VirtualMachine,
    class_base: Relocatable,
    deprecated_class: DeprecatedContractClass,
) -> Result<(), HintError> {
    vm.insert_value(class_base, Felt252::from(0))?; // DEPRECATED_COMPILED_CLASS_VERSION = 0

    let mut externals: Vec<MaybeRelocatable> = Vec::new();
    for elem in deprecated_class.entry_points_by_type.get(&EntryPointType::External).unwrap().iter() {
        externals.push(MaybeRelocatable::from(felt_api2vm(elem.selector.0)));
        externals.push(MaybeRelocatable::from(Felt252::from(elem.offset.0)));
    }
    vm.insert_value((class_base + 1)?, Felt252::from(externals.len() / 2))?;
    let externals_base = vm.add_memory_segment();
    vm.load_data(externals_base, &externals)?;

    vm.insert_value((class_base + 2)?, externals_base)?;

    let mut l1_handlers: Vec<MaybeRelocatable> = Vec::new();
    for elem in deprecated_class.entry_points_by_type.get(&EntryPointType::L1Handler).unwrap().iter() {
        l1_handlers.push(MaybeRelocatable::from(felt_api2vm(elem.selector.0)));
        l1_handlers.push(MaybeRelocatable::from(Felt252::from(elem.offset.0)));
    }
    vm.insert_value((class_base + 3)?, Felt252::from(l1_handlers.len() / 2))?;
    let l1_handlers_base = vm.add_memory_segment();
    vm.load_data(l1_handlers_base, &l1_handlers)?;

    vm.insert_value((class_base + 4)?, l1_handlers_base)?;

    let mut constructors: Vec<MaybeRelocatable> = Vec::new();
    for elem in deprecated_class.entry_points_by_type.get(&EntryPointType::Constructor).unwrap().iter() {
        constructors.push(MaybeRelocatable::from(felt_api2vm(elem.selector.0)));
        constructors.push(MaybeRelocatable::from(Felt252::from(elem.offset.0)));
    }
    vm.insert_value((class_base + 5)?, Felt252::from(constructors.len() / 2))?;
    let constructors_base = vm.add_memory_segment();
    vm.load_data(constructors_base, &constructors)?;

    vm.insert_value((class_base + 6)?, constructors_base)?;

    let builtins: Vec<String> = serde_json::from_value(deprecated_class.clone().program.builtins).unwrap();
    let builtins: Vec<MaybeRelocatable> =
        builtins.into_iter().map(|bi| MaybeRelocatable::from(Felt252::from_bytes_be_slice(bi.as_bytes()))).collect();

    vm.insert_value((class_base + 7)?, Felt252::from(builtins.len()))?;
    let builtins_base = vm.add_memory_segment();
    vm.load_data(builtins_base, &builtins)?;
    vm.insert_value((class_base + 8)?, builtins_base)?;

    let contract_definition_dump = serde_json::to_vec(&deprecated_class).expect("Serialization should not fail");
    let cairo_contract_class_json =
        serde_json::from_slice::<json::CairoContractDefinition<'_>>(&contract_definition_dump)
            .expect("Deserialization should not fail");

    let hinted_class_hash = {
        let class_hash =
            compute_cairo_hinted_class_hash(&cairo_contract_class_json).expect("Hashing should not fail here");
        Felt252::from_bytes_be(&class_hash.to_be_bytes())
    };

    vm.insert_value((class_base + 9)?, hinted_class_hash)?;

    let data: Vec<String> = serde_json::from_value(deprecated_class.program.data).unwrap();
    let data: Vec<MaybeRelocatable> =
        data.into_iter().map(|datum| MaybeRelocatable::from(Felt252::from_hex(&datum).unwrap())).collect();
    vm.insert_value((class_base + 10)?, Felt252::from(data.len()))?;
    let data_base = vm.add_memory_segment();
    vm.load_data(data_base, &data)?;

    vm.insert_value((class_base + 11)?, data_base)?;

    Ok(())
}

fn load_casm_entrypoints(
    vm: &mut VirtualMachine,
    base: Relocatable,
    entry_points: &[CasmContractEntryPoint],
) -> Result<(), HintError> {
    let mut b: Vec<MaybeRelocatable> = Vec::new();
    for ep in entry_points.iter() {
        b.push(MaybeRelocatable::from(Felt252::from(&ep.selector)));
        b.push(MaybeRelocatable::from(ep.offset));
        b.push(MaybeRelocatable::from(ep.builtins.len()));
        let builtins: Vec<MaybeRelocatable> =
            ep.builtins.iter().map(|bi| MaybeRelocatable::from(Felt252::from_bytes_be_slice(bi.as_bytes()))).collect();
        let builtins_base = vm.add_memory_segment();
        vm.load_data(builtins_base, &builtins)?;
        b.push(builtins_base.into());
    }
    vm.insert_value(base, Felt252::from(entry_points.len()))?;
    let externals_base = vm.add_memory_segment();
    vm.load_data(externals_base, &b)?;
    vm.insert_value((base + 1)?, externals_base)?;

    Ok(())
}

/// Helper function for `create_bytecode_segment_structure`.
/// `visited_pcs` should be given in reverse order, and is consumed by the function.
/// Returns the BytecodeSegmentStructure and the total length of the processed segment.
fn _create_bytecode_segment_structure_inner(
    bytecode: &[BigUint],
    bytecode_segment_lengths: NestedIntList,
    visited_pcs: &mut Vec<Felt252>,
    mut bytecode_offset: usize,
) -> Result<(BytecodeSegmentStructureImpl, usize), HintError> {
    match bytecode_segment_lengths {
        NestedIntList::Leaf(length) => {
            let segment_end = bytecode_offset + length;

            // Remove all the visited PCs that are in the segment.
            while !visited_pcs.is_empty()
                && (bytecode_offset..segment_end).contains(&(visited_pcs[visited_pcs.len() - 1].to_usize().unwrap()))
            {
                visited_pcs.pop();
            }

            let bytecode_segment: Vec<_> = bytecode[bytecode_offset..segment_end].to_vec();

            Ok((BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: bytecode_segment }), length))
        }
        NestedIntList::Node(lengths) => {
            let mut res = vec![];
            let mut total_len = 0;

            for item in lengths {
                let visited_pc_before = visited_pcs.last().copied();
                let (current_structure, item_len) =
                    _create_bytecode_segment_structure_inner(bytecode, item, visited_pcs, bytecode_offset)?;

                let visited_pc_after = visited_pcs.last().copied();
                let is_used = visited_pc_after != visited_pc_before;

                if is_used {
                    let visited_pc_before = visited_pc_before.expect("if is_used, visited_pc_before should be set");
                    if visited_pc_before != Felt252::from(bytecode_offset) {
                        return Err(HintError::AssertionFailed(
                            format!(
                                "Invalid segment structure: PC {visited_pc_before} was visited, but the beginning of \
                                 the segment ({bytecode_offset}) was not."
                            )
                            .into_boxed_str(),
                        ));
                    }
                }

                res.push(BytecodeSegment {
                    segment_length: Length(item_len as u64),
                    is_used,
                    inner_structure: current_structure,
                });

                bytecode_offset += item_len;
                total_len += item_len;
            }

            Ok((BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode { segments: res }), total_len))
        }
    }
}

//         res.append(
//             BytecodeSegment(
//                 segment_length=item_len, is_used=is_used, inner_structure=current_structure
//             )
//         )
//         bytecode_offset += item_len
//         total_len += item_len
//
//     return BytecodeSegmentedNode(segments=res), total_len

/// Creates a BytecodeSegmentStructure instance from the given bytecode and
/// bytecode_segment_lengths.
pub fn create_bytecode_segment_structure(
    bytecode: &[BigUint],
    bytecode_segment_lengths: NestedIntList,
    visited_pcs: Option<Vec<Felt252>>,
) -> Result<BytecodeSegmentStructureImpl, HintError> {
    let mut rev_visited_pcs = visited_pcs.unwrap_or_else(|| {
        let default_visited_pcs: Vec<_> = (0..bytecode.len()).map(Felt252::from).rev().collect();
        default_visited_pcs
    });

    let (res, total_len) =
        _create_bytecode_segment_structure_inner(bytecode, bytecode_segment_lengths, &mut rev_visited_pcs, 0)?;

    if total_len != bytecode.len() {
        return Err(HintError::AssertionFailed(
            format!("Invalid length bytecode segment structure: {total_len}. Bytecode length: {}.", bytecode.len())
                .into_boxed_str(),
        ));
    }

    if !rev_visited_pcs.is_empty() {
        return Err(HintError::AssertionFailed(
            format!("PC {} is out of range.", rev_visited_pcs[rev_visited_pcs.len() - 1]).into_boxed_str(),
        ));
    }

    Ok(res)
}

pub fn write_class(
    vm: &mut VirtualMachine,
    class_base: Relocatable,
    class: GenericCasmContractClass,
    visited_pcs: Option<Vec<Felt252>>,
) -> Result<BytecodeSegmentStructureImpl, HintError> {
    let version = Felt252::from_hex("0x434f4d50494c45445f434c4153535f5631").unwrap();
    vm.insert_value(class_base, version)?; // COMPILED_CLASS_V1

    let cairo_lang_class = class.to_cairo_lang_contract_class().map_err(|e| custom_hint_error(e.to_string()))?;

    load_casm_entrypoints(vm, (class_base + 1)?, &cairo_lang_class.entry_points_by_type.external)?;
    load_casm_entrypoints(vm, (class_base + 3)?, &cairo_lang_class.entry_points_by_type.l1_handler)?;
    load_casm_entrypoints(vm, (class_base + 5)?, &cairo_lang_class.entry_points_by_type.constructor)?;

    let bytecode: Vec<_> = cairo_lang_class.bytecode.iter().map(|x| x.value.clone()).collect();

    let bytecode_segment_lengths =
        cairo_lang_class.bytecode_segment_lengths.unwrap_or(NestedIntList::Leaf(bytecode.len()));

    let bytecode_segment_structure =
        create_bytecode_segment_structure(&bytecode, bytecode_segment_lengths, visited_pcs)?;
    let bytecode_with_skipped_segments = bytecode_segment_structure.bytecode_with_skipped_segments();

    let data: Vec<MaybeRelocatable> = bytecode_with_skipped_segments.into_iter().map(MaybeRelocatable::from).collect();
    vm.insert_value((class_base + 7)?, Felt252::from(data.len()))?;
    let data_base = vm.add_memory_segment();
    vm.load_data(data_base, &data)?;
    vm.insert_value((class_base + 8)?, data_base)?;

    Ok(bytecode_segment_structure)
}
