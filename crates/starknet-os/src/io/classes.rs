use cairo_lang_starknet_classes::casm_contract_class::CasmContractEntryPoint;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use pathfinder_gateway_types::class_hash::{compute_cairo_hinted_class_hash, json};
use starknet_api::deprecated_contract_class::{ContractClass as DeprecatedContractClass, EntryPointType};
use starknet_os_types::casm_contract_class::GenericCasmContractClass;

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
pub fn write_class(
    vm: &mut VirtualMachine,
    class_base: Relocatable,
    class: GenericCasmContractClass,
) -> Result<(), HintError> {
    let version = Felt252::from_hex("0x434f4d50494c45445f434c4153535f5631").unwrap();
    vm.insert_value(class_base, version)?; // COMPILED_CLASS_V1

    let cairo_lang_class = class.to_cairo_lang_contract_class().map_err(|e| custom_hint_error(e.to_string()))?;

    load_casm_entrypoints(vm, (class_base + 1)?, &cairo_lang_class.entry_points_by_type.external)?;
    load_casm_entrypoints(vm, (class_base + 3)?, &cairo_lang_class.entry_points_by_type.l1_handler)?;
    load_casm_entrypoints(vm, (class_base + 5)?, &cairo_lang_class.entry_points_by_type.constructor)?;

    let data: Vec<MaybeRelocatable> =
        cairo_lang_class.bytecode
            .into_iter()
            .map(
                |d| MaybeRelocatable::from(
                    Felt252::from_bytes_be_slice(&d.value.to_bytes_be()[..])
                ) // TODO: fix conversion
            ).collect();
    vm.insert_value((class_base + 7)?, Felt252::from(data.len()))?;
    let data_base = vm.add_memory_segment();
    vm.load_data(data_base, &data)?;
    vm.insert_value((class_base + 8)?, data_base)?;

    Ok(())
}
