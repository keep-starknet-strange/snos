use cairo_vm::felt::Felt252;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_traits::Num;
use starknet_api::deprecated_contract_class::{ContractClass as DeprecatedContractClass, EntryPointType};

use crate::utils::felt_api2vm;

pub fn write_deprecated_class(
    vm: &mut VirtualMachine,
    class_base: Relocatable,
    deprecated_class: DeprecatedContractClass,
) -> Result<(), HintError> {
    // DEPRECATED_COMPILED_CLASS_VERSION = 0
    vm.insert_value(class_base, Felt252::from(0))?;

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
        builtins.into_iter().map(|bi| MaybeRelocatable::from(Felt252::from_bytes_be(bi.as_bytes()))).collect();

    vm.insert_value((class_base + 7)?, Felt252::from(builtins.len()))?;
    let builtins_base = vm.add_memory_segment();
    vm.load_data(builtins_base, &builtins)?;
    vm.insert_value((class_base + 8)?, builtins_base)?;

    // TODO: comput actual class hash
    vm.insert_value(
        (class_base + 9)?,
        Felt252::from_str_radix("1ba5aa88eff644fa696f90d9346993614a974afad2612bd0074e8f5884fd66d", 16).unwrap(),
    )?;

    let data: Vec<String> = serde_json::from_value(deprecated_class.program.data).unwrap();
    let data: Vec<MaybeRelocatable> = data
        .into_iter()
        .map(|datum| MaybeRelocatable::from(Felt252::from_str_radix(datum.trim_start_matches("0x"), 16).unwrap()))
        .collect();
    vm.insert_value((class_base + 10)?, Felt252::from(data.len()))?;
    let data_base = vm.add_memory_segment();
    vm.load_data(data_base, &data)?;

    vm.insert_value((class_base + 11)?, data_base)?;

    Ok(())
}

fn _compute_deprecated_hinted_class_hash(_deprecated_class: DeprecatedContractClass) -> MaybeRelocatable {
    // TODO: impl deprecated hint class hash
    MaybeRelocatable::from(Felt252::from(0))
}
