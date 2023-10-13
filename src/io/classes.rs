use cairo_felt::Felt252;
use cairo_vm::types::relocatable::MaybeRelocatable;
use num_traits::Num;

use crate::utils::felt_api2vm;

use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPointType,
};

pub fn flatten_deprecated_class(
    deprecated_class: DeprecatedContractClass,
) -> Vec<MaybeRelocatable> {
    let mut dep_class_data: Vec<MaybeRelocatable> = Vec::new();
    dep_class_data.push(MaybeRelocatable::from(Felt252::from(0)));

    let mut externals: Vec<MaybeRelocatable> = Vec::new();
    for elem in deprecated_class
        .entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .iter()
    {
        externals.push(MaybeRelocatable::from(felt_api2vm(elem.selector.0)));
        externals.push(MaybeRelocatable::from(Felt252::from(elem.offset.0)));
    }
    dep_class_data.push(MaybeRelocatable::from(Felt252::from(externals.len())));
    dep_class_data.append(&mut externals);

    let mut l1_handlers: Vec<MaybeRelocatable> = Vec::new();
    for elem in deprecated_class
        .entry_points_by_type
        .get(&EntryPointType::L1Handler)
        .unwrap()
        .iter()
    {
        l1_handlers.push(MaybeRelocatable::from(felt_api2vm(elem.selector.0)));
        l1_handlers.push(MaybeRelocatable::from(Felt252::from(elem.offset.0)));
    }
    dep_class_data.push(MaybeRelocatable::from(Felt252::from(l1_handlers.len())));
    dep_class_data.append(&mut l1_handlers);

    let mut constructors: Vec<MaybeRelocatable> = Vec::new();
    for elem in deprecated_class
        .entry_points_by_type
        .get(&EntryPointType::Constructor)
        .unwrap()
        .iter()
    {
        constructors.push(MaybeRelocatable::from(felt_api2vm(elem.selector.0)));
        constructors.push(MaybeRelocatable::from(Felt252::from(elem.offset.0)));
    }
    dep_class_data.push(MaybeRelocatable::from(Felt252::from(constructors.len())));
    dep_class_data.append(&mut constructors);

    let builtins: Vec<String> =
        serde_json::from_value(deprecated_class.clone().program.builtins).unwrap();
    let mut builtins: Vec<MaybeRelocatable> = builtins
        .into_iter()
        .map(|bi| MaybeRelocatable::from(Felt252::from_bytes_be(bi.as_bytes())))
        .collect();
    dep_class_data.push(MaybeRelocatable::from(Felt252::from(builtins.len())));
    dep_class_data.append(&mut builtins);

    dep_class_data.push(compute_deprecated_hinted_class_hash(
        deprecated_class.clone(),
    ));

    let data: Vec<String> = serde_json::from_value(deprecated_class.program.data).unwrap();
    let mut data: Vec<MaybeRelocatable> = data
        .into_iter()
        .map(|datum| {
            MaybeRelocatable::from(
                Felt252::from_str_radix(datum.trim_start_matches("0x"), 16).unwrap(),
            )
        })
        .collect();
    dep_class_data.push(MaybeRelocatable::from(Felt252::from(data.len())));
    dep_class_data.append(&mut data);

    dep_class_data
}

fn compute_deprecated_hinted_class_hash(
    _deprecated_class: DeprecatedContractClass,
) -> MaybeRelocatable {
    // TODO: impl deprecated hint class hash
    MaybeRelocatable::from(Felt252::from(0))
}
