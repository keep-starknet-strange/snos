use cairo_vm::Felt252;
use starknet_api::transaction::{Resource, ResourceBoundsMapping};

pub const L1_GAS: &str = "L1_GAS";
pub const L2_GAS: &str = "L2_GAS";

pub fn create_resource_bounds_list(resource_bounds: &ResourceBoundsMapping) -> Vec<Felt252> {
    let l1_gas = Felt252::from_bytes_be_slice(L1_GAS.as_bytes());
    let l2_gas = Felt252::from_bytes_be_slice(L2_GAS.as_bytes());

    let mut resource_bounds_vec = vec![];

    let resource_types = [(Resource::L1Gas, l1_gas), (Resource::L2Gas, l2_gas)];

    for (resource, name_as_felt) in resource_types {
        let bounds = resource_bounds.0.get(&resource).expect("Expect to find well-known resource types");
        resource_bounds_vec.push(name_as_felt);
        resource_bounds_vec.push(bounds.max_amount.into());
        resource_bounds_vec.push(bounds.max_price_per_unit.into());
    }

    resource_bounds_vec
}
