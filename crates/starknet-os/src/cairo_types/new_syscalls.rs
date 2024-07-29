use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::Felt252;

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct CallContractRequest {
    // The address of the L2 contract to call.
    contract_address: Felt252,
    // The selector of the function to call.
    selector: Felt252,
    // The calldata.
    calldata_start: Felt252,
    calldata_end: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct CallContractResponse {
    retdata_start: Felt252,
    retdata_end: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct DeployRequest {
    // The hash of the class to deploy.
    class_hash: Felt252,
    // A salt for the new contract address calculation.
    contract_address_salt: Felt252,
    // The calldata for the constructor.
    constructor_calldata_start: Felt252,
    constructor_calldata_end: Felt252,
    // Used for deterministic contract address deployment.
    deploy_from_zero: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct DeployResponse {
    #[allow(unused)]
    pub contract_address: Felt252,
    #[allow(unused)]
    pub constructor_retdata_start: Relocatable,
    #[allow(unused)]
    pub constructor_retdata_end: Relocatable,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct EmitEventRequest {
    keys_start: Felt252,
    keys_end: Felt252,
    data_start: Felt252,
    data_end: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct GetBlockHashRequest {
    pub block_number: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct LibraryCallRequest {
    /// The hash of the class to run.
    #[allow(unused)]
    pub class_hash: Felt252,
    /// The selector of the function to call.
    #[allow(unused)]
    pub selector: Felt252,
    /// The calldata.
    #[allow(unused)]
    pub calldata_start: Relocatable,
    #[allow(unused)]
    pub calldata_end: Relocatable,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct SendMessageToL1Request {
    to_address: Felt252,
    payload_start: Felt252,
    payload_end: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct StorageReadRequest {
    address_domain: Felt252,
    key: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct StorageWriteRequest {
    pub address_domain: Felt252,
    pub key: Felt252,
    pub value: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct ReplaceClassRequest {
    pub class_hash: Felt252,
}
