use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::Felt252;

#[derive(FieldOffsetGetters)]
pub struct StorageReadRequest {
    pub selector: Felt252,
    pub address: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct StorageReadResponse {
    pub value: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct StorageRead {
    pub request: StorageReadRequest,
    pub response: StorageReadResponse,
}

#[derive(FieldOffsetGetters)]
pub struct StorageWrite {
    pub selector: Felt252,
    pub address: Felt252,
    pub value: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct SyscallContractResponse {
    pub retdata_size: Felt252,
    pub retdata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct NewSyscallContractResponse {
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct NewDeployResponse {
    pub contract_address: Felt252,
    pub constructor_retdata_start: Relocatable,
    pub constructor_retdata_end: Relocatable,
}
