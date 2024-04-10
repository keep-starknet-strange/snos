use cairo_type_derive::FieldOffsetGetters;
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
pub struct NewStorageWriteRequest {
    pub reserved: Felt252,
    pub key: Felt252,
    pub value: Felt252,
}
