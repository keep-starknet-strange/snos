use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::Felt252;

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct StorageReadRequest {
    pub selector: Felt252,
    pub address: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct StorageReadResponse {
    pub value: Felt252,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct StorageRead {
    pub request: StorageReadRequest,
    pub response: StorageReadResponse,
}

#[allow(unused)]
#[derive(FieldOffsetGetters)]
pub struct StorageWrite {
    pub selector: Felt252,
    pub address: Felt252,
    pub value: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct CallContractRequest {
    pub selector: Felt252,
    pub contract_address: Felt252,
    pub function_selector: Felt252,
    pub calldata_size: Felt252,
    pub calldata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct CallContractResponse {
    pub retdata_size: Felt252,
    pub retdata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct CallContract {
    pub request: CallContractRequest,
    pub response: CallContractResponse,
}

#[derive(FieldOffsetGetters)]
pub struct TxInfo {
    /// The version of the transaction. It is fixed (currently, 1) in the OS, and should be
    /// signed by the account contract.
    /// This field allows invalidating old transactions, whenever the meaning of the other
    /// transaction fields is changed (in the OS).
    pub version: Felt252,
    /// The account contract from which this transaction originates.
    pub account_contract_address: Felt252,
    /// The max_fee field of the transaction.
    pub max_fee: Felt252,
    /// The signature of the transaction.
    pub signature_len: Felt252,
    pub signature: Relocatable,
    /// The hash of the transaction.
    pub transaction_hash: Felt252,
    /// The identifier of the chain.
    /// This field can be used to prevent replay of testnet transactions on mainnet.
    pub chain_id: Felt252,
    /// The transaction's nonce.
    pub nonce: Felt252,
}
