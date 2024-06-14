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
pub struct GetBlockNumberRequest {
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockNumberResponse {
    pub block_number: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockNumber {
    pub request: GetBlockNumberRequest,
    pub response: GetBlockNumberResponse,
}

#[derive(FieldOffsetGetters)]
pub struct LibraryCallRequest {
    /// The system library call selector
    /// (= LIBRARY_CALL_SELECTOR or LIBRARY_CALL_L1_HANDLER_SELECTOR).
    pub selector: Felt252,
    /// The hash of the class to run.
    pub class_hash: Felt252,
    /// The selector of the function to call.
    pub function_selector: Felt252,
    /// The size of the calldata.
    pub calldata_size: Felt252,
    /// The calldata.
    pub calldata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct LibraryCall {
    pub request: LibraryCallRequest,
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

/// Describes the GetTxInfo system call format.
#[derive(FieldOffsetGetters)]
pub struct GetTxInfoRequest {
    /// The system call selector (= GET_TX_INFO_SELECTOR).
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxInfoResponse {
    /// Points to a TxInfo struct.
    pub tx_info: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxInfo {
    pub request: GetTxInfoRequest,
    pub response: GetTxInfoResponse,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxSignatureRequest {
    // The system call selector (= GET_TX_SIGNATURE_SELECTOR).
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxSignatureResponse {
    pub signature_len: Felt252,
    pub signature: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxSignature {
    pub request: GetTxSignatureRequest,
    pub response: GetTxSignatureResponse,
}
