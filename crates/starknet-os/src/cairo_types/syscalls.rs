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
    #[allow(unused)]
    pub selector: Felt252,
    #[allow(unused)]
    pub contract_address: Felt252,
    #[allow(unused)]
    pub function_selector: Felt252,
    #[allow(unused)]
    pub calldata_size: Felt252,
    #[allow(unused)]
    pub calldata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct CallContractResponse {
    #[allow(unused)]
    pub retdata_size: Felt252,
    #[allow(unused)]
    pub retdata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct CallContract {
    #[allow(unused)]
    pub request: CallContractRequest,
    #[allow(unused)]
    pub response: CallContractResponse,
}

/// Describes the Deploy system call format.
#[derive(FieldOffsetGetters)]
pub struct DeployRequest {
    /// The system call selector (= DEPLOY_SELECTOR).
    #[allow(unused)]
    pub selector: Felt252,
    /// The hash of the class to deploy.
    #[allow(unused)]
    pub class_hash: Felt252,
    /// A salt for the new contract address calculation.
    #[allow(unused)]
    pub contract_address_salt: Felt252,
    /// The size of the calldata for the constructor.
    #[allow(unused)]
    pub constructor_calldata_size: Felt252,
    /// The calldata for the constructor.
    #[allow(unused)]
    pub constructor_calldata: Relocatable,
    /// Used for deterministic contract address deployment.
    #[allow(unused)]
    pub deploy_from_zero: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct DeployResponse {
    #[allow(unused)]
    pub contract_address: Felt252,
    #[allow(unused)]
    pub constructor_retdata_size: Felt252,
    #[allow(unused)]
    pub constructor_retdata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct Deploy {
    #[allow(unused)]
    pub request: DeployRequest,
    #[allow(unused)]
    pub response: DeployResponse,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockNumberRequest {
    #[allow(unused)]
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockNumberResponse {
    #[allow(unused)]
    pub block_number: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockNumber {
    #[allow(unused)]
    pub request: GetBlockNumberRequest,
    #[allow(unused)]
    pub response: GetBlockNumberResponse,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockTimestampRequest {
    #[allow(unused)]
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockTimestampResponse {
    #[allow(unused)]
    pub block_timestamp: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetBlockTimestamp {
    #[allow(unused)]
    pub request: GetBlockTimestampRequest,
    #[allow(unused)]
    pub response: GetBlockTimestampResponse,
}

// Describes the GetContractAddress system call format.
#[derive(FieldOffsetGetters)]
pub struct GetContractAddressRequest {
    // The system call selector (= GET_CONTRACT_ADDRESS_SELECTOR).
    #[allow(unused)]
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetContractAddressResponse {
    #[allow(unused)]
    pub contract_address: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetContractAddress {
    #[allow(unused)]
    pub request: GetContractAddressRequest,
    #[allow(unused)]
    pub response: GetContractAddressResponse,
}

#[derive(FieldOffsetGetters)]
pub struct LibraryCallRequest {
    /// The system library call selector
    /// (= LIBRARY_CALL_SELECTOR or LIBRARY_CALL_L1_HANDLER_SELECTOR).
    #[allow(unused)]
    pub selector: Felt252,
    /// The hash of the class to run.
    #[allow(unused)]
    pub class_hash: Felt252,
    /// The selector of the function to call.
    #[allow(unused)]
    pub function_selector: Felt252,
    /// The size of the calldata.
    #[allow(unused)]
    pub calldata_size: Felt252,
    /// The calldata.
    #[allow(unused)]
    pub calldata: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct LibraryCall {
    #[allow(unused)]
    pub request: LibraryCallRequest,
    #[allow(unused)]
    pub response: CallContractResponse,
}

/// Describes the GetSequencerAddress system call format.
#[derive(FieldOffsetGetters)]
pub struct GetSequencerAddressRequest {
    // The system call selector (= GET_SEQUENCER_ADDRESS_SELECTOR).
    #[allow(unused)]
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetSequencerAddressResponse {
    #[allow(unused)]
    pub sequencer_address: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetSequencerAddress {
    #[allow(unused)]
    pub request: GetSequencerAddressRequest,
    #[allow(unused)]
    pub response: GetSequencerAddressResponse,
}

#[derive(FieldOffsetGetters)]
pub struct TxInfo {
    /// The version of the transaction. It is fixed (currently, 1) in the OS, and should be
    /// signed by the account contract.
    /// This field allows invalidating old transactions, whenever the meaning of the other
    /// transaction fields is changed (in the OS).
    #[allow(unused)]
    pub version: Felt252,
    /// The account contract from which this transaction originates.
    #[allow(unused)]
    pub account_contract_address: Felt252,
    /// The max_fee field of the transaction.
    #[allow(unused)]
    pub max_fee: Felt252,
    /// The signature of the transaction.
    #[allow(unused)]
    pub signature_len: Felt252,
    #[allow(unused)]
    pub signature: Relocatable,
    /// The hash of the transaction.
    #[allow(unused)]
    pub transaction_hash: Felt252,
    /// The identifier of the chain.
    /// This field can be used to prevent replay of testnet transactions on mainnet.
    #[allow(unused)]
    pub chain_id: Felt252,
    /// The transaction's nonce.
    #[allow(unused)]
    pub nonce: Felt252,
}

/// Describes the GetTxInfo system call format.
#[derive(FieldOffsetGetters)]
pub struct GetTxInfoRequest {
    /// The system call selector (= GET_TX_INFO_SELECTOR).
    #[allow(unused)]
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxInfoResponse {
    /// Points to a TxInfo struct.
    #[allow(unused)]
    pub tx_info: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxInfo {
    #[allow(unused)]
    pub request: GetTxInfoRequest,
    #[allow(unused)]
    pub response: GetTxInfoResponse,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxSignatureRequest {
    // The system call selector (= GET_TX_SIGNATURE_SELECTOR).
    #[allow(unused)]
    pub selector: Felt252,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxSignatureResponse {
    #[allow(unused)]
    pub signature_len: Felt252,
    #[allow(unused)]
    pub signature: Relocatable,
}

#[derive(FieldOffsetGetters)]
pub struct GetTxSignature {
    #[allow(unused)]
    pub request: GetTxSignatureRequest,
    #[allow(unused)]
    pub response: GetTxSignatureResponse,
}
