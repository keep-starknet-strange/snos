//! Error types for pie generation, felt conversion operations, and block processing.

use blockifier::transaction::errors::TransactionExecutionError;
use starknet::providers::ProviderError;
use starknet_api::StarknetApiError;
use thiserror::Error;

use starknet_os_types::starknet_core_addons::LegacyContractDecompressionError;

/// Main error type for PIE generation.
///
/// This enum represents all possible errors that can occur during the PIE generation
/// process, including block processing errors, RPC client errors, OS execution errors,
/// and configuration errors.
#[derive(thiserror::Error, Debug)]
pub enum PieGenerationError {
    /// Block processing failed for a specific block.
    #[error("Block processing failed for block {block_number}: {source}")]
    BlockProcessing {
        /// The block number that failed to process.
        block_number: u64,
        /// The underlying error that caused the failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// RPC client-related error.
    #[error("RPC client error: {0}")]
    RpcClient(String),

    /// OS execution related error.
    #[error("OS execution error: {0}")]
    OsExecution(String),

    /// I/O error during file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid configuration error.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// State processing error.
    #[error("State processing error: {0}")]
    StateProcessing(String),

    /// Contract class processing error.
    #[error("Contract class processing error: {0}")]
    ContractClassProcessing(String),
}

/// Errors that can occur during Felt conversion operations.
///
/// This enum represents various error conditions that can arise when converting
/// between Felt values and other numeric types, particularly when dealing with
/// overflow conditions or custom conversion errors.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum FeltConversionError {
    /// Overflow error when Felt value exceeds the maximum value for the target type.
    #[error("Overflow Error: Felt exceeds u128 max value")]
    OverflowError,

    /// Custom error with a specific error message.
    #[error("Conversion error: {0}")]
    CustomError(String),
}

impl FeltConversionError {
    /// Creates a new custom error with the specified message.
    ///
    /// # Arguments
    ///
    /// * `message` - The error message
    ///
    /// # Returns
    ///
    /// A new `FeltConversionError::CustomError` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use generate_pie::error::FeltConversionError;
    ///
    /// let error = FeltConversionError::new_custom("Invalid Felt format");
    /// assert_eq!(error, FeltConversionError::CustomError("Invalid Felt format".to_string()));
    /// ```
    pub fn new_custom(message: impl Into<String>) -> Self {
        Self::CustomError(message.into())
    }
}

/// Errors that can occur during block processing operations.
///
/// This enum represents various error conditions that can arise when processing
/// Starknet blocks, including RPC errors, transaction execution errors, and
/// data conversion errors.
#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
pub enum BlockProcessingError {
    /// RPC client error.
    #[error("RPC client error: {0}")]
    RpcClient(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Transaction execution error.
    #[error("Transaction execution error: {0}")]
    TransactionExecution(#[from] blockifier::blockifier::transaction_executor::TransactionExecutorError),

    /// Context building error.
    #[error("Context building error: {0}")]
    ContextBuilding(#[from] FeltConversionError),

    /// State update processing error.
    #[error("State update processing error: {0}")]
    StateUpdateProcessing(String),

    /// Storage proof error.
    #[error("Storage proof error: {0}")]
    StorageProof(String),

    /// Class proof error.
    #[error("Class proof error: {0}")]
    ClassProof(String),

    /// Contract class conversion error.
    #[error("Contract class conversion error: {0}")]
    ContractClassConversion(String),

    /// Invalid block state error.
    #[error("Invalid block state: {0}")]
    InvalidBlockState(String),

    /// Starknet version error.
    #[error("Starknet version error: {0}")]
    StarknetVersion(String),

    /// File I/O error.
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Custom error with a specific message.
    #[error("Block processing error: {0}")]
    Custom(String),
}

impl BlockProcessingError {
    /// Creates a new custom error with the specified message.
    ///
    /// # Arguments
    ///
    /// * `message` - The error message
    ///
    /// # Returns
    ///
    /// A new `BlockProcessingError::Custom` instance.
    pub fn new_custom(message: impl Into<String>) -> Self {
        Self::Custom(message.into())
    }
}

/// Errors encountered during conversion to blockifier types.
#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ToBlockifierError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
    #[error("OS Contract Class Error: {0}")]
    StarknetContractClassError(#[from] starknet_os_types::error::ContractClassError),
    #[error("Legacy Contract Decompression Error: {0}")]
    LegacyContractDecompressionError(#[from] LegacyContractDecompressionError),
    #[error("Starknet API Error: {0}")]
    StarknetApiError(#[from] StarknetApiError),
    #[error("Transaction Execution Error: {0}")]
    TransactionExecutionError(#[from] TransactionExecutionError),
    #[error("Felt Conversion Error: {0}")]
    FeltConversionError(#[from] FeltConversionError),
}
