//! Error types for Felt conversion operations and block processing.

use thiserror::Error;

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

    /// Block context error.
    #[error("Block context error: {0}")]
    BlockContext(String),

    /// Invalid block state error.
    #[error("Invalid block state: {0}")]
    InvalidBlockState(String),

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
