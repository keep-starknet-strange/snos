//! Error types for contract class operations.

use std::error::Error;

use cairo_lang_starknet_classes::casm_contract_class::StarknetSierraCompilationError;

/// Errors that can occur during contract class operations.
#[derive(thiserror::Error, Debug)]
pub enum ContractClassError {
    /// Error occurred during type conversion between different contract class formats.
    #[error(transparent)]
    ConversionError(#[from] ConversionError),

    /// Error occurred during JSON serialization or deserialization.
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),

    /// Error occurred during hash computation.
    #[error("Failed to hash class: {0}")]
    HashError(String),

    /// Error occurred during Sierra compilation.
    #[error(transparent)]
    CompilationError(#[from] StarknetSierraCompilationError),

    /// Error occurred during contract decompression.
    #[error("Failed to decompress contract: {0}")]
    DecompressionError(#[from] std::io::Error),
}

/// Errors that can occur during type conversion operations.
#[derive(thiserror::Error, Debug)]
pub enum ConversionError {
    /// Error occurred while building a Blockifier contract class.
    #[error("Could not build Blockifier contract class: {0}")]
    BlockifierError(Box<dyn Error + Send + Sync>),

    /// Missing Starknet serialized class data.
    #[error("Missing Starknet serialized class")]
    StarknetClassMissing,

    /// Missing Blockifier serialized class data.
    #[error("Missing Blockifier serialized class")]
    BlockifierClassMissing,

    /// Missing CairoLang serialized class data.
    #[error("Missing CairoLang serialized class")]
    CairoLangClassMissing,

    /// Invalid contract class format or structure.
    #[error("Invalid contract class format: {0}")]
    InvalidFormat(String),
}
