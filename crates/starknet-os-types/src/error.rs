use std::error::Error;

use cairo_lang_starknet_classes::casm_contract_class::StarknetSierraCompilationError;

#[derive(thiserror::Error, Debug)]
pub enum ContractClassError {
    #[error(transparent)]
    ConversionError(#[from] ConversionError),

    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),

    #[error("Failed to hash class: {0}")]
    HashError(String),

    #[error(transparent)]
    CompilationError(#[from] StarknetSierraCompilationError),
}

#[derive(thiserror::Error, Debug)]
pub enum ConversionError {
    #[error("Could not build Blockifier contract class: {0}")]
    BlockifierError(Box<dyn Error + 'static>),

    #[error("Missing Starknet serialized class")]
    StarknetClassMissing,

    #[error("Missing Blockifier serialized class")]
    BlockifierClassMissing,

    #[error("Missing CairoLang serialized class")]
    CairoLangClassMissing,
}
