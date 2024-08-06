use cairo_lang_starknet_classes::casm_contract_class::StarknetSierraCompilationError;

#[derive(thiserror::Error, Debug)]
pub enum ContractClassError {
    #[error("Internal error: no type conversion is possible to generate the desired effect.")]
    NoPossibleConversion,

    #[error("Could not build Blockifier contract class")]
    BlockifierConversionError,

    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),

    #[error("Failed to hash class: {0}")]
    HashError(String),

    #[error(transparent)]
    CompilationError(#[from] StarknetSierraCompilationError),
}
