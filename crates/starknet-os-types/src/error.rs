#[derive(thiserror::Error, Debug)]
pub enum ContractClassError {
    #[error("Internal error: no type conversion is possible to generate the desired effect.")]
    NoPossibleConversion,

    #[error("Could not build Blockifier contract class")]
    BlockifierConversionError,

    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
}
