use thiserror::Error;

#[derive(Error, Debug)]
pub enum FeltConversionError {
    #[error("Overflow Error: Felt exceeds u128 max value")]
    OverflowError,
    #[error("{0}")]
    CustomError(String),
}
