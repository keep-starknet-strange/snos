use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::Felt252;

#[derive(thiserror::Error, Debug)]
pub enum SnOsError {
    #[error("SnOs Error: {0}")]
    CatchAll(String),
    #[error("PIE Parse Error: {0}")]
    PieParsing(String),
    #[error("PIE Zip Error: {0}")]
    PieZipping(String),
    #[error("PIE Encode Error: {0}")]
    PieEncoding(String),
    #[error("SHARP Request Error: {0}")]
    SharpRequest(String),
    #[error("Starknet Os Runner Error: {0}")]
    Runner(CairoRunError),
    #[error("SnOs Output Error: {0}")]
    Output(String),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("SnOs Deprecated Syscall Error: {0}")]
    InvalidDeprecatedSyscallSelector(Felt252),
}
