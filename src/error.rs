use cairo_vm::felt::Felt252;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;

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

#[derive(thiserror::Error, Clone, Debug)]
pub enum CommitmentInfoError {
    #[error("Inconsistent tree heights : {0} {1}.")]
    InconsistentTreeHeights(usize, usize),
    #[error("Inconsistent tree roots, actual : {0} , expected : {1}.")]
    InconsistentTreeRoots(Felt252, Felt252),
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum FactTreeError {
    #[error("Unexpected result on single leaf index : {0}")]
    UnexpectedResult(Felt252),
}
