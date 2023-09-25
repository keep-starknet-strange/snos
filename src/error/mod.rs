use cairo_felt::Felt252;

#[derive(thiserror::Error, Clone, Debug)]
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
