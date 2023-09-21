use starknet::core::types::FieldElement;

#[derive(thiserror::Error, Clone, Debug)]
pub enum SnOsError {
    #[error("SnOs Error: {0}.")]
    CatchAll(String),
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum CommitmentInfoError {
    #[error("Inconsistent tree heights : {0} {1}.")]
    InconsistentTreeHeights(usize, usize),
    #[error("Inconsistent tree roots : {0} {1}.")]
    InconsistentTreeRoots(FieldElement, FieldElement),
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum FactTreeError {
    #[error("Unexpected result on single leaf index : {0}")]
    UnexpectedResult(FieldElement),
}
