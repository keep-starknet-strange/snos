use starknet::core::types::FieldElement;

#[derive(thiserror::Error, Clone, Debug)]
pub enum SnOsError {
    #[error("SnOs Error: {0}.")]
    CatchAll(String),
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum CommitmentInfoError {
    #[error("Inconsistent tree heights : {0} {1}.")]
    InconsistentTreeHeights(u32, u32),
    #[error("Inconsistent tree roots : {0} {1}.")]
    InconsistentTreeRoots(FieldElement, FieldElement),
}
