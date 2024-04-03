use cairo_vm::vm::errors::hint_errors::HintError;

use crate::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
use crate::storage::storage::StorageError;

#[derive(thiserror::Error, Debug)]
pub enum CombineError {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error("Only trees of same height can be combined; got left={0} right={1}")]
    TreeHeightsDiffer(Height, Height),

    #[error("Combining to virtual edge node can only be done on one empty and one non-empty node")]
    CannotCombineToVirtualEdgeNode,
}

#[derive(thiserror::Error, Debug)]
pub enum UpdateTreeError {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Combine(#[from] CombineError),
}

#[derive(thiserror::Error, Debug)]
pub enum TreeError {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    UpdateTree(#[from] UpdateTreeError),

    #[error("Got mismatching heights while comparing trees: {0} vs {1}")]
    TreeHeightsMismatch(Height, Height),

    #[error("Did not expect a leaf node")]
    IsLeaf,

    #[error("Did not expect an empty node")]
    IsEmpty,

    #[error("Edge path ({0}) must be at most of length {1}")]
    InvalidEdgePath(NodePath, Length),
}

impl From<TreeError> for HintError {
    fn from(error: TreeError) -> Self {
        HintError::CustomHint(error.to_string().into_boxed_str())
    }
}
