use std::collections::HashMap;

use starknet::core::types::FieldElement;

use crate::{
    error::FactTreeError,
    storage::{FactCheckingContext, Storage},
    utils::hasher::HasherT,
};

use super::nodes::InnerNodeFact;

pub type BinaryFactDict = HashMap<FieldElement, Vec<FieldElement>>;

pub trait BinaryFactTree<S: Storage, H: HasherT>
where
    Self: Sized,
{
    /// Initializes an empty BinaryFactTree of the given height.
    async fn empty_tree(
        &self,
        ffc: FactCheckingContext<S, H>,
        height: usize,
        leaft_fact: InnerNodeFact,
    );
    /// Returns the values of the leaves whose indices are given.
    async fn get_leaves(
        &self,
        ffc: &FactCheckingContext<S, H>,
        indices: Vec<FieldElement>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, InnerNodeFact>;

    async fn _get_leaves(
        &self,
        ffc: &FactCheckingContext<S, H>,
        indices: Vec<FieldElement>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, InnerNodeFact>;

    async fn update(
        &self,
        ffc: &FactCheckingContext<S, H>,
        modifications: HashMap<FieldElement, InnerNodeFact>,
        facts: Option<&mut BinaryFactDict>,
    ) -> Self;

    async fn get_leaf(
        &self,
        ffc: &FactCheckingContext<S, H>,
        index: FieldElement,
    ) -> Result<InnerNodeFact, FactTreeError> {
        let leaves = self.get_leaves(ffc, vec![index], None).await;
        if leaves.keys().ne([index].iter()) {
            return Err(FactTreeError::UnexpectedResult(index));
        }

        // TODO: remove unwrap
        let leaf = leaves.get(&index).unwrap().clone();

        Ok(leaf)
    }
}
