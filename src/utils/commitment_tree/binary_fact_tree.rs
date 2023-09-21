use std::collections::HashMap;

use starknet::core::types::FieldElement;

use crate::{
    error::FactTreeError,
    storage::{FactCheckingContext, Storage},
};

use super::leaf_fact::LeafFact;

pub type BinaryFactDict = HashMap<FieldElement, Vec<FieldElement>>;

pub trait BinaryFactTree<S: Storage, L: LeafFact>
where
    Self: Sized,
{
    /// Initializes an empty BinaryFactTree of the given height.
    async fn empty_tree(&self, ffc: FactCheckingContext<S>, height: usize, leaft_fact: L);
    /// Returns the values of the leaves whose indices are given.
    async fn get_leaves(
        &self,
        ffc: FactCheckingContext<S>,
        indices: Vec<FieldElement>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, L>;

    async fn _get_leaves(
        &self,
        ffc: FactCheckingContext<S>,
        indices: Vec<FieldElement>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, L>;

    async fn update(
        &self,
        ffc: FactCheckingContext<S>,
        modifications: HashMap<FieldElement, L>,
        facts: Option<&mut BinaryFactDict>,
    ) -> Self;

    async fn get_leaf(
        &self,
        ffc: FactCheckingContext<S>,
        index: FieldElement,
    ) -> Result<L, FactTreeError> {
        let leaves = self.get_leaves(ffc, vec![index], None).await;
        if leaves.keys().ne([index].iter()) {
            return Err(FactTreeError::UnexpectedResult(index));
        }

        // TODO: remove unwrap
        let leaf = *leaves.get(&index).unwrap();

        Ok(leaf)
    }
}
