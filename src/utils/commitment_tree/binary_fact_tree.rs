use std::collections::HashMap;

use cairo_felt::Felt252;

use crate::{
    error::FactTreeError,
    storage::{FactCheckingContext, Storage},
    utils::hasher::HasherT,
};

use super::nodes::InnerNodeFact;

pub type BinaryFactDict = HashMap<Felt252, Vec<Felt252>>;

pub trait BinaryFactTree<S: Storage, H: HasherT>
where
    Self: Sized,
{
    /// Initializes an empty BinaryFactTree of the given height.
    fn empty_tree(&self, ffc: FactCheckingContext<S, H>, height: usize, leaft_fact: InnerNodeFact);
    /// Returns the values of the leaves whose indices are given.
    fn get_leaves(
        &self,
        ffc: &FactCheckingContext<S, H>,
        indices: Vec<Felt252>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact>;

    fn _get_leaves(
        &self,
        ffc: &FactCheckingContext<S, H>,
        indices: Vec<Felt252>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact>;

    fn update(
        &self,
        ffc: &FactCheckingContext<S, H>,
        modifications: HashMap<Felt252, InnerNodeFact>,
        facts: Option<&mut BinaryFactDict>,
    ) -> Self;

    fn get_leaf(
        &self,
        ffc: &FactCheckingContext<S, H>,
        index: Felt252,
    ) -> Result<InnerNodeFact, FactTreeError> {
        let leaves = self.get_leaves(ffc, vec![index.clone()], None);
        if leaves.keys().ne([index.clone()].iter()) {
            return Err(FactTreeError::UnexpectedResult(index));
        }

        // TODO: remove unwrap
        let leaf = leaves.get(&index).unwrap().clone();

        Ok(leaf)
    }
}
