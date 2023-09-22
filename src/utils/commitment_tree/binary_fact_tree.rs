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
        indices: Vec<Felt252>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact>;

    async fn _get_leaves(
        &self,
        ffc: &FactCheckingContext<S, H>,
        indices: Vec<Felt252>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact>;

    async fn update(
        &self,
        ffc: &FactCheckingContext<S, H>,
        modifications: HashMap<Felt252, InnerNodeFact>,
        facts: Option<&mut BinaryFactDict>,
    ) -> Self;

    async fn get_leaf(
        &self,
        ffc: &FactCheckingContext<S, H>,
        index: Felt252,
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
