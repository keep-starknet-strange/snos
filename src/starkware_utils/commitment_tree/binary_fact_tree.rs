use std::collections::HashMap;

use cairo_vm::Felt252;
use num_bigint::BigUint;

use crate::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::storage::storage::{FactFetchingContext, HashFunctionType, Storage};

pub trait Leaf: Clone {}

pub type BinaryFactDict = HashMap<BigUint, Vec<BigUint>>;

/// Converts a BinaryFactDict from maps of BigUints to Felt252s.
pub fn binary_fact_dict_to_felts(binary_fact_dict: BinaryFactDict) -> HashMap<Felt252, Vec<Felt252>> {
    binary_fact_dict
        .into_iter()
        .map(|(key, values)| (Felt252::from(key), values.into_iter().map(Felt252::from).collect()))
        .collect()
}

/// An abstract base class for Merkle and Patricia-Merkle tree.
/// An immutable binary tree backed by an immutable fact storage.
#[allow(async_fn_in_trait)]
pub trait BinaryFactTree<S, H, LF>: Sized
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    /// Initializes an empty BinaryFactTree of the given height.
    async fn empty_tree(ffc: &mut FactFetchingContext<S, H>, height: Height, leaf_fact: LF) -> Result<Self, TreeError>;

    /// Returns the values of the leaves whose indices are given.
    async fn get_leaves(
        &self,
        ffc: &mut FactFetchingContext<S, H>,
        indices: &[TreeIndex],
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<HashMap<TreeIndex, LF>, TreeError>;

    async fn get_leaf(&self, ffc: &mut FactFetchingContext<S, H>, index: TreeIndex) -> Result<Option<LF>, TreeError> {
        let mut facts = None;
        let leaves = self.get_leaves(ffc, vec![index.clone()].as_ref(), &mut facts).await?;
        Ok(leaves.get(&index).cloned())
    }

    /// Updates the tree with the given list of modifications, writes all the new facts to the
    /// storage and returns a new BinaryFactTree representing the fact of the root of the new tree.
    ///
    /// If facts argument is not None, this dictionary is filled during traversal through the tree
    /// by the facts of their paths from the leaves up.
    async fn update(
        &mut self,
        ffc: &mut FactFetchingContext<S, H>,
        modifications: Vec<(TreeIndex, LF)>,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Self, TreeError>;
}
