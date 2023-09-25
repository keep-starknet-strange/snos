use std::collections::HashMap;

use cairo_felt::Felt252;

use crate::{
    error::FactTreeError,
    storage::{FactCheckingContext, Storage},
    utils::hasher::HasherT,
};

use super::{
    binary_fact_tree::{BinaryFactDict, BinaryFactTree},
    nodes::InnerNodeFact,
};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PatriciaTree {
    pub root: Felt252,
    pub height: usize,
}

impl<S: Storage, H: HasherT> BinaryFactTree<S, H> for PatriciaTree {
    async fn empty_tree(
        &self,
        _ffc: FactCheckingContext<S, H>,
        _height: usize,
        _leaft_fact: InnerNodeFact,
    ) {
        todo!()
    }

    async fn get_leaves(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _indices: Vec<Felt252>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact> {
        todo!()
    }

    async fn _get_leaves(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _indices: Vec<Felt252>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact> {
        todo!()
    }

    async fn update(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _modifications: HashMap<Felt252, InnerNodeFact>,
        _facts: Option<&mut BinaryFactDict>,
    ) -> Self {
        todo!()
    }

    async fn get_leaf(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _index: Felt252,
    ) -> Result<InnerNodeFact, FactTreeError> {
        todo!()
    }
}
