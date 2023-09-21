use std::collections::HashMap;

use starknet::core::types::FieldElement;

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
    pub root: FieldElement,
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
        _indices: Vec<FieldElement>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, InnerNodeFact> {
        todo!()
    }

    async fn _get_leaves(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _indices: Vec<FieldElement>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, InnerNodeFact> {
        todo!()
    }

    async fn update(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _modifications: HashMap<FieldElement, InnerNodeFact>,
        _facts: Option<&mut BinaryFactDict>,
    ) -> Self {
        todo!()
    }

    async fn get_leaf(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _index: FieldElement,
    ) -> Result<InnerNodeFact, FactTreeError> {
        todo!()
    }
}
