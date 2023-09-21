use std::collections::HashMap;

use starknet::core::types::FieldElement;

use crate::{
    error::FactTreeError,
    storage::{FactCheckingContext, Storage},
};

use super::{
    binary_fact_tree::{BinaryFactDict, BinaryFactTree},
    leaf_fact::LeafFact,
};

pub struct PatriciaTree {
    pub root: FieldElement,
    pub height: usize,
}

impl<S: Storage, L: LeafFact> BinaryFactTree<S, L> for PatriciaTree {
    async fn empty_tree(&self, _ffc: FactCheckingContext<S>, _height: usize, _leaft_fact: L) {
        todo!()
    }

    async fn get_leaves(
        &self,
        _ffc: FactCheckingContext<S>,
        _indices: Vec<FieldElement>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, L> {
        todo!()
    }

    async fn _get_leaves(
        &self,
        _ffc: FactCheckingContext<S>,
        _indices: Vec<FieldElement>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, L> {
        todo!()
    }

    async fn update(
        &self,
        _ffc: FactCheckingContext<S>,
        _modifications: HashMap<FieldElement, L>,
        _facts: Option<&mut BinaryFactDict>,
    ) -> Self {
        todo!()
    }

    async fn get_leaf(
        &self,
        _ffc: FactCheckingContext<S>,
        _index: FieldElement,
    ) -> Result<L, FactTreeError> {
        todo!()
    }
}
