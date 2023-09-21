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
    async fn empty_tree(&self, ffc: FactCheckingContext<S>, height: usize, leaft_fact: L) {
        todo!()
    }

    async fn get_leaves(
        &self,
        ffc: FactCheckingContext<S>,
        indices: Vec<FieldElement>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, L> {
        todo!()
    }

    async fn _get_leaves(
        &self,
        ffc: FactCheckingContext<S>,
        indices: Vec<FieldElement>,
        facts: Option<BinaryFactDict>,
    ) -> HashMap<FieldElement, L> {
        todo!()
    }

    async fn update(
        &self,
        ffc: FactCheckingContext<S>,
        modifications: HashMap<FieldElement, L>,
        facts: Option<&mut BinaryFactDict>,
    ) -> Self {
        todo!()
    }

    async fn get_leaf(
        &self,
        ffc: FactCheckingContext<S>,
        index: FieldElement,
    ) -> Result<L, FactTreeError> {
        todo!()
    }
}
