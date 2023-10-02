use std::collections::HashMap;

use cairo_felt::Felt252;

use crate::{
    error::FactTreeError,
    storage::{FactCheckingContext, Storage},
    utils::hasher::HasherT,
};

use super::{
    binary_fact_tree::{BinaryFactDict, BinaryFactTree},
    nodes::{InnerNodeFact, EMPTY_NODE_HASH},
};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PatriciaTree {
    pub root: Felt252,
    pub height: usize,
}

impl<S: Storage, H: HasherT> BinaryFactTree<S, H> for PatriciaTree {
    fn empty_tree(
        &self,
        _ffc: FactCheckingContext<S, H>,
        height: usize,
        leaft_fact: InnerNodeFact,
    ) -> Self {
        assert!(matches!(leaft_fact, InnerNodeFact::Empty(EmptyNode)));

        Self {
            root: Felt252::from_bytes_be(&EMPTY_NODE_HASH[..]),
            height,
        }
    }

    fn get_leaves(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _indices: Vec<Felt252>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact> {
        todo!()
    }

    fn _get_leaves(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _indices: Vec<Felt252>,
        _facts: Option<BinaryFactDict>,
    ) -> HashMap<Felt252, InnerNodeFact> {
        todo!()
    }

    fn update(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _modifications: HashMap<Felt252, InnerNodeFact>,
        _facts: Option<&mut BinaryFactDict>,
    ) -> Self {
        todo!()
    }

    fn get_leaf(
        &self,
        _ffc: &FactCheckingContext<S, H>,
        _index: Felt252,
    ) -> Result<InnerNodeFact, FactTreeError> {
        todo!()
    }
}
