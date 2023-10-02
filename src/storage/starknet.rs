use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

use cairo_felt::Felt252;

use crate::{
    error::CommitmentInfoError,
    utils::{
        commitment_tree::{
            binary_fact_tree::BinaryFactTree, nodes::InnerNodeFact, patricia_tree::PatriciaTree,
        },
        hasher::HasherT,
    },
};

use super::{FactCheckingContext, Storage};

type CommitmentFacts = HashMap<Felt252, Vec<Felt252>>;

#[derive(Serialize, Deserialize)]
pub struct CommitmentInfo<S: Storage, H: HasherT> {
    pub previous_root: Felt252,
    pub updated_root: Felt252,
    tree_height: usize,
    commitment_facts: CommitmentFacts,
    _phantom_storage: PhantomData<S>,
    _phantom_hasher: PhantomData<H>,
}

impl<S: Storage, H: HasherT> CommitmentInfo<S, H> {
    /// # Returns
    /// * `commitment_info` - Commitment information corresponding to the expected modifications
    /// and updated tree
    pub fn create_from_expected_updated_tree(
        &mut self,
        previous_tree: PatriciaTree,
        expected_updated_tree: PatriciaTree,
        expected_accessed_indices: Vec<Felt252>,
        ffc: FactCheckingContext<S, H>,
    ) -> Result<CommitmentInfo<S, H>, CommitmentInfoError> {
        if previous_tree.height != expected_updated_tree.height {
            return Err(CommitmentInfoError::InconsistentTreeHeights(
                previous_tree.height,
                expected_updated_tree.height,
            ));
        }

        let modifications: HashMap<Felt252, InnerNodeFact> =
            expected_updated_tree.get_leaves(&ffc, expected_accessed_indices, None);

        let commitment_info = self.create_from_modifications(
            previous_tree,
            expected_updated_tree.root,
            modifications,
            &ffc,
        )?;

        Ok(commitment_info)
    }

    /// # Returns
    /// * `commitment_info` - Commitment information corresponding to the given modifications.
    pub fn create_from_modifications(
        &mut self,
        previous_tree: PatriciaTree,
        expected_updated_root: Felt252,
        modifications: HashMap<Felt252, InnerNodeFact>,
        ffc: &FactCheckingContext<S, H>,
    ) -> Result<CommitmentInfo<S, H>, CommitmentInfoError> {
        let mut commitment_facts = CommitmentFacts::new();
        let actual_updated_tree =
            previous_tree.update(ffc, modifications, Some(&mut commitment_facts));
        let actual_updated_root: Felt252 = actual_updated_tree.root;

        if actual_updated_root != expected_updated_root {
            return Err(CommitmentInfoError::InconsistentTreeRoots(
                actual_updated_root,
                expected_updated_root,
            ));
        }

        Ok(Self {
            previous_root: previous_tree.root,
            updated_root: actual_updated_root,
            tree_height: previous_tree.height,
            commitment_facts,
            _phantom_storage: PhantomData,
            _phantom_hasher: PhantomData,
        })
    }
}

// impl DBObject for ContractState {
//     fn db_key(suffix: Vec<u8>) -> Vec<u8> {
//         let prefix: &[u8] = b"contract_state";
//         let sep: &[u8] = b":";

//         [prefix, sep, suffix.as_slice()].concat()
//     }
// }
