use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use starknet::core::types::FieldElement;

use crate::{
    error::CommitmentInfoError,
    utils::commitment_tree::{
        binary_fact_tree::BinaryFactTree, leaf_fact::LeafFact, patricia_tree::PatriciaTree,
    },
};

use super::{FactCheckingContext, Storage};

type CommitmentFacts = HashMap<FieldElement, Vec<FieldElement>>;

#[derive(Serialize, Deserialize)]
pub struct CommitmentInfo {
    previous_root: FieldElement,
    updated_root: FieldElement,
    tree_height: usize,
    commitment_facts: CommitmentFacts,
}

impl CommitmentInfo {
    /// # Returns
    /// * `commitment_info` - Commitment information corresponding to the expected modifications
    /// and updated tree
    pub async fn create_from_expected_updated_tree<S: Storage, L: LeafFact>(
        &mut self,
        previous_tree: PatriciaTree,
        expected_updated_tree: PatriciaTree,
        expected_accessed_indices: Vec<FieldElement>,
        _leaft_fact_type: L,
        ffc: FactCheckingContext<S>,
    ) -> Result<CommitmentInfo, CommitmentInfoError> {
        if previous_tree.height != expected_updated_tree.height {
            return Err(CommitmentInfoError::InconsistentTreeHeights(
                previous_tree.height,
                expected_updated_tree.height,
            ));
        }

        let modifications: HashMap<FieldElement, L> = expected_updated_tree
            .get_leaves(ffc.clone(), expected_accessed_indices, None)
            .await;

        let commitment_info = self
            .create_from_modifications(
                previous_tree,
                expected_updated_tree.root,
                modifications,
                ffc,
            )
            .await?;

        Ok(commitment_info)
    }

    /// # Returns
    /// * `commitment_info` - Commitment information corresponding to the given modifications.
    pub async fn create_from_modifications<S: Storage, L: LeafFact>(
        &mut self,
        previous_tree: PatriciaTree,
        expected_updated_root: FieldElement,
        modifications: HashMap<FieldElement, L>,
        ffc: FactCheckingContext<S>,
    ) -> Result<CommitmentInfo, CommitmentInfoError> {
        let mut commitment_facts = CommitmentFacts::new();
        let actual_updated_tree = previous_tree
            .update(ffc, modifications, Some(&mut commitment_facts))
            .await;
        let actual_updated_root: FieldElement = actual_updated_tree.root.into();

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
        })
    }
}
