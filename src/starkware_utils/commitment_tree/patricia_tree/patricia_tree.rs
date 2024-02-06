use std::collections::HashMap;

use crate::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use crate::starkware_utils::commitment_tree::binary_fact_tree::{BinaryFactDict, BinaryFactTree};
use crate::starkware_utils::commitment_tree::binary_fact_tree_node::BinaryFactTreeNode;
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::virtual_calculation_node::VirtualCalculationNode;
use crate::starkware_utils::commitment_tree::patricia_tree::virtual_patricia_node::VirtualPatriciaNode;
use crate::starkware_utils::commitment_tree::update_tree::update_tree;
use crate::storage::storage::{FactFetchingContext, HashFunctionType, Storage};

pub const EMPTY_NODE_HASH: [u8; 32] = [0; 32];

#[derive(Clone, Debug)]
pub struct PatriciaTree {
    pub root: Vec<u8>,
    pub height: Height,
}

impl<S, H, L> BinaryFactTree<S, H, L> for PatriciaTree
where
    S: Storage + 'static,
    H: HashFunctionType + Sync + Send + 'static,
    L: LeafFact<S, H> + Send + 'static,
{
    async fn empty_tree(ffc: &mut FactFetchingContext<S, H>, height: Height, leaf_fact: L) -> Result<Self, TreeError> {
        let empty_leaf_fact_hash = leaf_fact.set_fact(ffc).await?;
        Ok(Self { root: empty_leaf_fact_hash, height })
    }

    async fn get_leaves(
        &self,
        ffc: &mut FactFetchingContext<S, H>,
        indices: &[TreeIndex],
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<HashMap<TreeIndex, L>, TreeError> {
        let virtual_root_node = VirtualPatriciaNode::from_hash(self.root.clone(), self.height);
        virtual_root_node._get_leaves(ffc, indices, facts).await
    }

    async fn update(
        &mut self,
        ffc: &mut FactFetchingContext<S, H>,
        modifications: Vec<(TreeIndex, L)>,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Self, TreeError> {
        let virtual_root_node = VirtualPatriciaNode::from_hash(self.root.clone(), self.height);
        let updated_virtual_root_node = update_tree::<
            S,
            H,
            L,
            VirtualPatriciaNode<S, H, L>,
            VirtualCalculationNode<S, H, L>,
        >(virtual_root_node, ffc, modifications, facts)
        .await?;

        // In case root is an edge node, its fact must be explicitly written to DB.
        let root_hash = updated_virtual_root_node.commit(ffc, facts).await?;
        Ok(Self { root: root_hash, height: updated_virtual_root_node.height })
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;
    use crate::crypto::pedersen::PedersenHash;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage_utils::SimpleLeafFact;

    #[fixture]
    fn storage() -> impl Storage {
        DictStorage::default()
    }

    #[fixture]
    fn hash_function() -> impl HashFunctionType {
        PedersenHash
    }

    #[rstest]
    #[tokio::test]
    async fn test_empty_tree() {
        let height = Height(10);
        let mut ffc = FactFetchingContext::<_, PedersenHash>::new(DictStorage::default());

        let leaf_node = SimpleLeafFact::empty();

        let patricia_tree = PatriciaTree::empty_tree(&mut ffc, height, leaf_node).await.unwrap();
        assert_eq!(patricia_tree.root, EMPTY_NODE_HASH);
        assert_eq!(patricia_tree.height, height);
    }
}
