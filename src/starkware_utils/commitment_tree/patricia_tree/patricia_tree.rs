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

impl<S, H, LF> BinaryFactTree<S, H, LF> for PatriciaTree
where
    S: Storage + 'static,
    H: HashFunctionType + Sync + Send + 'static,
    LF: LeafFact<S, H> + Send + 'static,
{
    async fn empty_tree(ffc: &mut FactFetchingContext<S, H>, height: Height, leaf_fact: LF) -> Result<Self, TreeError> {
        let empty_leaf_fact_hash = leaf_fact.set_fact(ffc).await?;
        Ok(Self { root: empty_leaf_fact_hash, height })
    }

    async fn get_leaves(
        &self,
        ffc: &mut FactFetchingContext<S, H>,
        indices: &[TreeIndex],
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<HashMap<TreeIndex, LF>, TreeError> {
        let virtual_root_node = VirtualPatriciaNode::from_hash(self.root.clone(), self.height);
        virtual_root_node._get_leaves(ffc, indices, facts).await
    }

    async fn update(
        &mut self,
        ffc: &mut FactFetchingContext<S, H>,
        modifications: Vec<(TreeIndex, LF)>,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Self, TreeError> {
        let virtual_root_node = VirtualPatriciaNode::from_hash(self.root.clone(), self.height);
        let updated_virtual_root_node = update_tree::<
            S,
            H,
            LF,
            VirtualPatriciaNode<S, H, LF>,
            VirtualCalculationNode<S, H, LF>,
        >(virtual_root_node, ffc, modifications, facts)
        .await?;

        // In case root is an edge node, its fact must be explicitly written to DB.
        let root_hash = updated_virtual_root_node.commit(ffc, facts).await?;
        Ok(Self { root: root_hash, height: updated_virtual_root_node.height })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};

    use assert_matches::assert_matches;
    use cairo_vm::Felt252;
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    use rand::seq::IteratorRandom;
    use rand::Rng;
    use rstest::{fixture, rstest};

    use super::*;
    use crate::crypto::pedersen::PedersenHash;
    use crate::starknet::starknet_storage::StorageLeaf;
    use crate::starkware_utils::commitment_tree::base_types::{Length, NodePath};
    use crate::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::Fact;
    use crate::storage::storage_utils::SimpleLeafFact;

    type StorageType = DictStorage;
    type HashFunction = PedersenHash;
    type FFC = FactFetchingContext<StorageType, HashFunction>;

    #[fixture]
    fn ffc() -> FFC {
        FactFetchingContext::<_, HashFunction>::new(DictStorage::default())
    }

    /// Binary node facts are simply the hash of the two children; edge node facts are the hash of
    /// the bottom node fact and the path, plus the path length.
    fn hash_preimage(preimage: &[BigUint]) -> BigUint {
        let hash = if preimage.len() == 2 {
            let node_fact =
                BinaryNodeFact::new(preimage[0].to_bytes_be().to_vec(), preimage[1].to_bytes_be().to_vec()).unwrap();
            <BinaryNodeFact as Fact<StorageType, HashFunction>>::hash(&node_fact)
        } else {
            let length = Length(preimage[0].to_u64().unwrap());
            let path = NodePath(preimage[1].clone());
            let bottom = preimage[2].to_bytes_be().to_vec();
            let node_fact = EdgeNodeFact::new(bottom, path, length).unwrap();
            <EdgeNodeFact as Fact<StorageType, HashFunction>>::hash(&node_fact)
        };

        BigUint::from_bytes_be(&hash)
    }

    /// Given a list of leaves and a collection of preimages, verifies that the preimages suffice to
    /// descend to all leaves.
    fn verify_leaves_are_reachable_from_root(root: BigUint, leaf_hashes: &[BigUint], preimages: BinaryFactDict) {
        let mut leaves_reached = HashSet::<BigUint>::new();
        let mut facts_to_open = VecDeque::new();
        facts_to_open.push_back(root);

        while let Some(next_fact) = facts_to_open.pop_front() {
            if leaf_hashes.contains(&next_fact) {
                leaves_reached.insert(next_fact);
                continue;
            }

            let preimage = preimages.get(&next_fact).unwrap();
            if preimage.len() == 3 {
                // Edge node. Next fact is the third entry.
                facts_to_open.push_back(preimage[2].clone());
            } else {
                let left_child = &preimage[0];
                let right_child = &preimage[1];
                facts_to_open.push_back(left_child.clone());
                facts_to_open.push_back(right_child.clone());
            }
        }

        let leaves_to_reach: HashSet<_> = leaf_hashes.iter().cloned().collect();
        assert_eq!(leaves_reached, leaves_to_reach);
    }

    #[rstest]
    #[tokio::test]
    async fn test_empty_tree(mut ffc: FFC) {
        let height = Height(10);

        let leaf_node = SimpleLeafFact::empty();

        let patricia_tree = PatriciaTree::empty_tree(&mut ffc, height, leaf_node).await.unwrap();
        assert_eq!(patricia_tree.root, EMPTY_NODE_HASH);
        assert_eq!(patricia_tree.height, height);
    }

    /// Builds a Patricia tree using update(), and tests that the facts stored suffice to decommit.
    #[rstest]
    #[case::full_tree_small(Height(2), 1 << 2)]
    #[case::full_tree_large(Height(10), 1 << 10)]
    #[case::sparse_tree(Height(10), 5)]
    #[case::dense_tree(Height(10), 1 << 9)]
    #[tokio::test]
    async fn test_update_and_decommit(mut ffc: FFC, #[case] height: Height, #[case] n_leaves: usize) {
        let mut rng = rand::thread_rng();

        let mut tree = PatriciaTree::empty_tree(&mut ffc, height, SimpleLeafFact::empty()).await.unwrap();

        // Create some random modifications, store the facts and update the tree.
        // Note that leaves with value 0 are not modifications (hence, range(1, ...)).
        let leaves: Vec<_> =
            (0..n_leaves).map(|_| rng.gen_range(1..=1000u64)).map(|x| SimpleLeafFact::new(Felt252::from(x))).collect();

        let mut leaf_hashes_bytes = vec![];
        for leaf_fact in leaves.iter() {
            let leaf_hash = leaf_fact.set_fact(&mut ffc).await.unwrap();
            leaf_hashes_bytes.push(leaf_hash);
        }
        let leaf_hashes: Vec<_> =
            leaf_hashes_bytes.iter().map(|leaf_hash_bytes| BigUint::from_bytes_be(leaf_hash_bytes)).collect();
        let indices: Vec<_> =
            (0u64..1 << height.0).choose_multiple(&mut rng, n_leaves).into_iter().map(BigUint::from).collect();
        let modifications: Vec<_> = indices.iter().cloned().zip(leaves.iter().cloned()).collect();
        let mut preimages = Some(BinaryFactDict::new());

        let tree = tree.update(&mut ffc, modifications, &mut preimages).await.unwrap();
        let root = BigUint::from_bytes_be(&tree.root);

        // Sanity check - the hash of the values should be the keys.
        let preimages = preimages.unwrap();
        for (fact, preimage) in preimages.iter() {
            let preimage_hash = hash_preimage(preimage);
            assert_eq!(fact, &preimage_hash);
        }

        // Verify that the root can be reached using the preimages, from every leaf.
        verify_leaves_are_reachable_from_root(root, &leaf_hashes, preimages);
    }

    /// A basic test to see if a leaf can be set and retrieved inside a tree.
    #[rstest]
    #[tokio::test]
    async fn test_update_and_get_leaf(mut ffc: FFC) {
        let mut tree = PatriciaTree::empty_tree(&mut ffc, Height(251), StorageLeaf::empty()).await.unwrap();

        let index = BigUint::from(1000u64);
        let leaf = StorageLeaf::new(Felt252::from(2000));
        let modifications = vec![(index.clone(), leaf.clone())];
        let mut facts = None;
        let tree = tree.update(&mut ffc, modifications, &mut facts).await.unwrap();

        let leaf_from_tree: Option<StorageLeaf> = tree.get_leaf(&mut ffc, index).await.unwrap();
        assert_matches!(leaf_from_tree, Some(l) if l == leaf);
    }
}
