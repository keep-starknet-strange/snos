use std::cmp::PartialEq;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::Deref;

use futures::future::FutureExt;
use num_bigint::BigUint;
use starknet_os_types::hash::Hash;

use crate::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath, TreeIndex};
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactDict;
use crate::starkware_utils::commitment_tree::binary_fact_tree_node::{
    read_node_fact, write_node_fact, BinaryFactTreeNode,
};
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::nodes::{
    verify_path_value, EdgeNodeFact, PatriciaNodeFact,
};
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::EMPTY_NODE_HASH;
use crate::storage::storage::{FactFetchingContext, HashFunctionType, Storage};

#[derive(Debug)]
pub struct VirtualPatriciaNode<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    pub bottom_node: Hash,
    pub path: NodePath,
    pub length: Length,
    /// The height of the subtree rooted at this node.
    /// In other words, this is the length of the path from this node to the leaves.
    pub height: Height,

    _phantom: PhantomData<(S, H, LF)>,
}

impl<S, H, LF> VirtualPatriciaNode<S, H, LF>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
{
    #[allow(unused)]
    pub fn new(bottom_node: Hash, path: NodePath, length: Length, height: Height) -> Result<Self, TreeError> {
        verify_path_value(&path, length)?;
        Ok(Self::new_unchecked(bottom_node, path, length, height))
    }

    pub fn new_unchecked(bottom_node: Hash, path: NodePath, length: Length, height: Height) -> Self {
        debug_assert!(verify_path_value(&path, length).is_ok());
        Self { bottom_node, path: path.clone(), length, height, _phantom: Default::default() }
    }

    fn empty_node(height: Height) -> Self {
        Self {
            bottom_node: Hash::empty(),
            path: NodePath(0u64.into()),
            length: Length(0),
            height,
            _phantom: Default::default(),
        }
    }

    pub fn from_hash(hash_value: Hash, height: Height) -> Self {
        Self::new_unchecked(hash_value, NodePath(0u64.into()), Length(0), height)
    }

    fn is_empty(&self) -> bool {
        self.bottom_node == EMPTY_NODE_HASH
    }

    fn is_virtual_edge(&self) -> bool {
        self.length.0 != 0
    }

    /// Calculates and returns the hash of self.
    /// If this is a virtual edge node, an edge node fact is written to the DB.
    pub async fn commit(
        &self,
        ffc: &mut FactFetchingContext<S, H>,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Hash, TreeError> {
        if !self.is_virtual_edge() {
            // Node is already of form (hash, 0, 0); no work to be done.
            return Ok(self.bottom_node);
        }

        let edge_node_fact = EdgeNodeFact::new(self.bottom_node, self.path.clone(), self.length)?;

        let hash = write_node_fact(ffc, edge_node_fact, facts).await?;
        Ok(hash)
    }

    /// Returns the children of a virtual edge node: an empty node and a shorter-by-one virtual
    /// edge node, according to the direction embedded in the edge path.
    fn get_virtual_edge_node_children(&self) -> Result<(Self, Self), TreeError> {
        let children_height = self.height - 1;
        let children_length = self.length - 1;

        // Turn the MSB off.
        let path = NodePath(self.path.0.clone() & ((BigUint::from(1u64) << children_length.0) - BigUint::from(1u64)));
        let non_empty_child =
            VirtualPatriciaNode::new_unchecked(self.bottom_node, path, children_length, children_height);

        let edge_child_direction = self.path.0.clone() >> children_length.0;
        let empty_child = Self::empty_node(children_height);
        if edge_child_direction == BigUint::from(0u64) {
            // Non-empty on the left
            Ok((non_empty_child, empty_child))
        } else {
            // Non-empty on the right
            Ok((empty_child, non_empty_child))
        }
    }

    async fn read_bottom_node_fact(
        &self,
        ffc: &mut FactFetchingContext<S, H>,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<PatriciaNodeFact, TreeError> {
        let node_fact = read_node_fact::<S, H, PatriciaNodeFact>(ffc, &self.bottom_node, facts).await?;
        Ok(node_fact)
    }

    /// Returns the values of the leaves whose indices are given.
    async fn get_edge_node_leaves(
        &self,
        ffc: &mut FactFetchingContext<S, H>,
        indices: &[TreeIndex],
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<HashMap<TreeIndex, LF>, TreeError> {
        // Partition indices.
        let path_suffix_width = self.height.0 - self.length.0;
        let path_prefix = self.path.0.clone() << path_suffix_width;
        let (bottom_subtree_indices, empty_indices) = {
            let mut bottom_indices = vec![];
            let mut empty_indices = vec![];
            for index in indices.iter().cloned().map(BigUint::from) {
                if index.clone() >> path_suffix_width == self.path.0 {
                    bottom_indices.push(index - &path_prefix);
                } else {
                    empty_indices.push(index);
                }
            }
            (bottom_indices, empty_indices)
        };

        // Get bottom subtree root.
        let bottom_subtree_root = Self::from_hash(self.bottom_node, Height(path_suffix_width));
        let bottom_subtree_leaves = bottom_subtree_root._get_leaves(ffc, &bottom_subtree_indices, facts).await?;
        let empty_leaves = get_empty_leaves(ffc, &empty_indices).await?;

        Ok(unify_edge_leaves(path_prefix, empty_leaves, bottom_subtree_leaves))
    }
}

impl<S, H, LF> PartialEq for VirtualPatriciaNode<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    fn eq(&self, other: &Self) -> bool {
        self.bottom_node == other.bottom_node
            && self.path == other.path
            && self.length == other.length
            && self.height == other.height
    }
}

impl<S, H, LF> Clone for VirtualPatriciaNode<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    fn clone(&self) -> Self {
        Self {
            bottom_node: self.bottom_node,
            path: self.path.clone(),
            length: self.length,
            height: self.height,
            _phantom: Default::default(),
        }
    }
}

impl<S, H, LF> BinaryFactTreeNode<S, H, LF> for VirtualPatriciaNode<S, H, LF>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
{
    fn _leaf_hash(&self) -> Hash {
        self.bottom_node
    }

    fn get_height_in_tree(&self) -> Height {
        self.height
    }

    fn create_leaf(hash_value: Hash) -> Self {
        Self::from_hash(hash_value, Height(0))
    }

    /// Returns the two VirtualPatriciaNode objects which are the subtrees of the current
    /// VirtualPatriciaNode.
    ///
    /// If facts argument is not None, this dictionary is filled with facts read from the DB.
    fn get_children<'a>(
        &'a self,
        ffc: &'a mut FactFetchingContext<S, H>,
        facts: &'a mut Option<BinaryFactDict>,
    ) -> impl std::future::Future<Output = Result<(Self, Self), TreeError>> + Send {
        async move {
            if self.is_leaf() {
                return Err(TreeError::IsLeaf);
            }
            let children_height = self.height - 1;
            if self.is_empty() {
                let empty_child = Self::empty_node(children_height);
                return Ok((empty_child.clone(), empty_child));
            }

            if self.is_virtual_edge() {
                return self.get_virtual_edge_node_children();
            }

            // At this point the preimage of self.bottom_node must be read from the storage, to know
            // what kind of node it represents - a committed edge node, or a binary node.
            let fact = self.read_bottom_node_fact(ffc, facts).await?;

            match fact {
                PatriciaNodeFact::Edge(edge_node_fact) => {
                    // A previously committed edge node.
                    let edge_node = Self::new_unchecked(
                        edge_node_fact.bottom_node,
                        edge_node_fact.edge_path,
                        edge_node_fact.edge_length,
                        self.height,
                    );
                    edge_node.get_virtual_edge_node_children()
                }
                PatriciaNodeFact::Binary(binary_node_fact) => Ok((
                    Self::from_hash(binary_node_fact.left_node, children_height),
                    Self::from_hash(binary_node_fact.right_node, children_height),
                )),
            }
        }
        .boxed()
    }

    fn _get_leaves<'a>(
        &'a self,
        ffc: &'a mut FactFetchingContext<S, H>,
        indices: &'a [TreeIndex],
        facts: &'a mut Option<BinaryFactDict>,
    ) -> impl std::future::Future<Output = Result<HashMap<TreeIndex, LF>, TreeError>> + std::marker::Send {
        async move {
            if indices.is_empty() {
                return Ok(HashMap::new());
            }

            if self.is_empty() {
                return get_empty_leaves(ffc, indices).await;
            }

            if self.is_leaf() {
                return self._get_leaf(ffc, indices).await;
            }

            if self.is_virtual_edge() {
                return self.get_edge_node_leaves(ffc, indices, facts).await;
            }

            self._get_binary_node_leaves(ffc, indices, facts).await
        }
        .boxed()
    }
}

async fn get_empty_leaves<S, H, LF>(
    ffc: &mut FactFetchingContext<S, H>,
    indices: &[TreeIndex],
) -> Result<HashMap<TreeIndex, LF>, TreeError>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    if indices.is_empty() {
        return Ok(HashMap::new());
    }

    let storage = ffc.acquire_storage().await;
    let empty_leaf = LF::get_or_fail(storage.deref(), EMPTY_NODE_HASH.as_ref()).await?;
    let result: HashMap<_, LF> = indices.iter().map(|index| (index.clone(), empty_leaf.clone())).collect();
    Ok(result)
}

fn unify_edge_leaves<S, H, LF>(
    path_prefix: BigUint,
    empty_leaves: HashMap<TreeIndex, LF>,
    bottom_subtree_leaves: HashMap<TreeIndex, LF>,
) -> HashMap<TreeIndex, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    let mut edge_leaves = empty_leaves;
    for (index, leaf_fact) in bottom_subtree_leaves.into_iter() {
        edge_leaves.insert(index + &path_prefix, leaf_fact);
    }

    edge_leaves
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cairo_vm::Felt252;
    use rand::seq::SliceRandom;
    use rand::Rng;
    use rstest::{fixture, rstest};

    use super::*;
    use crate::crypto::pedersen::PedersenHash;
    use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
    use crate::starkware_utils::commitment_tree::binary_fact_tree_node::BinaryFactTreeNodeDiff;
    use crate::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
    use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
    use crate::starkware_utils::commitment_tree::patricia_tree::patricia_utils::compute_patricia_from_leaves_for_test;
    use crate::starkware_utils::commitment_tree::patricia_tree::virtual_calculation_node::VirtualCalculationNode;
    use crate::starkware_utils::commitment_tree::update_tree::update_tree;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::{Fact, FactFetchingContext};
    use crate::storage::storage_utils::SimpleLeafFact;

    type StorageType = DictStorage;
    type HashFunction = PedersenHash;
    type LeafFactType = SimpleLeafFact;
    #[allow(clippy::upper_case_acronyms)]
    type FFC = FactFetchingContext<StorageType, HashFunction>;
    #[allow(clippy::upper_case_acronyms)]
    type VPN = VirtualPatriciaNode<DictStorage, HashFunction, LeafFactType>;
    #[allow(clippy::upper_case_acronyms)]
    type VCN = VirtualCalculationNode<StorageType, HashFunction, LeafFactType>;

    #[fixture]
    fn ffc() -> FFC {
        FactFetchingContext::<_, HashFunction>::new(DictStorage::default())
    }

    /// Returns the non-canonical form (hash, 0, 0) of a virtual edge node.
    async fn make_virtual_edge_non_canonical(ffc: &mut FFC, node: &VPN) -> VPN {
        assert!(node.is_virtual_edge(), "Node should be of canonical form.");

        let mut facts = None;
        let node_hash = node.commit(ffc, &mut facts).await.unwrap();
        VPN::from_hash(node_hash, node.height)
    }

    fn verify_root(leaves: &[Felt252], expected_root_hash: &[u8]) -> Result<(), ()> {
        let (root_hash, _preimage, _node_at_path) = compute_patricia_from_leaves_for_test::<HashFunction>(leaves);
        let root_hash_bytes = root_hash.to_bytes_be();

        println!("{}", root_hash.to_biguint());

        if root_hash_bytes == expected_root_hash {
            Ok(())
        } else {
            Err(())
        }
    }

    async fn build_empty_patricia_virtual_node(ffc: &mut FFC, height: Height) -> VPN {
        // Done manually, since PatriciaTree.empty() is in charge of that and is not used here.
        SimpleLeafFact::empty().set_fact(ffc).await.unwrap();

        // Build empty tree.
        VirtualPatriciaNode::empty_node(height)
    }

    async fn build_patricia_virtual_node(
        ffc: &mut FFC,
        height: Height,
        leaves: HashMap<TreeIndex, SimpleLeafFact>,
    ) -> VPN {
        let tree = build_empty_patricia_virtual_node(ffc, height).await;
        let modifications: Vec<_> = leaves.into_iter().collect();

        let mut facts = None;
        update_tree::<StorageType, HashFunction, LeafFactType, VPN, VCN>(tree, ffc, modifications, &mut facts)
            .await
            .unwrap()
    }

    async fn sample_and_verify_leaf_values(
        ffc: &mut FFC,
        tree: &VPN,
        expected_leaves: &HashMap<TreeIndex, LeafFactType>,
    ) {
        let sampled_indices: Vec<_> = expected_leaves.keys().cloned().collect();
        let mut facts = None;
        let actual_leaves = tree._get_leaves(ffc, &sampled_indices, &mut facts).await.unwrap();

        println!("Expected:");
        for (i, lf) in expected_leaves {
            println!("{i}: {}", lf.value.to_biguint());
        }

        println!("Actual:");
        for (i, lf) in &actual_leaves {
            println!("{i}: {}", lf.value.to_biguint());
        }
        assert_eq!(&actual_leaves, expected_leaves);
    }

    /// Builds a Patricia tree of length 3 with the following values in the leaves:
    /// 1 -> 12, 6 -> 30. This is done using only "low-level" VirtualPatriciaNode methods,
    /// without _update().
    ///            0
    ///      0           0
    ///   0     0     0     0
    /// 0  12 0   0 0   0 30  0
    #[rstest]
    #[tokio::test]
    async fn test_get_children(mut ffc: FFC) {
        let empty_tree_0 = build_empty_patricia_virtual_node(&mut ffc, Height(0)).await;
        let empty_tree_1 = build_empty_patricia_virtual_node(&mut ffc, Height(1)).await;

        let mut facts = None;
        let empty_tree_1_children = empty_tree_1.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(empty_tree_1_children, (empty_tree_0.clone(), empty_tree_0.clone()));

        // Create leaves and write their facts to DB.
        let leaf_hash_12 = SimpleLeafFact::new(Felt252::from(12)).set_fact(&mut ffc).await.unwrap();
        let leaf_hash_30 = SimpleLeafFact::new(Felt252::from(30)).set_fact(&mut ffc).await.unwrap();

        let leaf_12 = VPN::new(leaf_hash_12, NodePath(0u64.into()), Length(0), Height(0)).unwrap();
        let leaf_30 = VPN::new(leaf_hash_30, NodePath(0u64.into()), Length(0), Height(0)).unwrap();

        // Build left subtree and write its fact to DB.
        EdgeNodeFact::new(leaf_hash_12, NodePath(1u64.into()), Length(1)).unwrap().set_fact(&mut ffc).await.unwrap();
        let left_tree_1 = VPN::new(leaf_hash_12, NodePath(1u64.into()), Length(1), Height(1)).unwrap();

        let expected_children = (empty_tree_0.clone(), leaf_12.clone());
        let left_tree_1_children = left_tree_1.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(left_tree_1_children, expected_children);

        let non_canonical_node = make_virtual_edge_non_canonical(&mut ffc, &left_tree_1).await;
        let non_canonical_node_children = non_canonical_node.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(non_canonical_node_children, expected_children);

        // Combine left edge node and right empty tree. Write the result's fact to DB.
        EdgeNodeFact::new(leaf_hash_12, NodePath(0b01u64.into()), Length(2)).unwrap().set_fact(&mut ffc).await.unwrap();
        let left_tree_2 = VPN::new(leaf_hash_12, NodePath(0b01u64.into()), Length(2), Height(2)).unwrap();
        // Get children on both forms.
        let expected_children = (left_tree_1.clone(), empty_tree_1.clone());
        let left_tree_2_children = left_tree_2.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(left_tree_2_children, expected_children);
        let non_canonical_node = make_virtual_edge_non_canonical(&mut ffc, &left_tree_2).await;
        let non_canonical_node_children = non_canonical_node.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(non_canonical_node_children, expected_children);

        // Build right subtree.
        // Combine left leaf and right empty tree. Write the result's fact to DB.
        EdgeNodeFact::new(leaf_hash_30, NodePath(0u64.into()), Length(1)).unwrap().set_fact(&mut ffc).await.unwrap();
        let right_tree_1 = VPN::new(leaf_hash_30, NodePath(0u64.into()), Length(1), Height(1)).unwrap();
        // Get children on both forms.
        let expected_children = (leaf_30.clone(), empty_tree_0.clone());
        let right_tree_1_children = right_tree_1.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(right_tree_1_children, expected_children);
        let non_canonical_node = make_virtual_edge_non_canonical(&mut ffc, &right_tree_1).await;
        let non_canonical_node_children = non_canonical_node.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(non_canonical_node_children, expected_children);

        EdgeNodeFact::new(leaf_hash_30, NodePath(0b10u64.into()), Length(2)).unwrap().set_fact(&mut ffc).await.unwrap();
        let right_tree_2 = VPN::new(leaf_hash_30, NodePath(0b10u64.into()), Length(2), Height(2)).unwrap();
        // Get children on both forms.
        let expected_children = (empty_tree_1.clone(), right_tree_1.clone());
        let right_tree_2_children = right_tree_2.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(right_tree_2_children, expected_children);
        let non_canonical_node = make_virtual_edge_non_canonical(&mut ffc, &right_tree_2).await;
        let non_canonical_node_children = non_canonical_node.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(non_canonical_node_children, expected_children);

        // Build whole tree and write its fact to DB.
        let left_node = left_tree_2.commit(&mut ffc, &mut facts).await.unwrap();
        let right_node = right_tree_2.commit(&mut ffc, &mut facts).await.unwrap();
        let root_hash = BinaryNodeFact::new(left_node, right_node).unwrap().set_fact(&mut ffc).await.unwrap();

        let tree = VPN::new(root_hash, NodePath(0u64.into()), Length(0), Height(3)).unwrap();
        let (left_edge_child, right_edge_child) = tree.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(left_edge_child, VPN::new(left_node, NodePath(0u64.into()), Length(0), Height(2)).unwrap());
        assert_eq!(right_edge_child, VPN::new(right_node, NodePath(0u64.into()), Length(0), Height(2)).unwrap());

        // Test operations on the committed left tree.
        // Getting its children should return another edge with length shorter-by-one.
        let left_edge_child_children = left_edge_child.get_children(&mut ffc, &mut facts).await.unwrap();
        assert_eq!(left_edge_child_children, (left_tree_1, empty_tree_1));
    }

    /// Builds a Patricia tree of length 3 with the following values in the leaves:
    /// 1 -> 12, 6 -> 30. This is the same tree as in the test above,
    /// but in this test built using _update().
    #[rstest]
    #[tokio::test]
    async fn test_update_and_get_leaves(mut ffc: FFC) {
        // Build empty tree.
        let tree = build_empty_patricia_virtual_node(&mut ffc, Height(3)).await;

        // Compare empty root to test util result.
        let n_leaves = 8u64;
        let leaves = vec![Felt252::ZERO; n_leaves as usize];
        verify_root(&leaves, &tree.bottom_node).unwrap();

        // Update leaf values.
        let leaves = HashMap::from([
            (BigUint::from(1u64), SimpleLeafFact::new(Felt252::from(12))),
            (BigUint::from(1u64), SimpleLeafFact::new(Felt252::from(1000))),
            (BigUint::from(6u64), SimpleLeafFact::new(Felt252::from(30))),
        ]);

        let mut facts = None;
        let modifications: Vec<_> = leaves.clone().into_iter().collect();
        let tree =
            update_tree::<StorageType, HashFunction, LeafFactType, VPN, VCN>(tree, &mut ffc, modifications, &mut facts)
                .await
                .unwrap();

        // Check get_leaves().
        let expected_leaves: HashMap<_, _> = (0..n_leaves)
            .map(BigUint::from)
            .map(|leaf_id| (leaf_id.clone(), leaves.get(&leaf_id).cloned().unwrap_or(SimpleLeafFact::empty())))
            .collect();

        sample_and_verify_leaf_values(&mut ffc, &tree, &expected_leaves).await;

        // Compare to test util result.
        let verify_root_leaves: Vec<_> =
            (0..n_leaves).map(|key| expected_leaves.get(&BigUint::from(key)).unwrap().value).collect();
        verify_root(&verify_root_leaves, &tree.bottom_node).unwrap();

        // Update leaf values again: new leaves contain addition, deletion and updating a key.
        let updated_leaves = HashMap::from([
            (BigUint::from(0u64), SimpleLeafFact::new(Felt252::from(2))),
            (BigUint::from(1u64), SimpleLeafFact::new(Felt252::from(20))),
            (BigUint::from(3u64), SimpleLeafFact::new(Felt252::from(6))),
            (BigUint::from(6u64), SimpleLeafFact::empty()),
        ]);

        let modifications: Vec<_> = updated_leaves.clone().into_iter().collect();
        let tree =
            update_tree::<StorageType, HashFunction, LeafFactType, VPN, VCN>(tree, &mut ffc, modifications, &mut facts)
                .await
                .unwrap();

        let updated_leaves = {
            let mut expected_leaves = expected_leaves;
            expected_leaves.extend(updated_leaves);
            expected_leaves
        };

        sample_and_verify_leaf_values(&mut ffc, &tree, &updated_leaves).await;

        let sorted_by_index_leaf_values: Vec<_> =
            (0..n_leaves).map(BigUint::from).map(|key| updated_leaves[&key].value).collect();
        let expected_root_hash = tree.commit(&mut ffc, &mut facts).await.unwrap();
        verify_root(&sorted_by_index_leaf_values, &expected_root_hash).unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_binary_fact_tree_node_create_diff(mut ffc: FFC) {
        let mut facts = None;
        let empty_tree = PatriciaTree::empty_tree(&mut ffc, Height(251), SimpleLeafFact::empty()).await.unwrap();
        let virtual_empty_tree_node = VPN::from_hash(empty_tree.root, empty_tree.height);

        // All tree values are zero except for the fifth leaf, which has a value of 8.
        let modifications = vec![(BigUint::from(5u64), SimpleLeafFact::new(Felt252::from(8)))];
        let one_change_tree = empty_tree.clone().update(&mut ffc, modifications, &mut facts).await.unwrap();
        let virtual_one_change_node = VPN::from_hash(one_change_tree.root, empty_tree.height);

        // All tree values are zero except for the fifth leaf, which has a value of 8.
        // and the 58th leaf, which is 81.
        let modifications = vec![(BigUint::from(58u64), SimpleLeafFact::new(Felt252::from(81)))];
        let two_change_tree = one_change_tree.update(&mut ffc, modifications, &mut facts).await.unwrap();
        let virtual_two_change_node = VPN::from_hash(two_change_tree.root, empty_tree.height);

        // The difference between the tree whose values are all zero and the tree that has
        // all values zero except two values is exactly the 2 values.
        let expected_diff = vec![
            BinaryFactTreeNodeDiff::new(5, SimpleLeafFact::empty(), SimpleLeafFact::new(Felt252::from(8))),
            BinaryFactTreeNodeDiff::new(58, SimpleLeafFact::empty(), SimpleLeafFact::new(Felt252::from(81))),
        ];
        let diff_result = {
            virtual_empty_tree_node
                .get_diff_between_trees(virtual_two_change_node.clone(), &mut ffc, &mut facts)
                .await
                .unwrap()
        };
        assert_eq!(diff_result, expected_diff);

        // The difference between the tree whose values are zero except for the fifth leaf
        // and the tree whose values are all zero except for the fifth leaf (there they are equal)
        // and for the 58th leaf is exactly the 58th leaf.    # The difference between the tree whose values
        // are zero except for the fifth leaf and the tree whose values are all zero except for the
        // fifth leaf (there they are equal) and for the 58th leaf is exactly the 58th leaf.
        let expected_diff =
            vec![BinaryFactTreeNodeDiff::new(58, SimpleLeafFact::empty(), SimpleLeafFact::new(Felt252::from(81)))];
        let diff_result = virtual_one_change_node
            .get_diff_between_trees(virtual_two_change_node, &mut ffc, &mut facts)
            .await
            .unwrap();
        assert_eq!(diff_result, expected_diff);
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_leaves(mut ffc: FFC) {
        let mut rng = rand::thread_rng();

        let height = Height(100);
        let n_leaves: u64 = rng.gen_range(1..=5) * 100;
        let leaf_values: Vec<u64> = (0..n_leaves).map(|_| rng.gen_range(1..1000)).collect();
        let leaf_indices: Vec<BigUint> =
            (0..n_leaves).map(|_| BigUint::from(rng.gen::<u64>()) % (BigUint::from(1u64) << height.0)).collect();
        let leaves: HashMap<_, _> = leaf_indices
            .iter()
            .cloned()
            .zip(leaf_values.iter().map(|x| SimpleLeafFact::new(Felt252::from(*x))))
            .collect();
        let tree = build_patricia_virtual_node(&mut ffc, height, leaves.clone()).await;

        // Sample random subset of initialized leaves.
        let n_sampled_leaves = rng.gen_range(1..=n_leaves) as usize;
        let sampled_indices: HashSet<_> = leaf_indices.choose_multiple(&mut rng, n_sampled_leaves).collect();
        let expected_leaves: HashMap<_, _> =
            leaves.into_iter().filter(|(index, _)| sampled_indices.contains(index)).collect();
        sample_and_verify_leaf_values(&mut ffc, &tree, &expected_leaves).await;

        // Sample random subset of empty leaves
        // (almost zero prob. they will land on initialized ones).
        let empty_leaf = SimpleLeafFact::empty();
        let sampled_indices: Vec<_> =
            (0..10).map(|_| BigUint::from(rng.gen::<u64>()) % (BigUint::from(1u64) << height.0)).collect();
        let expected_leaves: HashMap<_, _> =
            sampled_indices.into_iter().map(BigUint::from).map(|index| (index, empty_leaf.clone())).collect();
        sample_and_verify_leaf_values(&mut ffc, &tree, &expected_leaves).await;
    }
}
