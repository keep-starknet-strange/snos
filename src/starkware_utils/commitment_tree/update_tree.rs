use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::DerefMut;

use num_bigint::BigUint;

use crate::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactDict;
use crate::starkware_utils::commitment_tree::binary_fact_tree_node::BinaryFactTreeNode;
use crate::starkware_utils::commitment_tree::calculation::{Calculation, CalculationNode, NodeFactDict};
use crate::starkware_utils::commitment_tree::errors::{TreeError, UpdateTreeError};
use crate::starkware_utils::commitment_tree::inner_node_fact::InnerNodeFact;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::merkle_tree::traverse_tree::{traverse_tree, TreeTraverser};
use crate::starkware_utils::commitment_tree::patricia_tree::nodes::PatriciaNodeFact;
use crate::storage::storage::{DbObject, FactFetchingContext, HashFunctionType, Storage, StorageError};

#[derive(Clone, Debug, PartialEq)]
pub enum TreeUpdate<LF>
where
    LF: Clone,
{
    Tuple(Box<UpdateTree<LF>>, Box<UpdateTree<LF>>),
    Leaf(LF),
}

pub type UpdateTree<LF> = Option<TreeUpdate<LF>>;

/// Checks if there are merkle nodes that are not updated, but all of its children are.
/// Starts at node_index, and goes up to the root.
async fn update_necessary<S, H, LF, CN>(
    node_index: TreeIndex,
    updated_nodes: &mut HashMap<TreeIndex, CN>,
    ffc: &mut FactFetchingContext<S, H>,
    facts: &mut Option<BinaryFactDict>,
) -> Result<(), UpdateTreeError>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H>,
    CN: CalculationNode<S, H, LF>,
{
    let mut cur_node_index = node_index;

    // Xoring by 1 switch between 2k <-> 2k + 1, which are siblings in the tree.
    // The parent of these siblings is k = floor(n/2) for n = 2k, 2k+1.
    let one = BigUint::from(1u64);
    while updated_nodes.contains_key(&(cur_node_index.clone() ^ &one)) {
        cur_node_index /= 2u64;
        // Unwrapping is safe, guaranteed by construction
        let (left_index, right_index) = (&cur_node_index * 2u64, &cur_node_index * 2u64 + 1u64);
        let left = updated_nodes.get(&(left_index)).unwrap().clone();
        let right = updated_nodes.get(&(right_index)).unwrap().clone();

        let calculation_node = CN::combine(ffc, left, right, facts).await?;
        updated_nodes.insert(cur_node_index.clone(), calculation_node);

        updated_nodes.remove(&left_index);
        updated_nodes.remove(&right_index);
    }

    Ok(())
}

async fn update_if_possible<S, H, LF, BFTN, CN>(
    node_index: TreeIndex,
    binary_fact_tree_node: &BFTN,
    updated_nodes: &mut HashMap<TreeIndex, CN>,
    ffc: &mut FactFetchingContext<S, H>,
    facts: &mut Option<BinaryFactDict>,
) -> Result<(), UpdateTreeError>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    BFTN: BinaryFactTreeNode<S, H, LF>,
    CN: CalculationNode<S, H, LF, BinaryFactTreeNodeType = BFTN>,
{
    let calculation_node = CN::create_from_node(binary_fact_tree_node);
    updated_nodes.insert(node_index.clone(), calculation_node);

    update_necessary(node_index, updated_nodes, ffc, facts).await
}

async fn set_fact<S, H, LF, CN>(
    new_fact: LF,
    node_index: TreeIndex,
    updated_nodes: &mut HashMap<TreeIndex, CN>,
    ffc: &mut FactFetchingContext<S, H>,
    facts: &mut Option<BinaryFactDict>,
) -> Result<(), UpdateTreeError>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    CN: CalculationNode<S, H, LF>,
{
    let calculation_node = CN::create_from_fact(new_fact);
    updated_nodes.insert(node_index.clone(), calculation_node);

    update_necessary(node_index, updated_nodes, ffc, facts).await
}

struct NodeType<LF, BFTN>
where
    LF: Clone,
{
    index: TreeIndex,
    tree: BFTN,
    update: UpdateTree<LF>,
}

struct TreeUpdateTraverser<'trav, S, H, LF, BFTN, CN>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    BFTN: BinaryFactTreeNode<S, H, LF> + Send,
    CN: CalculationNode<S, H, LF, BinaryFactTreeNodeType = BFTN>,
{
    pub ffc: &'trav mut FactFetchingContext<S, H>,
    pub facts: &'trav mut Option<BinaryFactDict>,
    pub updated_nodes: HashMap<TreeIndex, CN>,
    _lf: PhantomData<LF>,
}

impl<'trav, S, H, LF, BFTN, CN> TreeUpdateTraverser<'trav, S, H, LF, BFTN, CN>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    BFTN: BinaryFactTreeNode<S, H, LF> + Send,
    CN: CalculationNode<S, H, LF, BinaryFactTreeNodeType = BFTN>,
{
    pub fn new(ffc: &'trav mut FactFetchingContext<S, H>, facts: &'trav mut Option<BinaryFactDict>) -> Self {
        Self { ffc, facts, updated_nodes: Default::default(), _lf: Default::default() }
    }
}

impl<'trav, S, H, LF, BFTN, CN> TreeTraverser<'trav, S, H, LF> for TreeUpdateTraverser<'trav, S, H, LF, BFTN, CN>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    BFTN: BinaryFactTreeNode<S, H, LF> + Send,
    CN: CalculationNode<S, H, LF, BinaryFactTreeNodeType = BFTN>,
{
    type NodeType = NodeType<LF, BFTN>;

    async fn get_children(&mut self, node: &Self::NodeType) -> Result<Vec<Self::NodeType>, TreeError> {
        let node_index = node.index.clone();
        let binary_fact_tree_node = &node.tree;
        let subtree_update = &node.update;

        let children = match subtree_update {
            None => {
                update_if_possible(node_index, binary_fact_tree_node, &mut self.updated_nodes, self.ffc, self.facts)
                    .await?;
                vec![]
            }
            Some(tree_update) => match tree_update {
                TreeUpdate::Leaf(leaf_fact) => {
                    debug_assert!(binary_fact_tree_node.is_leaf());
                    set_fact::<S, H, LF, CN>(
                        leaf_fact.clone(),
                        node_index,
                        &mut self.updated_nodes,
                        self.ffc,
                        self.facts,
                    )
                    .await?;
                    vec![]
                }
                TreeUpdate::Tuple(left_update, right_update) => {
                    let (left, right) = binary_fact_tree_node.get_children(self.ffc, self.facts).await?;

                    vec![
                        NodeType { index: 2u64 * &node_index, tree: left, update: *left_update.clone() },
                        NodeType { index: 2u64 * &node_index + 1u64, tree: right, update: *right_update.clone() },
                    ]
                }
            },
        };

        Ok(children)
    }
}

async fn build_updated_calculation<S, H, LF, BFTN, CN>(
    tree: BFTN,
    modifications: Vec<(TreeIndex, LF)>,
    ffc: &mut FactFetchingContext<S, H>,
    facts: &mut Option<BinaryFactDict>,
) -> Result<CN, TreeError>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    BFTN: BinaryFactTreeNode<S, H, LF> + Send,
    CN: CalculationNode<S, H, LF, BinaryFactTreeNodeType = BFTN> + Send,
{
    let update_tree = build_update_tree(tree.get_height_in_tree(), modifications);
    let first_node = NodeType { index: 1u64.into(), tree, update: update_tree };

    let mut tree_update_traverser = TreeUpdateTraverser::<S, H, LF, BFTN, CN>::new(ffc, facts);
    traverse_tree(&mut tree_update_traverser, first_node).await?;

    let mut updated_nodes = tree_update_traverser.updated_nodes;
    // Since the updated_nodes dictionary cleans itself, we expect only the new root to be
    // present, at node index 1.
    debug_assert_eq!(updated_nodes.len(), 1);
    debug_assert!(updated_nodes.contains_key(&1u64.into()));

    Ok(updated_nodes.remove(&1u64.into()).unwrap())
}

/// Updates the tree with the given list of modifications, writes all the new facts to the
/// storage and returns a new BinaryFactTree representing the fact of the root of the new tree.
///
/// If facts argument is not None, this dictionary is filled during building the new tree
/// by the facts of the modified nodes (the modified leaves won't enter to this dict as they are
/// already known to the function caller).
///
/// This method is to be called by a update() method of a specific tree implementation
/// (derived class of BinaryFactTree).
///
/// For efficiency, the function does not compute and store the new facts while traversing the
/// tree. Instead, it first traverses the tree to fetch the needed facts for the update. It then
/// computes the new facts. Once all facts are computed, it finally stores them.
pub async fn update_tree<S, H, LF, BFTN, CN>(
    tree: BFTN,
    ffc: &mut FactFetchingContext<S, H>,
    modifications: Vec<(TreeIndex, LF)>,
    facts: &mut Option<BinaryFactDict>,
) -> Result<BFTN, TreeError>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    BFTN: BinaryFactTreeNode<S, H, LF> + Send,
    CN: CalculationNode<S, H, LF, BinaryFactTreeNodeType = BFTN> + Calculation<BFTN, LF> + Send,
{
    // A map from node index to the updated subtree, in which inner nodes are not hashed yet, but
    // rather consist of their children.
    // This map is populated when we traverse a node and know its value in the updated tree.
    // This happens when either of these happens:
    // 1. The node has no updates => value remains the same.
    // 2. Node is a leaf update, and we just updated the leaf value.
    // 3. When its two children are already updated (happens in update_necessary()).
    let mut new_facts = NodeFactDict::<LF>::default();

    let updated_calc_node: CN =
        build_updated_calculation::<S, H, LF, BFTN, CN>(tree, modifications, ffc, facts).await?;

    let root_node = updated_calc_node.full_calculate(&mut new_facts);

    write_fact_nodes(ffc, &new_facts).await?;

    if let Some(facts) = facts {
        // The leaves aren't stored in `facts`. Only nodes are stored there.
        for (fact_hash, node_fact) in new_facts.inner_nodes.iter() {
            facts.insert(
                BigUint::from_bytes_be(fact_hash),
                <PatriciaNodeFact as InnerNodeFact<S, H>>::to_tuple(node_fact),
            );
        }
    }

    Ok(root_node)
}

type Layer<LF> = HashMap<TreeIndex, TreeUpdate<LF>>;

/// Constructs a tree from leaf updates. This is not a full binary tree. It is just the subtree
/// induced by the modification leaves.
/// Returns a tree. A tree is either:
///  * None (if no modifications exist in its subtree).
///  * A leaf (if a single modification is given at height 0; i.e., a leaf).
///  * A pair of trees.
pub fn build_update_tree<LF>(height: Height, modifications: Vec<(TreeIndex, LF)>) -> UpdateTree<LF>
where
    LF: Clone,
{
    // Bottom layer. This will prefer the last modification to an index.
    if modifications.is_empty() {
        return None;
    }

    // A layer is a dictionary from index in current merkle layer [0, 2**layer_height) to a tree.
    // A tree is either None, a leaf, or a pair of trees.
    let mut layer: Layer<LF> =
        modifications.into_iter().map(|(index, leaf_fact)| (index, TreeUpdate::Leaf(leaf_fact))).collect();

    for _ in 0..height.0 {
        let parents: HashSet<TreeIndex> = layer.keys().map(|key| key / 2u64).collect();
        let mut new_layer: Layer<LF> = Layer::new();

        for index in parents.into_iter() {
            let left_update = layer.get(&(&index * 2u64)).cloned();
            let right_update = layer.get(&(&index * 2u64 + 1u64)).cloned();

            new_layer.insert(index, TreeUpdate::Tuple(Box::new(left_update), Box::new(right_update)));
        }

        layer = new_layer;
    }

    // We reached layer_height=0, the top layer with only the root (with index 0).
    debug_assert!(layer.len() == 1);

    // unwrap() is safe here, 0 should always be in `layer` by construction
    Some(layer.remove(&0u64.into()).unwrap())
}

async fn write_fact_nodes<S, H, LF>(
    ffc: &mut FactFetchingContext<S, H>,
    fact_nodes: &NodeFactDict<LF>,
) -> Result<(), StorageError>
where
    S: Storage,
    H: HashFunctionType,
    LF: DbObject,
{
    // TODO: this implementation is sync and simplistic for now.
    //       Determine if it is necessary to improve it.
    let mut storage = ffc.acquire_storage().await;
    for (root_hash, root_node) in fact_nodes.inner_nodes.iter() {
        root_node.set(storage.deref_mut(), root_hash).await?;
    }
    for (root_hash, root_node) in fact_nodes.leaves.iter() {
        root_node.set(storage.deref_mut(), root_hash).await?;
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub enum DecodeNodeCase {
    Left,
    Right,
    Both,
}

#[derive(Clone, Debug)]
pub struct DecodedNode<'a, LF>
where
    LF: Clone,
{
    pub left_child: &'a Option<TreeUpdate<LF>>,
    pub right_child: &'a Option<TreeUpdate<LF>>,
    pub case: DecodeNodeCase,
}

/// Given a node generated by build_update_tree(), returns which update case it belongs to,
/// and both children. This is a utility to make cairo hints shorter.
/// Cases: both, if both children are to be updated, and left or right, if only one child is to be
/// updated.
pub fn decode_node<LF>(node: &TreeUpdate<LF>) -> Result<DecodedNode<LF>, TreeError>
where
    LF: Clone,
{
    match node {
        TreeUpdate::Tuple(left, right) => {
            let case = match (left.is_none(), right.is_none()) {
                (true, false) => DecodeNodeCase::Right,
                (false, true) => DecodeNodeCase::Left,
                (false, false) => DecodeNodeCase::Both,
                (true, true) => return Err(TreeError::IsEmpty),
            };
            Ok(DecodedNode { left_child: left.as_ref(), right_child: right.as_ref(), case })
        }
        TreeUpdate::Leaf(_) => Err(TreeError::IsLeaf),
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use cairo_vm::Felt252;

    use super::*;
    use crate::storage::storage_utils::SimpleLeafFact;

    type LeafFactType = SimpleLeafFact;

    #[test]
    fn test_build_update_tree_empty() {
        let update_tree = build_update_tree::<LeafFactType>(Height(3), vec![]);
        assert_matches!(update_tree, None);
    }

    fn print_update_tree(index: u64, update_tree: &UpdateTree<LeafFactType>) {
        match update_tree {
            None => {
                return;
            }
            Some(TreeUpdate::Tuple(left, right)) => {
                print_update_tree(index * 2, left);
                print_update_tree(index * 2 + 1, right);
            }
            Some(TreeUpdate::Leaf(leaf_fact)) => println!("{index}: {}", leaf_fact.value.to_biguint()),
        }
    }

    #[test]
    fn test_build_update_tree() {
        let modifications = vec![
            (BigUint::from(1u64), SimpleLeafFact::new(Felt252::from(12))),
            (BigUint::from(4u64), SimpleLeafFact::new(Felt252::from(1000))),
            (BigUint::from(6u64), SimpleLeafFact::new(Felt252::from(30))),
        ];
        let update_tree = build_update_tree::<LeafFactType>(Height(3), modifications);
        print_update_tree(0, &update_tree);

        // TODO finish this test
    }

    #[test]
    fn test_decode_node() {
        let leaf_fact_left = SimpleLeafFact::new(Felt252::from(252));
        let leaf_fact_right = SimpleLeafFact::new(Felt252::from(3000));

        // Left node
        let node = TreeUpdate::Tuple(Box::new(Some(TreeUpdate::Leaf(leaf_fact_left.clone()))), Box::new(None));
        let DecodedNode { left_child, right_child, case } = decode_node(&node).unwrap();
        assert_matches!(left_child.clone(), Some(TreeUpdate::Leaf(leaf_fact)) if leaf_fact == leaf_fact_left);
        assert_matches!(right_child, None);
        assert_matches!(case, DecodeNodeCase::Left);

        // Right node
        let node = TreeUpdate::Tuple(Box::new(None), Box::new(Some(TreeUpdate::Leaf(leaf_fact_right.clone()))));
        let DecodedNode { left_child, right_child, case } = decode_node(&node).unwrap();
        assert_matches!(left_child, None);
        assert_matches!(right_child.clone(), Some(TreeUpdate::Leaf(leaf_fact)) if leaf_fact ==
        leaf_fact_right);
        assert_matches!(case, DecodeNodeCase::Right);

        // Two children
        let node = TreeUpdate::Tuple(
            Box::new(Some(TreeUpdate::Leaf(leaf_fact_left.clone()))),
            Box::new(Some(TreeUpdate::Leaf(leaf_fact_right.clone()))),
        );
        let DecodedNode { left_child, right_child, case } = decode_node(&node).unwrap();
        assert_matches!(left_child.clone(), Some(TreeUpdate::Leaf(leaf_fact)) if leaf_fact ==
        leaf_fact_left);
        assert_matches!(right_child.clone(), Some(TreeUpdate::Leaf(leaf_fact)) if leaf_fact ==
                leaf_fact_right);
        assert_matches!(case, DecodeNodeCase::Both);

        // No children
        let node = TreeUpdate::<SimpleLeafFact>::Tuple(Box::new(None), Box::new(None));
        let result = decode_node(&node);
        assert_matches!(result, Err(TreeError::IsEmpty));
    }
}
