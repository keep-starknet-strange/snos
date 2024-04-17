use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::Deref;

use futures::future::FutureExt;
use num_bigint::BigUint;

use crate::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactDict;
use crate::starkware_utils::commitment_tree::errors::TreeError;
use crate::starkware_utils::commitment_tree::inner_node_fact::InnerNodeFact;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::merkle_tree::traverse_tree::{traverse_tree, TreeTraverser};
use crate::storage::storage::{FactFetchingContext, HashFunctionType, Storage, StorageError};

#[derive(Debug, PartialEq)]
pub struct BinaryFactTreeNodeDiff<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    pub path: usize,
    previous: LF,
    current: LF,
    _storage: PhantomData<S>,
    _hash_function_type: PhantomData<H>,
}

impl<S, H, LF> BinaryFactTreeNodeDiff<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    pub fn new(path: usize, previous: LF, current: LF) -> Self {
        Self { path, previous, current, _storage: Default::default(), _hash_function_type: Default::default() }
    }
}

struct BinaryFactTreeTraverser<'trav, S, H, LF, N>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    N: BinaryFactTreeNode<S, H, LF> + Send,
{
    pub ffc: &'trav mut FactFetchingContext<S, H>,
    pub facts: &'trav mut Option<BinaryFactDict>,
    pub result: Vec<BinaryFactTreeNodeDiff<S, H, LF>>,
    _n: PhantomData<N>,
}

impl<'trav, S, H, LF, N> BinaryFactTreeTraverser<'trav, S, H, LF, N>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    N: BinaryFactTreeNode<S, H, LF> + Send,
{
    #[allow(unused)]
    pub fn new(ffc: &'trav mut FactFetchingContext<S, H>, facts: &'trav mut Option<BinaryFactDict>) -> Self {
        Self { ffc, facts, result: vec![], _n: Default::default() }
    }
}

struct BinaryFactTreeDiff<S, H, LF, N>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    N: BinaryFactTreeNode<S, H, LF> + Send,
{
    path: usize,
    previous: N,
    current: N,
    _storage: PhantomData<S>,
    _hash_function_type: PhantomData<H>,
    _leaf_fact: PhantomData<LF>,
}

impl<S, H, LF, N> BinaryFactTreeDiff<S, H, LF, N>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Send,
    N: BinaryFactTreeNode<S, H, LF> + Send,
{
    pub fn new(path: usize, previous: N, current: N) -> Self {
        Self {
            path,
            previous,
            current,
            _storage: Default::default(),
            _hash_function_type: Default::default(),
            _leaf_fact: Default::default(),
        }
    }
}

impl<'trav, S, H, LF, N> TreeTraverser<'trav, S, H, LF> for BinaryFactTreeTraverser<'trav, S, H, LF, N>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Sync + Send,
    N: BinaryFactTreeNode<S, H, LF> + Sync + 'trav,
{
    type NodeType = BinaryFactTreeDiff<S, H, LF, N>;

    async fn get_children(&mut self, node: &Self::NodeType) -> Result<Vec<Self::NodeType>, TreeError> {
        if node.previous.is_leaf() {
            let storage = self.ffc.acquire_storage().await;
            // unwrap() on leaf_hash is guaranteed to be safe because of the check above
            let previous = LF::get_or_fail(storage.deref(), &node.previous.leaf_hash().unwrap()).await?;
            let current = LF::get_or_fail(storage.deref(), &node.current.leaf_hash().unwrap()).await?;
            self.result.push(BinaryFactTreeNodeDiff::new(node.path, previous, current));
            return Ok(vec![]);
        }

        let (previous_left, previous_right) = node.previous.get_children(self.ffc, self.facts).await?;
        let (current_left, current_right) = node.current.get_children(self.ffc, self.facts).await?;

        let mut children = vec![];
        if previous_left != current_left {
            // Shift left for the left child
            let path = node.path << 1;
            children.push(BinaryFactTreeDiff::new(path, previous_left, current_left));
        }
        if previous_right != current_right {
            // Shift left and turn on the LSB bit for the right child
            let path = (node.path << 1) + 1;
            children.push(BinaryFactTreeDiff::new(path, previous_right, current_right));
        }

        Ok(children)
    }
}

#[allow(async_fn_in_trait)]
pub trait BinaryFactTreeNode<S, H, LF>: Sized + PartialEq + Sync + Send
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H> + Sync + Send,
{
    fn is_leaf(&self) -> bool {
        self.get_height_in_tree() == Height(0)
    }
    fn _leaf_hash(&self) -> Vec<u8>;
    fn leaf_hash(&self) -> Option<Vec<u8>> {
        match self.is_leaf() {
            true => Some(self._leaf_hash()),
            false => None,
        }
    }

    /// Returns the height of the node in a tree.
    fn get_height_in_tree(&self) -> Height;

    fn create_leaf(hash_value: Vec<u8>) -> Self;

    /// Returns the two BinaryFactTreeNode objects which are the roots of the subtrees of the
    /// current BinaryFactTreeNode.
    ///
    /// If facts argument is not None, this dictionary is filled with facts read from the DB.
    fn get_children<'a>(
        &'a self,
        ffc: &'a mut FactFetchingContext<S, H>,
        facts: &'a mut Option<BinaryFactDict>,
    ) -> impl std::future::Future<Output = Result<(Self, Self), TreeError>> + Send;

    fn _get_leaves<'a>(
        &'a self,
        ffc: &'a mut FactFetchingContext<S, H>,
        indices: &'a [TreeIndex],
        facts: &'a mut Option<BinaryFactDict>,
    ) -> impl std::future::Future<Output = Result<HashMap<TreeIndex, LF>, TreeError>> + Send {
        async move {
            if indices.is_empty() {
                return Ok(HashMap::default());
            }

            if self.is_leaf() {
                return self._get_leaf(ffc, indices).await;
            }

            self._get_binary_node_leaves(ffc, indices, facts).await
        }
        .boxed()
    }

    /// Returns the values of the leaves whose indices are given.
    fn _get_binary_node_leaves<'a>(
        &'a self,
        ffc: &'a mut FactFetchingContext<S, H>,
        indices: &'a [TreeIndex],
        facts: &'a mut Option<BinaryFactDict>,
    ) -> impl std::future::Future<Output = Result<HashMap<TreeIndex, LF>, TreeError>> + Send {
        async move {
            // Partition indices.
            let height_in_tree = self.get_height_in_tree();
            debug_assert!(height_in_tree.0 > 0, "otherwise pow() below will overflow");
            let mid = BigUint::from(1u64) << (height_in_tree.0 - 1);

            let (left_indices, right_indices) = {
                let mut left = vec![];
                let mut right = vec![];
                for index in indices {
                    if index < &mid {
                        left.push(index.clone());
                    } else {
                        right.push(index.clone() - &mid);
                    }
                }
                (left, right)
            };

            let (left_child, right_child) = self.get_children(ffc, facts).await?;

            let left_leaves = left_child._get_leaves(ffc, &left_indices, facts).await?;
            let right_leaves = right_child._get_leaves(ffc, &right_indices, facts).await?;

            Ok(unify_binary_leaves(mid, left_leaves, right_leaves))
        }
        .boxed()
    }

    /// Returns a list of (key, old_fact, new_fact) that are different
    /// between this tree and another.
    ///
    /// The height of the two trees must be equal.
    ///
    /// If the 'facts' argument is not None, this dictionary is filled with facts read from the DB.
    async fn get_diff_between_trees(
        self,
        other: Self,
        ffc: &mut FactFetchingContext<S, H>,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Vec<BinaryFactTreeNodeDiff<S, H, LF>>, TreeError> {
        // Tree heights must be equal
        let height = self.get_height_in_tree();
        let other_height = other.get_height_in_tree();
        if height != other_height {
            return Err(TreeError::TreeHeightsMismatch(height, other_height));
        }
        let mut tree_traverser = BinaryFactTreeTraverser::new(ffc, facts);

        let root = BinaryFactTreeDiff::new(0, self, other);
        traverse_tree(&mut tree_traverser, root).await?;

        Ok(tree_traverser.result)
    }

    fn _get_leaf<'a>(
        &'a self,
        ffc: &'a FactFetchingContext<S, H>,
        _indices: &'a [TreeIndex],
    ) -> impl std::future::Future<Output = Result<HashMap<TreeIndex, LF>, TreeError>> + Send {
        async move {
            // TODO: determine what to do with the assertion in the Python code
            // assert set(indices) == {0}, f"Commitment tree indices out of range: {indices}."

            let storage = ffc.acquire_storage().await;
            let leaf = LF::get_or_fail(storage.deref(), &self._leaf_hash()).await?;
            Ok(HashMap::from([(BigUint::from(0u64), leaf)]))
        }
        .boxed()
    }
}

pub fn unify_binary_leaves<S, H, LF>(
    middle_index: TreeIndex,
    left_leaves: HashMap<TreeIndex, LF>,
    right_leaves: HashMap<TreeIndex, LF>,
) -> HashMap<TreeIndex, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    let mut leaves = left_leaves;
    for (index, leaf) in right_leaves {
        leaves.insert(index + &middle_index, leaf);
    }

    leaves
}

pub async fn read_node_fact<S, H, INF>(
    ffc: &FactFetchingContext<S, H>,
    fact_hash: &[u8],
    facts: &mut Option<BinaryFactDict>,
) -> Result<INF, StorageError>
where
    S: Storage,
    H: HashFunctionType,
    INF: InnerNodeFact<S, H>,
{
    let storage = ffc.acquire_storage().await;
    let inner_node_fact = INF::get_or_fail(storage.deref(), fact_hash).await?;

    if let Some(facts) = facts {
        let fact_key = BigUint::from_bytes_be(fact_hash);
        facts.insert(fact_key, inner_node_fact.to_tuple());
    }
    Ok(inner_node_fact)
}

pub async fn write_node_fact<S, H, INF>(
    ffc: &mut FactFetchingContext<S, H>,
    inner_node_fact: INF,
    facts: &mut Option<BinaryFactDict>,
) -> Result<Vec<u8>, StorageError>
where
    S: Storage,
    H: HashFunctionType,
    INF: InnerNodeFact<S, H>,
{
    let fact_hash = inner_node_fact.set_fact(ffc).await?;

    if let Some(facts) = facts {
        let fact_key = BigUint::from_bytes_be(&fact_hash);
        facts.insert(fact_key, inner_node_fact.to_tuple());
    }

    Ok(fact_hash)
}
