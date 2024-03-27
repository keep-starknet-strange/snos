use std::any::Any;
use std::marker::PhantomData;

use num_bigint::BigUint;

use crate::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactDict;
use crate::starkware_utils::commitment_tree::binary_fact_tree_node::read_node_fact;
use crate::starkware_utils::commitment_tree::calculation::{
    Calculation, CalculationNode, ConstantCalculation, DependencyWrapper, HashCalculation, LeafFactCalculation,
    NodeFactDict,
};
use crate::starkware_utils::commitment_tree::errors::{CombineError, TreeError};
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::nodes::{
    verify_path_value, BinaryNodeFact, EdgeNodeFact, PatriciaNodeFact,
};
use crate::starkware_utils::commitment_tree::patricia_tree::patricia_tree::EMPTY_NODE_HASH;
use crate::starkware_utils::commitment_tree::patricia_tree::virtual_patricia_node::VirtualPatriciaNode;
use crate::storage::storage::{Fact, FactFetchingContext, HashFunctionType, Storage, StorageError};

#[derive(Debug, PartialEq)]
pub struct BinaryCalculation<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H>,
{
    left: Box<HashCalculationImpl<S, H, LF>>,
    right: Box<HashCalculationImpl<S, H, LF>>,
    _phantom: PhantomData<(S, H)>,
}

impl<S, H, LF> BinaryCalculation<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H>,
{
    pub fn new(left: Box<HashCalculationImpl<S, H, LF>>, right: Box<HashCalculationImpl<S, H, LF>>) -> Self {
        Self { left, right, _phantom: Default::default() }
    }
}

// A custom implementation is required to avoid requiring Clone on Storage and HashFunctionType
// because of the PhantomData fields in the struct.
impl<S, H, LF> Clone for BinaryCalculation<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H>,
{
    fn clone(&self) -> Self {
        Self::new(self.left.clone(), self.right.clone())
    }
}

impl<S, H, LF> Calculation<Vec<u8>, LF> for BinaryCalculation<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H> + 'static,
{
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        vec![
            Box::new(DependencyWrapper::new(self.left.clone_box())),
            Box::new(DependencyWrapper::new(self.right.clone_box())),
        ]
    }

    fn calculate(&self, dependency_results: Vec<Box<dyn Any>>, fact_nodes: &mut NodeFactDict<LF>) -> Vec<u8> {
        let left_hash: &Vec<u8> = dependency_results[0].downcast_ref().unwrap();
        let right_hash: &Vec<u8> = dependency_results[1].downcast_ref().unwrap();

        let fact = BinaryNodeFact { left_node: left_hash.clone(), right_node: right_hash.clone() };
        let fact_hash = <BinaryNodeFact as Fact<S, H>>::hash(&fact);
        fact_nodes.inner_nodes.insert(fact_hash.clone(), PatriciaNodeFact::Binary(fact));

        fact_hash
    }
}

impl<S, H, LF> HashCalculation<LF> for BinaryCalculation<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H> + 'static,
{
    fn clone_box(&self) -> Box<dyn HashCalculation<LF>> {
        Box::new(Self { left: self.left.clone(), right: self.right.clone(), _phantom: Default::default() })
    }
}

#[derive(Debug, PartialEq)]
pub struct EdgeCalculation<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H>,
{
    // Use Box here as `EdgeCalculation` is also a variant of `BottomCalculation`.
    bottom: Box<HashCalculationImpl<S, H, LF>>,
    path: NodePath,
    length: Length,
    _phantom: PhantomData<(S, H)>,
}

impl<S, H, LF> EdgeCalculation<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    pub fn new(bottom: Box<HashCalculationImpl<S, H, LF>>, path: NodePath, length: Length) -> Self {
        debug_assert!(verify_path_value(&path, length).is_ok());
        Self { bottom, path, length, _phantom: Default::default() }
    }
}

// A custom implementation is required to avoid requiring Clone on Storage and HashFunctionType
// because of the PhantomData fields in the struct.
impl<S, H, LF> Clone for EdgeCalculation<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    fn clone(&self) -> Self {
        Self { bottom: self.bottom.clone(), path: self.path.clone(), length: self.length, _phantom: Default::default() }
    }
}

impl<S, H, LF> Calculation<Vec<u8>, LF> for EdgeCalculation<S, H, LF>
where
    H: HashFunctionType + 'static,
    S: Storage,
    LF: LeafFact<S, H> + 'static,
{
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        vec![Box::new(DependencyWrapper::new(self.bottom.clone_box()))]
    }

    fn calculate(&self, dependency_results: Vec<Box<dyn Any>>, fact_nodes: &mut NodeFactDict<LF>) -> Vec<u8> {
        let bottom_hash: &Vec<u8> = dependency_results[0].downcast_ref().unwrap();
        let fact = EdgeNodeFact::new_unchecked(bottom_hash.clone(), self.path.clone(), self.length);
        let fact_hash = <EdgeNodeFact as Fact<S, H>>::hash(&fact);
        fact_nodes.inner_nodes.insert(fact_hash.clone(), PatriciaNodeFact::Edge(fact));

        fact_hash
    }
}

impl<S, H, LF> HashCalculation<LF> for EdgeCalculation<S, H, LF>
where
    S: Storage,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H> + 'static,
{
    fn clone_box(&self) -> Box<dyn HashCalculation<LF>> {
        Box::new(Self {
            bottom: self.bottom.clone(),
            path: self.path.clone(),
            length: self.length,
            _phantom: Default::default(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum HashCalculationImpl<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H>,
{
    Binary(BinaryCalculation<S, H, LF>),
    Edge(EdgeCalculation<S, H, LF>),
    LeafFact(LeafFactCalculation<S, H, LF>),
    Constant(ConstantCalculation<Vec<u8>>),
}

impl<S, H, LF> HashCalculationImpl<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    pub fn is_empty(&self) -> bool {
        match self {
            HashCalculationImpl::Constant(constant_calculation) => constant_calculation.value == EMPTY_NODE_HASH,
            HashCalculationImpl::LeafFact(leaf_fact_calculation) => leaf_fact_calculation.fact.is_empty(),
            _ => false,
        }
    }
}

impl<S, H, LF> Clone for HashCalculationImpl<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    fn clone(&self) -> Self {
        match self {
            HashCalculationImpl::Binary(binary) => HashCalculationImpl::Binary(binary.clone()),
            HashCalculationImpl::Edge(edge) => HashCalculationImpl::Edge(edge.clone()),
            HashCalculationImpl::LeafFact(leaf_fact) => HashCalculationImpl::LeafFact(leaf_fact.clone()),
            HashCalculationImpl::Constant(constant) => HashCalculationImpl::Constant(constant.clone()),
        }
    }
}

// impl<S, H> Clone for

impl<S, H, LF> Calculation<Vec<u8>, LF> for HashCalculationImpl<S, H, LF>
where
    H: 'static + HashFunctionType,
    S: Storage,
    LF: LeafFact<S, H> + 'static,
{
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        match self {
            HashCalculationImpl::Binary(binary) => binary.get_dependency_calculations(),
            HashCalculationImpl::Edge(edge) => edge.get_dependency_calculations(),
            HashCalculationImpl::LeafFact(leaf_fact) => leaf_fact.get_dependency_calculations(),
            HashCalculationImpl::Constant(constant) => constant.get_dependency_calculations(),
        }
    }

    fn calculate(&self, dependency_results: Vec<Box<dyn Any>>, fact_nodes: &mut NodeFactDict<LF>) -> Vec<u8> {
        match self {
            HashCalculationImpl::Binary(binary) => binary.calculate(dependency_results, fact_nodes),
            HashCalculationImpl::Edge(edge) => edge.calculate(dependency_results, fact_nodes),
            HashCalculationImpl::LeafFact(leaf_fact) => leaf_fact.calculate(dependency_results, fact_nodes),
            HashCalculationImpl::Constant(constant) => constant.calculate(dependency_results, fact_nodes),
        }
    }
}

impl<S, H, LF> HashCalculation<LF> for HashCalculationImpl<S, H, LF>
where
    S: Storage,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H> + 'static,
{
    fn clone_box(&self) -> Box<dyn HashCalculation<LF>> {
        match self {
            HashCalculationImpl::Binary(binary) => binary.clone_box(),
            HashCalculationImpl::Edge(edge) => edge.clone_box(),
            HashCalculationImpl::LeafFact(leaf_fact) => leaf_fact.clone_box(),
            HashCalculationImpl::Constant(constant) => constant.clone_box(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct VirtualCalculationNode<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H>,
{
    bottom_calculation: HashCalculationImpl<S, H, LF>,
    path: NodePath,
    length: Length,
    /// The height of the subtree rooted at this node.
    /// In other words, this is the length of the path from this node to the leaves.
    height: Height,
    _phantom: PhantomData<(S, H)>,
}

impl<S, H, LF> VirtualCalculationNode<S, H, LF>
where
    S: Storage + Sync + Send + 'static,
    H: HashFunctionType + Sync + Send + 'static,
    LF: LeafFact<S, H>,
{
    pub fn new_unchecked(
        bottom_calculation: HashCalculationImpl<S, H, LF>,
        path: NodePath,
        length: Length,
        height: Height,
    ) -> Self {
        debug_assert!(verify_path_value(&path, length).is_ok());
        Self { bottom_calculation, path, length, height, _phantom: Default::default() }
    }

    #[allow(unused)]
    pub fn new(
        bottom_calculation: HashCalculationImpl<S, H, LF>,
        path: NodePath,
        length: Length,
        height: Height,
    ) -> Result<Self, TreeError> {
        verify_path_value(&path, length)?;
        Ok(Self::new_unchecked(bottom_calculation, path.clone(), length, height))
    }

    pub fn empty_node(height: Height) -> Self {
        let bottom_calculation = HashCalculationImpl::Constant(ConstantCalculation::new(EMPTY_NODE_HASH.to_vec()));
        VirtualCalculationNode::new_unchecked(bottom_calculation, NodePath(0u64.into()), Length(0), height)
    }

    fn is_empty(&self) -> bool {
        self.bottom_calculation.is_empty()
    }

    fn is_virtual_edge(&self) -> bool {
        self.length.0 != 0
    }

    fn is_leaf(&self) -> bool {
        self.height.0 == 0
    }

    /// Converts self into a non-virtual calculation. Enters the virtual edge (if it exists) into
    /// the resulting calculation.
    fn commit(self) -> HashCalculationImpl<S, H, LF> {
        if !self.is_virtual_edge() {
            return self.bottom_calculation;
        }

        HashCalculationImpl::Edge(EdgeCalculation::<S, H, LF>::new(
            Box::new(self.bottom_calculation),
            self.path,
            self.length,
        ))
    }

    fn combine_to_binary_node(left: Self, right: Self) -> Self {
        let height = Height(&right.height.0 + 1);
        let bottom_calculation =
            HashCalculationImpl::Binary(BinaryCalculation::new(Box::new(left.commit()), Box::new(right.commit())));
        VirtualCalculationNode::new_unchecked(bottom_calculation, NodePath(0u64.into()), Length(0), height)
    }

    async fn decommit(
        self,
        ffc: &mut FactFetchingContext<S, H>,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Self, StorageError> {
        if self.is_leaf() || self.is_empty() || self.is_virtual_edge() {
            return Ok(self);
        }

        // Check if the bottom calculation represents an edge.
        if let HashCalculationImpl::Edge(edge_calculation) = &self.bottom_calculation {
            // Moving the edge of bottom_calculation into the virtual edge.
            return Ok(Self::new_unchecked(
                *edge_calculation.bottom.clone(),
                edge_calculation.path.clone(),
                edge_calculation.length,
                self.height,
            ));
        }

        if let HashCalculationImpl::Constant(constant_calculation) = &self.bottom_calculation {
            let bottom_fact = read_node_fact::<S, H, PatriciaNodeFact>(ffc, &constant_calculation.value, facts).await?;
            if let PatriciaNodeFact::Edge(edge_node_fact) = bottom_fact {
                return Ok(Self::new_unchecked(
                    HashCalculationImpl::Constant(ConstantCalculation::new(edge_node_fact.bottom_node)),
                    edge_node_fact.edge_path,
                    edge_node_fact.edge_length,
                    self.height,
                ));
            }
        }

        Ok(self)
    }

    async fn combine_to_virtual_edge_node(
        ffc: &mut FactFetchingContext<S, H>,
        left: Self,
        right: Self,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Self, CombineError> {
        let (left_is_empty, non_empty_child) = match (left.is_empty(), right.is_empty()) {
            (true, false) => (true, right),
            (false, true) => (false, left),
            (_, _) => {
                return Err(CombineError::CannotCombineToVirtualEdgeNode);
            }
        };
        let non_empty_child = non_empty_child.decommit(ffc, facts).await?;

        let mut parent_path = non_empty_child.path;
        if left_is_empty {
            // Turn on the MSB bit if the non-empty child is on the right.
            parent_path = NodePath(parent_path.0 + (BigUint::from(1u64) << non_empty_child.length.0));
        }

        let length = Length(non_empty_child.length.0 + 1);
        let height = Height(non_empty_child.height.0 + 1);
        Ok(Self::new_unchecked(non_empty_child.bottom_calculation, parent_path, length, height))
    }
}

impl<S, H, LF> Clone for VirtualCalculationNode<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H>,
{
    fn clone(&self) -> Self {
        Self {
            bottom_calculation: self.bottom_calculation.clone(),
            path: self.path.clone(),
            length: self.length,
            height: self.height,
            _phantom: Default::default(),
        }
    }
}

impl<S, H, LF> Calculation<VirtualPatriciaNode<S, H, LF>, LF> for VirtualCalculationNode<S, H, LF>
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send + 'static,
    LF: LeafFact<S, H> + Send + 'static,
{
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        self.bottom_calculation.get_dependency_calculations()
    }

    fn calculate(
        &self,
        dependency_results: Vec<Box<dyn Any>>,
        fact_nodes: &mut NodeFactDict<LF>,
    ) -> VirtualPatriciaNode<S, H, LF> {
        let bottom_hash = self.bottom_calculation.calculate(dependency_results, fact_nodes);
        VirtualPatriciaNode::new_unchecked(bottom_hash, self.path.clone(), self.length, self.height)
    }
}

impl<S, H, LF> CalculationNode<S, H, LF> for VirtualCalculationNode<S, H, LF>
where
    S: Storage + Sync + Send + 'static,
    H: HashFunctionType + Sync + Send + 'static,
    LF: LeafFact<S, H>,
{
    type BinaryFactTreeNodeType = VirtualPatriciaNode<S, H, LF>;

    /// Gets two VirtualCalculationNode objects left and right representing children nodes, and
    /// builds their parent node. Returns a new VirtualCalculationNode.
    ///
    /// If facts argument is not None, this dictionary is filled with facts read from the DB.
    async fn combine(
        ffc: &mut FactFetchingContext<S, H>,
        left: Self,
        right: Self,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Self, CombineError> {
        if left.height != right.height {
            return Err(CombineError::TreeHeightsDiffer(left.height, right.height));
        }

        let parent_height = Height(right.height.0 + 1);
        if left.is_empty() && right.is_empty() {
            return Ok(Self::empty_node(parent_height));
        }

        if !left.is_empty() && !right.is_empty() {
            return Ok(Self::combine_to_binary_node(left, right));
        }

        Self::combine_to_virtual_edge_node(ffc, left, right, facts).await
    }

    fn create_from_node(node: &Self::BinaryFactTreeNodeType) -> Self {
        let bottom_calculation = HashCalculationImpl::Constant(ConstantCalculation::new(node.bottom_node.clone()));
        Self::new_unchecked(bottom_calculation, node.path.clone(), node.length, node.height)
    }

    fn create_from_fact(fact: LF) -> Self {
        let bottom_calculation = HashCalculationImpl::LeafFact(LeafFactCalculation::new(fact));
        Self::new_unchecked(bottom_calculation, NodePath(0u64.into()), Length(0), Height(0))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use cairo_vm::Felt252;
    use rstest::{fixture, rstest};

    use super::*;
    use crate::crypto::pedersen::PedersenHash;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::FactFetchingContext;
    use crate::storage::storage_utils::SimpleLeafFact;

    type StorageType = DictStorage;
    type HashFunction = PedersenHash;
    type LeafFactType = SimpleLeafFact;
    type FFC = FactFetchingContext<StorageType, HashFunction>;
    type LeafCalculation = HashCalculationImpl<StorageType, HashFunction, LeafFactType>;

    type VCN = VirtualCalculationNode<StorageType, HashFunction, LeafFactType>;

    #[fixture]
    fn ffc() -> FFC {
        FactFetchingContext::<_, HashFunction>::new(DictStorage::default())
    }

    #[fixture]
    async fn leaf_calculation(mut ffc: FFC) -> LeafCalculation {
        let leaf_hash = SimpleLeafFact::new(Felt252::from(42)).set_fact(&mut ffc).await.unwrap();
        HashCalculationImpl::Constant(ConstantCalculation::new(leaf_hash))
    }

    #[fixture]
    async fn leaf_calculation2(mut ffc: FFC) -> LeafCalculation {
        let leaf_hash = SimpleLeafFact::new(Felt252::from(153)).set_fact(&mut ffc).await.unwrap();
        HashCalculationImpl::Constant(ConstantCalculation::new(leaf_hash))
    }

    #[rstest]
    #[tokio::test]
    async fn test_invalid_length(#[future] leaf_calculation: LeafCalculation) {
        let leaf_calculation = leaf_calculation.await;
        let result = VCN::new(leaf_calculation, NodePath(1u64.into()), Length(0), Height(1));
        assert!(result.is_err());
    }

    #[rstest]
    #[case(Height(0))]
    #[case(Height(7))]
    #[tokio::test]
    async fn test_combine_two_empty(mut ffc: FFC, #[case] height: Height) {
        let mut facts = None;
        let left_child = VCN::empty_node(height);
        let right_child = VCN::empty_node(height);
        let parent = VCN::combine(&mut ffc, left_child, right_child, &mut facts).await.unwrap();
        assert_eq!(parent, VCN::empty_node(Height(height.0 + 1)));
    }

    #[rstest]
    #[tokio::test]
    async fn test_combine_unmatching_height(mut ffc: FFC) {
        let mut facts = None;
        let (height_0, height_1) = (Height(0), Height(1));
        let empty_node_0 = VCN::empty_node(height_0);
        let empty_node_1 = VCN::empty_node(height_1);

        let result = VCN::combine(&mut ffc, empty_node_0, empty_node_1, &mut facts).await;
        assert_matches!(result, Err(CombineError::TreeHeightsDiffer(left,right)) if left == height_0 && right == height_1);
    }

    #[rstest]
    #[tokio::test]
    async fn test_combine_left_empty_right_leaf(mut ffc: FFC, #[future] leaf_calculation: LeafCalculation) {
        let leaf_calculation = leaf_calculation.await;
        let mut facts = None;

        let left = VCN::empty_node(Height(0u64.into()));
        let right = VCN::new(leaf_calculation.clone(), NodePath(0u64.into()), Length(0), Height(0)).unwrap();
        let parent = VCN::combine(&mut ffc, left, right, &mut facts).await.unwrap();
        assert_eq!(parent, VCN::new(leaf_calculation, NodePath(1u64.into()), Length(1), Height(1)).unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_combine_left_leaf_right_empty(mut ffc: FFC, #[future] leaf_calculation: LeafCalculation) {
        let leaf_calculation = leaf_calculation.await;
        let mut facts = None;

        let left = VCN::new(leaf_calculation.clone(), NodePath(0u64.into()), Length(0), Height(0)).unwrap();
        let right = VCN::empty_node(Height(0));
        let parent = VCN::combine(&mut ffc, left, right, &mut facts).await.unwrap();
        assert_eq!(parent, VCN::new(leaf_calculation, NodePath(0u64.into()), Length(1), Height(1)).unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_combine_left_empty_right_virtual_edge(mut ffc: FFC, #[future] leaf_calculation: LeafCalculation) {
        let leaf_calculation = leaf_calculation.await;
        let mut facts = None;

        let left = VCN::empty_node(Height(1));
        let right = VCN::new(leaf_calculation.clone(), NodePath(0u64.into()), Length(1), Height(1)).unwrap();
        let parent = VCN::combine(&mut ffc, left, right, &mut facts).await.unwrap();
        assert_eq!(parent, VCN::new(leaf_calculation, NodePath(0b10u64.into()), Length(2), Height(2)).unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_combine_left_virtual_edge_right_empty(mut ffc: FFC, #[future] leaf_calculation: LeafCalculation) {
        let leaf_calculation = leaf_calculation.await;
        let mut facts = None;

        let left = VCN::new(leaf_calculation.clone(), NodePath(1u64.into()), Length(1), Height(1)).unwrap();
        let right = VCN::empty_node(Height(1));
        let parent = VCN::combine(&mut ffc, left, right, &mut facts).await.unwrap();
        assert_eq!(parent, VCN::new(leaf_calculation, NodePath(0b01u64.into()), Length(2), Height(2)).unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_combine_two_virtual_edges(
        mut ffc: FFC,
        #[future] leaf_calculation: LeafCalculation,
        #[future] leaf_calculation2: LeafCalculation,
    ) {
        let leaf_calculation = leaf_calculation.await;
        let leaf_calculation2 = leaf_calculation2.await;
        let mut facts = None;

        let left = VCN::new(leaf_calculation.clone(), NodePath(1u64.into()), Length(1), Height(1)).unwrap();
        let right = VCN::new(leaf_calculation2.clone(), NodePath(0u64.into()), Length(1), Height(1)).unwrap();
        let parent = VCN::combine(&mut ffc, left, right, &mut facts).await.unwrap();
        assert_eq!(
            parent,
            VCN::new(
                HashCalculationImpl::Binary(BinaryCalculation::new(
                    Box::new(HashCalculationImpl::Edge(EdgeCalculation::new(
                        Box::new(leaf_calculation),
                        NodePath(1u64.into()),
                        Length(1)
                    ))),
                    Box::new(HashCalculationImpl::Edge(EdgeCalculation::new(
                        Box::new(leaf_calculation2),
                        NodePath(0u64.into()),
                        Length(1)
                    )))
                )),
                NodePath(0u64.into()),
                Length(0),
                Height(2)
            )
            .unwrap()
        );
    }
}
