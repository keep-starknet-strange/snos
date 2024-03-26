use std::any::Any;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactDict;
use crate::starkware_utils::commitment_tree::errors::CombineError;
use crate::starkware_utils::commitment_tree::leaf_fact::LeafFact;
use crate::starkware_utils::commitment_tree::patricia_tree::nodes::PatriciaNodeFact;
use crate::storage::storage::{FactFetchingContext, HashFunctionType, Storage};

// These enums are used instead of trait objects because the conditions to turn
// LeafFact and InnerNodeFact into object safe traits are complex to lift: multiple places where
// `Sized` is required, async methods, generic type parameters, etc.
// This can be solved somehow by moving some features to `Storage`, but is out of scope for now.
// These enums do the trick in the meantime, at the cost of a little flexibility.

pub type CalculationInnerNodeFact = PatriciaNodeFact;

/// A mapping between a hash and its corresponding fact. Split into two maps, one for leaves and
/// one for inner nodes.
pub struct NodeFactDict<LF> {
    pub inner_nodes: HashMap<Vec<u8>, CalculationInnerNodeFact>,
    pub leaves: HashMap<Vec<u8>, LF>,
}

impl<LF> Default for NodeFactDict<LF> {
    fn default() -> Self {
        Self { inner_nodes: Default::default(), leaves: Default::default() }
    }
}

/// A calculation that can produce a result of type T. The calculation is dependent on the results
/// of other calculations. Those calculations can be of type other than T.
/// The result of the calculation can be produced when the results of the dependency calculations
/// are given.
pub trait Calculation<T, LF> {
    /// Returns a list of the calculations that this calculation depends on.
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>>;

    /// Produces the result of this calculation, given a list of results for the dependency
    /// calculations. The order of dependency_results should match the order of the list returned by
    /// get_dependency_calculations.
    ///
    /// The calculation might need to calculate hashes along the way. It will use hash_func for
    /// that.
    ///
    /// Any facts generated during the calculation will be saved in fact_nodes
    /// (using their hash as the key).
    fn calculate(&self, dependency_results: Vec<Box<dyn Any>>, fact_nodes: &mut NodeFactDict<LF>) -> T;

    /// Same as calculate(), but return the facts.

    fn calculate_new_fact_nodes(&self, dependency_results: Vec<Box<dyn Any>>) -> (T, NodeFactDict<LF>) {
        let mut fact_nodes = NodeFactDict::default();
        let result = self.calculate(dependency_results, &mut fact_nodes);

        (result, fact_nodes)
    }

    /// Produces the result of this calculation.
    ///
    /// Recursively calculates the result of the dependency calculations.
    ///
    /// Any facts generated during the calculation will be saved in fact_nodes
    /// (using their hash as the key).
    fn full_calculate(&self, fact_nodes: &mut NodeFactDict<LF>) -> T {
        let dependency_results: Vec<Box<dyn Any>> = self
            .get_dependency_calculations()
            .iter()
            .map(|calculation| calculation.full_calculate(fact_nodes))
            .collect();

        self.calculate(dependency_results, fact_nodes)
    }

    /// Produces the result of this calculation. Returns the result and a dict containing generated
    /// facts.
    ///
    /// Recursively calculates the result of the dependency calculations.
    fn full_calculate_new_fact_nodes(&self) -> (T, NodeFactDict<LF>) {
        let mut fact_nodes = NodeFactDict::default();
        let result = self.full_calculate(&mut fact_nodes);

        (result, fact_nodes)
    }
}

pub(crate) struct DependencyWrapper<D, T, LF>
where
    D: Calculation<T, LF>,
{
    inner: D,
    _t: PhantomData<T>,
    _lf: PhantomData<LF>,
}

impl<D, T, LF> DependencyWrapper<D, T, LF>
where
    D: Calculation<T, LF>,
{
    pub fn new(wrapped: D) -> Self {
        Self { inner: wrapped, _t: Default::default(), _lf: Default::default() }
    }
}
impl<D, T, LF> Calculation<Box<dyn Any>, LF> for DependencyWrapper<D, T, LF>
where
    D: Calculation<T, LF>,
    T: 'static,
{
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        self.inner.get_dependency_calculations()
    }

    fn calculate(&self, dependency_results: Vec<Box<dyn Any>>, fact_nodes: &mut NodeFactDict<LF>) -> Box<dyn Any> {
        Box::new(self.inner.calculate(dependency_results, fact_nodes))
    }
}

pub(crate) trait HashCalculation<LF>: Calculation<Vec<u8>, LF> {
    /// Method that allows cloning a Box<dyn HashCalculation> despite not being able to
    /// require Clone.
    /// Note that we could use https://github.com/dtolnay/dyn-clone for a more generic
    /// approach.
    fn clone_box(&self) -> Box<dyn HashCalculation<LF>>;
}

/// A calculation that contains a value and simply produces it. It doesn't depend on any other
/// calculations.
#[derive(Clone, Debug, PartialEq)]
pub struct ConstantCalculation<T>
where
    T: Clone,
{
    pub value: T,
}

impl<T> ConstantCalculation<T>
where
    T: Clone,
{
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T, LF> Calculation<T, LF> for ConstantCalculation<T>
where
    T: Clone,
{
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        vec![]
    }

    fn calculate(&self, _dependency_results: Vec<Box<dyn Any>>, _fact_nodes: &mut NodeFactDict<LF>) -> T {
        self.value.clone()
    }
}

impl<LF> HashCalculation<LF> for ConstantCalculation<Vec<u8>> {
    fn clone_box(&self) -> Box<dyn HashCalculation<LF>> {
        Box::new(self.clone())
    }
}

// Required for the implementation of VirtualCalculationNode
impl<LF> Calculation<Vec<u8>, LF> for Box<dyn HashCalculation<LF>> {
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        (**self).get_dependency_calculations()
    }

    fn calculate(&self, dependency_results: Vec<Box<dyn Any>>, fact_nodes: &mut NodeFactDict<LF>) -> Vec<u8> {
        (**self).calculate(dependency_results, fact_nodes)
    }
}

// Required for the implementation of VirtualCalculationNode
impl<LF> HashCalculation<LF> for Box<dyn HashCalculation<LF>> {
    fn clone_box(&self) -> Box<dyn HashCalculation<LF>> {
        (**self).clone_box()
    }
}

#[derive(Debug, PartialEq)]
pub struct LeafFactCalculation<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    pub fact: LF,
    _phantom: PhantomData<(S, H)>,
}

impl<S, H, LF> LeafFactCalculation<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    pub fn new(fact: LF) -> Self {
        Self { fact, _phantom: Default::default() }
    }
}

// A custom implementation is required to avoid requiring Clone on Storage and HashFunctionType
// because of the PhantomData fields in the struct.
impl<S, H, LF> Clone for LeafFactCalculation<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    fn clone(&self) -> Self {
        Self::new(self.fact.clone())
    }
}

impl<S, H, LF> Calculation<Vec<u8>, LF> for LeafFactCalculation<S, H, LF>
where
    S: Storage,
    H: HashFunctionType,
    LF: LeafFact<S, H>,
{
    fn get_dependency_calculations(&self) -> Vec<Box<dyn Calculation<Box<dyn Any>, LF>>> {
        vec![]
    }

    fn calculate(&self, _dependency_results: Vec<Box<dyn Any>>, fact_nodes: &mut NodeFactDict<LF>) -> Vec<u8> {
        let hash_result = self.fact.hash();
        fact_nodes.leaves.insert(hash_result.clone(), self.fact.clone());
        hash_result
    }
}

impl<S, H, LF> HashCalculation<LF> for LeafFactCalculation<S, H, LF>
where
    S: Storage + 'static,
    H: HashFunctionType + 'static,
    LF: LeafFact<S, H> + 'static,
{
    fn clone_box(&self) -> Box<dyn HashCalculation<LF>> {
        Box::new(Self { fact: self.fact.clone(), _phantom: Default::default() })
    }
}

/// A calculation that produces a BinaryFactTreeNode. The calculation can be created from either
/// a node or from a combination of two other calculations of the same type.
#[allow(async_fn_in_trait)]
pub trait CalculationNode<S, H, LF>: Sized + Clone
where
    S: Storage + Sync + Send,
    H: HashFunctionType + Sync + Send,
    LF: LeafFact<S, H>,
{
    type BinaryFactTreeNodeType;

    /// Combines two calculations into a calculation that its children are the given calculations.
    /// The function might need to read facts from the DB using FFC.
    /// If so, and if facts argument is not None, facts is filled with the facts read.
    async fn combine(
        ffc: &mut FactFetchingContext<S, H>,
        left: Self,
        right: Self,
        facts: &mut Option<BinaryFactDict>,
    ) -> Result<Self, CombineError>;

    /// Creates a Calculation object from a node. It will produce the node and will have no
    /// dependencies.
    /// This will be used in order to create calculations that represent unchanged subtrees.
    fn create_from_node(node: &Self::BinaryFactTreeNodeType) -> Self;

    /// Creates a Calculation object from a fact. It will calculate the fact's hash and produce a
    /// node with the hash result. It will have no dependencies.
    /// This will be used in order to create calculations that represent changed leaves.
    fn create_from_fact(fact: LF) -> Self;
}
