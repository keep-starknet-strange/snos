use num_bigint::BigUint;

use crate::storage::storage::{Fact, HashFunctionType, Storage};

pub trait InnerNodeFact<S, H>: Fact<S, H>
where
    S: Storage,
    H: HashFunctionType,
{
    fn to_tuple(&self) -> Vec<BigUint>;
}
