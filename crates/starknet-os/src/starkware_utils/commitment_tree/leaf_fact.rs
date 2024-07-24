use crate::storage::storage::{Fact, HashFunctionType, Storage};

pub trait LeafFact<S: Storage, H: HashFunctionType>: Fact<S, H> + Sync + Sized + Clone {
    fn is_empty(&self) -> bool;
}
