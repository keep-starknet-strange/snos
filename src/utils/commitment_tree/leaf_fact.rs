use crate::storage::Fact;

pub trait LeafFact: Fact {
    /// Returns true iff the fact represents a leaf that has no value or was deleted.
    fn is_empty(&self) -> bool;
}
