use std::collections::{HashMap, HashSet};

use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::Felt252;

pub type Preimage = HashMap<Felt252, Vec<Felt252>>;

#[derive(Clone, Debug, PartialEq)]
pub struct PatriciaSkipValidationRunner {
    pub verified_addresses: HashSet<Relocatable>,
}

// TODO: define correctly when implementing the descend functionality
pub type DescentMap = HashMap<(Felt252, Felt252), Vec<Felt252>>;
