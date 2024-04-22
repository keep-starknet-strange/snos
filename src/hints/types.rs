use std::collections::{HashMap, HashSet};

use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;

use crate::hints::vars;

pub type Preimage = HashMap<Felt252, Vec<Felt252>>;

#[derive(Clone, Debug, PartialEq)]
pub struct PatriciaSkipValidationRunner {
    pub verified_addresses: HashSet<Relocatable>,
}

/// Inserts a hash result address in `__patricia_skip_validation_runner` if it exists.
///
/// This skips validation of the preimage dict to speed up the VM. When this flag is set,
/// mistakes in the preimage dict will be discovered only in the prover.
pub fn skip_verification_if_configured(
    exec_scopes: &mut ExecutionScopes,
    address: Relocatable,
) -> Result<(), HintError> {
    let patricia_skip_validation_runner: &mut Option<PatriciaSkipValidationRunner> =
        exec_scopes.get_mut_ref(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER)?;
    if let Some(skipped) = patricia_skip_validation_runner {
        skipped.verified_addresses.insert(address);
    }

    Ok(())
}
