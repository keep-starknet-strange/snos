use cairo_vm::Felt252;

pub trait KzgCommitmentComputer {
    fn compute_kzg_commitment_from_coefficients(&self, coefficients: &[Felt252]) -> (Felt252, Felt252);
}

/// A struct with a default implementation of the KZG commitment computation.
///
/// We do not know yet how to compute the KZG commitment, this structure is a default
/// implementation that will panic until we figure it out properly.
#[derive(Debug)]
pub struct PlaceholderKzgCommitmentComputer;

impl KzgCommitmentComputer for PlaceholderKzgCommitmentComputer {
    fn compute_kzg_commitment_from_coefficients(&self, _coefficients: &[Felt252]) -> (Felt252, Felt252) {
        todo!("Define correct method to compute KZG commitment");
    }
}
