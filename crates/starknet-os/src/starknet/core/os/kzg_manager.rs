use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;

#[derive(Debug, Default)]
pub struct KzgManager {
    da_segment: Option<Vec<Felt252>>,
}

impl KzgManager {
    pub fn store_da_segment(&mut self, da_segment: Vec<Felt252>) -> Result<(), HintError> {
        // Stores the data-availabilty segment, to be used for computing the KZG commitment
        // and published on L1 using a blob transaction.

        if self.da_segment.is_some() {
            return Err(HintError::AssertionFailed("DA segment is already initialized.".to_string().into_boxed_str()));
        }

        self.da_segment = Some(da_segment);

        Ok(())
    }
}
