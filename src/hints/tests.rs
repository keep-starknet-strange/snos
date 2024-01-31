#[cfg(test)]
mod tests {

    use cairo_vm::{
        serde::deserialize_program::ApTracking,
        types::exec_scope::ExecutionScopes,
    };
    use num_bigint::BigInt;

    use crate::hints::*;
    
    #[test]
    fn test_set_ap_to_actual_fee_hint() {
        let mut vm = VirtualMachine::new(false);
        // TODO: allocate memory?

        let ids_data = Default::default();
        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();
        
        // TODO: inject execution_hepler (whose responsibility is this by design?)
        // TODO: inject transaction data / fee
        
        set_ap_to_actual_fee(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default())
            .expect("set_ap_to_actual_fee() failed");
        
    }
}