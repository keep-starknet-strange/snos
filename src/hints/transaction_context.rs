use crate::io::InternalTransaction;

/// Implements hint:
///
/// from starkware.starknet.business_logic.transaction.objects import InternalL1Handler
/// ids.contract_address = (
///    tx.contract_address if isinstance(tx, InternalL1Handler) else tx.sender_address
/// )
pub fn load_transaction_context(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut transactions = exec_scopes.get::<Iter<InternalTransaction>>("transactions")?;
    // Safe to unwrap because the remaining number of txs is checked in the cairo code.
    let tx = transactions.next().unwrap();
    exec_scopes.insert_value("transactions", transactions);
    insert_value_from_var_name("tx_type", Felt252::from_bytes_be(tx.r#type.as_bytes()), vm, ids_data, ap_tracking)
}
