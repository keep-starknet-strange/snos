use starknet::core::types::{
    ExecuteInvocation, TransactionTrace, TransactionTraceWithHash, FunctionInvocation
};
use std::collections::HashSet;
use cairo_vm::Felt252;

    // Receives the transaction traces of a given block 
    // And extract the contracts addresses that where subcalled
    pub(crate) fn get_subcalled_contracts_from_tx_traces(traces: Vec<TransactionTraceWithHash>) -> HashSet<Felt252> {
        let mut contracts_subcalled: HashSet<Felt252> = HashSet::new();
        // let traces = provider.trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
        for trace in traces {
            match trace.trace_root {
                TransactionTrace::Invoke(invoke_trace) => {
                    if let Some(inv) = invoke_trace.validate_invocation {
                        process_function_invocations(inv, &mut contracts_subcalled);
                    }
                    match invoke_trace.execute_invocation {
                        ExecuteInvocation::Success(inv) => {
                            process_function_invocations(inv, &mut contracts_subcalled);
                        }
                        ExecuteInvocation::Reverted(_) => unimplemented!("handle reverted invoke trace"),
                    }
                    if let Some(inv) = invoke_trace.fee_transfer_invocation {
                        process_function_invocations(inv, &mut contracts_subcalled);
                    }
                }
                _ => unimplemented!("process other txn traces"),
            }
        }
        contracts_subcalled
    }

    // Utility to extract all contract address in a nested call structure. Any given call can have
    // nested calls, creating a tree structure of calls, so this fn traverses this structure and
    // returns a flat list of all contracts encountered along the way.
    fn process_function_invocations(inv: FunctionInvocation, contracts: &mut HashSet<Felt252>) {
        contracts.insert(inv.contract_address);
        for call in inv.calls {
            process_function_invocations(call, contracts);
        }
    }