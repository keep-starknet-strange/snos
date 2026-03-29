use blockifier::execution::stack_trace::{EntryPointErrorFrame, ErrorStack, ErrorStackSegment, PreambleType};
use blockifier::transaction::objects::{RevertError, TransactionExecutionInfo};
use starknet_api::block_hash::block_hash_calculator::TransactionOutputForHash;
use starknet_api::transaction::{RevertedTransactionExecutionStatus, TransactionExecutionStatus};

/// Build the transaction output used for block-hash commitments.
///
/// For constructor-based reverts, Pathfinder receipts omit VM traceback frames even though
/// Blockifier's raw `Display` includes them. Receipt commitment hashing is sensitive to the exact
/// revert-reason string, so we normalize only this receipt-hashing path to the canonical form.
pub(crate) fn transaction_output_for_block_hash(execution_info: &TransactionExecutionInfo) -> TransactionOutputForHash {
    let mut output = execution_info.output_for_hashing();

    if let Some(revert_reason) = format_revert_reason_for_block_hash(execution_info.revert_error.as_ref()) {
        output.execution_status =
            TransactionExecutionStatus::Reverted(RevertedTransactionExecutionStatus { revert_reason });
    }

    output
}

fn format_revert_reason_for_block_hash(revert_error: Option<&RevertError>) -> Option<String> {
    let revert_error = revert_error?;

    Some(match revert_error {
        RevertError::Execution(error_stack) if should_strip_vm_tracebacks(error_stack) => {
            RevertError::Execution(strip_vm_tracebacks(error_stack)).to_string()
        }
        _ => revert_error.to_string(),
    })
}

fn should_strip_vm_tracebacks(error_stack: &ErrorStack) -> bool {
    deepest_entry_point_preamble_type(error_stack) == Some(PreambleType::Constructor)
}

fn deepest_entry_point_preamble_type(error_stack: &ErrorStack) -> Option<PreambleType> {
    error_stack.stack.iter().rev().find_map(|segment| match segment {
        ErrorStackSegment::EntryPoint(entry_point) => Some(entry_point.preamble_type.clone()),
        _ => None,
    })
}

fn strip_vm_tracebacks(error_stack: &ErrorStack) -> ErrorStack {
    ErrorStack {
        header: error_stack.header.clone(),
        stack: error_stack
            .stack
            .iter()
            .filter_map(|segment| match segment {
                ErrorStackSegment::Vm(_) => None,
                ErrorStackSegment::EntryPoint(entry_point) => {
                    Some(ErrorStackSegment::EntryPoint(copy_entry_point(entry_point)))
                }
                ErrorStackSegment::Cairo1RevertSummary(summary) => {
                    Some(ErrorStackSegment::Cairo1RevertSummary(summary.clone()))
                }
                ErrorStackSegment::StringFrame(frame) => Some(ErrorStackSegment::StringFrame(frame.clone())),
            })
            .collect(),
    }
}

fn copy_entry_point(entry_point: &EntryPointErrorFrame) -> EntryPointErrorFrame {
    EntryPointErrorFrame {
        depth: entry_point.depth,
        preamble_type: entry_point.preamble_type.clone(),
        storage_address: entry_point.storage_address,
        class_hash: entry_point.class_hash,
        selector: entry_point.selector,
    }
}

#[cfg(test)]
mod tests {
    use super::{format_revert_reason_for_block_hash, transaction_output_for_block_hash};
    use blockifier::execution::stack_trace::{
        EntryPointErrorFrame, ErrorStack, ErrorStackHeader, ErrorStackSegment, PreambleType, VmExceptionFrame,
    };
    use blockifier::transaction::objects::{RevertError, TransactionExecutionInfo};
    use cairo_vm::types::relocatable::Relocatable;
    use starknet_api::transaction::{RevertedTransactionExecutionStatus, TransactionExecutionStatus};
    use starknet_api::{class_hash, contract_address, felt};

    fn copy_entry_point_for_test(
        depth: usize,
        preamble_type: PreambleType,
        storage_address: starknet_api::core::ContractAddress,
        class_hash: starknet_api::core::ClassHash,
        selector: starknet_types_core::felt::Felt,
    ) -> EntryPointErrorFrame {
        EntryPointErrorFrame {
            depth,
            preamble_type,
            storage_address,
            class_hash,
            selector: Some(starknet_api::core::EntryPointSelector(selector)),
        }
    }

    fn constructor_revert_error() -> RevertError {
        let mut stack = ErrorStack { header: ErrorStackHeader::Execution, stack: Vec::new() };
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            0,
            PreambleType::CallContract,
            contract_address!("0x0578a41eafe7e6f5a34ff42444ca7df1b04516fc2e6d4d9a65e329eeb75109de"),
            class_hash!("0x0012276b8ff0f4c1f5c3a087ddc53a263fda97a5ee784f66bcda65467be5a98c"),
            felt!("0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 2929)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:56)\nUnknown \
                 location (pc=0:1187)\nUnknown location (pc=0:1670)\nUnknown location (pc=0:2289)\n"
                    .to_string(),
            ),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            1,
            PreambleType::CallContract,
            contract_address!("0x02ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125"),
            class_hash!("0x01b2df6d8861670d4a8ca4670433b2418d78169c2947f46dc614e69f333745c8"),
            felt!("0x02730079d734ee55315f4f141eaed376bddd8c2133523d223a344c5604e0f7f8"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 774)),
            error_attr_value: None,
            traceback: Some("Cairo traceback (most recent call last):\nUnknown location (pc=0:152)\n".to_string()),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            2,
            PreambleType::Constructor,
            contract_address!("0x062d39dd09d4799967ad7201a2a7651ae7c9ace4722182b900329e0817aef9a3"),
            class_hash!("0x0012276b8ff0f4c1f5c3a087ddc53a263fda97a5ee784f66bcda65467be5a98c"),
            felt!("0x028ffe4ff0f226a9107253e17a904099aa4f63a02a5621de0576e5aa71bc5194"),
        )));
        stack.push(ErrorStackSegment::StringFrame(
            "Execution failed. Failure reason:\nError in contract (contract address: \
             0x062d39dd09d4799967ad7201a2a7651ae7c9ace4722182b900329e0817aef9a3, class hash: \
             0x0012276b8ff0f4c1f5c3a087ddc53a263fda97a5ee784f66bcda65467be5a98c, selector: \
             0x028ffe4ff0f226a9107253e17a904099aa4f63a02a5621de0576e5aa71bc5194):\n\
             0x4661696c656420746f20646573657269616c697a6520706172616d202331 ('Failed to deserialize \
             param #1').\n"
                .replace("             ", ""),
        ));

        RevertError::Execution(stack)
    }

    fn non_constructor_revert_error() -> RevertError {
        let mut stack = ErrorStack { header: ErrorStackHeader::Execution, stack: Vec::new() };
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            0,
            PreambleType::CallContract,
            contract_address!("0x1"),
            class_hash!("0x2"),
            felt!("0x3"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 12)),
            error_attr_value: None,
            traceback: Some("Cairo traceback (most recent call last):\nUnknown location (pc=0:34)\n".to_string()),
        }));
        stack.push(ErrorStackSegment::StringFrame("failure\n".to_string()));

        RevertError::Execution(stack)
    }

    #[test]
    fn constructor_revert_reason_strips_vm_tracebacks_for_block_hash() {
        let raw = constructor_revert_error().to_string();
        let formatted = format_revert_reason_for_block_hash(Some(&constructor_revert_error())).unwrap();

        assert!(raw.contains("Error at pc="));
        assert!(raw.contains("Cairo traceback (most recent call last):"));
        assert!(!formatted.contains("Error at pc="));
        assert!(!formatted.contains("Cairo traceback (most recent call last):"));
        assert!(formatted.contains("Failed to deserialize param #1"));
    }

    #[test]
    fn non_constructor_revert_reason_keeps_vm_tracebacks_for_block_hash() {
        let revert_error = non_constructor_revert_error();
        let formatted = format_revert_reason_for_block_hash(Some(&revert_error)).unwrap();

        assert_eq!(formatted, revert_error.to_string());
        assert!(formatted.contains("Error at pc="));
    }

    #[test]
    fn transaction_output_uses_normalized_constructor_revert_reason() {
        let execution_info =
            TransactionExecutionInfo { revert_error: Some(constructor_revert_error()), ..Default::default() };

        let output = transaction_output_for_block_hash(&execution_info);

        match output.execution_status {
            TransactionExecutionStatus::Reverted(RevertedTransactionExecutionStatus { revert_reason }) => {
                assert!(!revert_reason.contains("Error at pc="));
                assert!(revert_reason.contains("Failed to deserialize param #1"));
            }
            status => panic!("expected reverted execution status, got {:?}", status),
        }
    }
}
