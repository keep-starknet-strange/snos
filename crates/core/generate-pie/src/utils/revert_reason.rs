use blockifier::execution::stack_trace::{EntryPointErrorFrame, ErrorStack, ErrorStackSegment, PreambleType};
use blockifier::transaction::objects::{RevertError, TransactionExecutionInfo};
use starknet_api::block_hash::block_hash_calculator::TransactionOutputForHash;
use starknet_api::transaction::{RevertedTransactionExecutionStatus, TransactionExecutionStatus};

/// Build the transaction output used for block-hash commitments.
///
/// For nested revert summaries, Pathfinder receipts omit the intermediate VM traceback frames even
/// though Blockifier's raw `Display` includes them. Receipt commitment hashing is sensitive to the
/// exact revert-reason string, so we normalize only this receipt-hashing path to the canonical
/// form.
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
    is_nested_constructor_failure(error_stack) || is_undeployed_contract_failure(error_stack)
}

/// Constructor-chain failures: a `Constructor` frame wrapped in another "Execution failed" /
/// Cairo1 revert frame. Pathfinder strips the VM tracebacks for this shape.
fn is_nested_constructor_failure(error_stack: &ErrorStack) -> bool {
    has_constructor_frame(error_stack)
        && error_stack.stack.iter().any(|segment| match segment {
            ErrorStackSegment::Cairo1RevertSummary(_) => true,
            ErrorStackSegment::StringFrame(frame) => frame.starts_with("Execution failed. Failure reason:\n"),
            _ => false,
        })
}

/// "Callee not deployed" failures: a contract call targets an address with no class, so the call
/// never enters Cairo. The chain stores the receipt with the caller's VM traceback stripped
/// (the canonical receipt for this shape omits the intermediate `Error at pc=...` frames), so the
/// receipt commitment must be computed over that stripped form.
fn is_undeployed_contract_failure(error_stack: &ErrorStack) -> bool {
    error_stack
        .stack
        .iter()
        .any(|segment| matches!(segment, ErrorStackSegment::StringFrame(frame) if frame.contains("is not deployed.")))
}

fn has_constructor_frame(error_stack: &ErrorStack) -> bool {
    error_stack.stack.iter().any(|segment| match segment {
        ErrorStackSegment::EntryPoint(entry_point) => matches!(entry_point.preamble_type, PreambleType::Constructor),
        _ => false,
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
    use super::{format_revert_reason_for_block_hash, should_strip_vm_tracebacks, transaction_output_for_block_hash};
    use blockifier::execution::stack_trace::{
        Cairo1RevertFrame, Cairo1RevertHeader, Cairo1RevertSummary, EntryPointErrorFrame, ErrorStack, ErrorStackHeader,
        ErrorStackSegment, PreambleType, VmExceptionFrame,
    };
    use blockifier::transaction::objects::{RevertError, TransactionExecutionInfo};
    use cairo_vm::types::relocatable::Relocatable;
    use starknet_api::hash::starknet_keccak_hash;
    use starknet_api::transaction::{RevertedTransactionExecutionStatus, TransactionExecutionStatus};
    use starknet_api::{class_hash, contract_address, felt};
    use starknet_types_core::felt::Felt;

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

    /// Real "callee not deployed" revert from Paradex mocknet block 138087, tx
    /// `0x37e4ace7cf678da99e30d39c32677dd197a7babbd51b4d05e4faccf921cfa8d`: a `CallContract` whose
    /// callee (class hash `0x0`) is not deployed. Blockifier renders the caller's VM traceback, but
    /// the canonical chain receipt omits it, so the receipt-hashing path must strip it.
    fn undeployed_contract_revert_error() -> RevertError {
        let mut stack = ErrorStack { header: ErrorStackHeader::Execution, stack: Vec::new() };
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            0,
            PreambleType::CallContract,
            contract_address!("0x01fa85856d49323676bf3c6d81e19e444285f6f036ebeaa1770887d12b71b0de"),
            class_hash!("0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2"),
            felt!("0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 35988)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:330)\nUnknown location \
                 (pc=0:11695)\n"
                    .replace("                 ", ""),
            ),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            1,
            PreambleType::CallContract,
            contract_address!("0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf"),
            class_hash!("0x0"),
            felt!("0x01987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d"),
        )));
        stack.push(ErrorStackSegment::StringFrame(
            "Requested contract address 0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf is not \
             deployed.\n"
                .replace("             ", ""),
        ));
        RevertError::Execution(stack)
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

    fn constructor_deployment_failure_revert_error() -> RevertError {
        let mut stack = ErrorStack { header: ErrorStackHeader::Execution, stack: Vec::new() };
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            0,
            PreambleType::CallContract,
            contract_address!("0x03666fcf7f5c9195d08464c5f2713d756864220f02342bd2382f781afc1c2b0d"),
            class_hash!("0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564"),
            felt!("0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 7331)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:188)\nUnknown location \
                 (pc=0:2616)\nUnknown location (pc=0:3553)\nUnknown location (pc=0:4820)\nUnknown \
                 location (pc=0:5564)\nUnknown location (pc=0:6675)\n"
                    .replace("                 ", ""),
            ),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            1,
            PreambleType::CallContract,
            contract_address!("0x076f0c5e5a7c9ded2d875321902d958dafa28a40bd56b51b6c983df94d7e03c9"),
            class_hash!("0x0637eda47d4e51b44a71ae559a69601ea8fcda38dfc1345665a8465ebe02a2e9"),
            felt!("0x00161dc77f8e29b5e4194910df4cf7368b6c3c4ef7168245d7b194c9402b3fa6"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 651)),
            error_attr_value: None,
            traceback: Some("Cairo traceback (most recent call last):\nUnknown location (pc=0:70)\n".to_string()),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            2,
            PreambleType::Constructor,
            contract_address!("0x03673e9f0d6396cac1c232bfbfb2155d7bcc3af7e0268e440b4822c8145e47c4"),
            class_hash!("0x07efbb7f0a20d7fa7d25ff24fff9a974695c109ff17696aa8a68b105542c5cd3"),
            felt!("0x0"),
        )));
        stack.push(ErrorStackSegment::StringFrame(
            "Deployment failed: contract already deployed at address \
             0x03673e9f0d6396cac1c232bfbfb2155d7bcc3af7e0268e440b4822c8145e47c4\n"
                .replace("             ", ""),
        ));

        RevertError::Execution(stack)
    }

    fn nested_library_revert_error() -> RevertError {
        let mut stack = ErrorStack { header: ErrorStackHeader::Execution, stack: Vec::new() };
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            0,
            PreambleType::CallContract,
            contract_address!("0x059ca23468e45338238bee2787d4143f42214b479d8c149846c98c3675ae5e62"),
            class_hash!("0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"),
            felt!("0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 12)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:161)\nUnknown location (pc=0:147)\n"
                    .to_string(),
            ),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            1,
            PreambleType::LibraryCall,
            contract_address!("0x059ca23468e45338238bee2787d4143f42214b479d8c149846c98c3675ae5e62"),
            class_hash!("0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2"),
            felt!("0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 39)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:1398)\nUnknown location \
                 (pc=0:1351)\nUnknown location (pc=0:569)\n"
                    .replace("                 ", ""),
            ),
        }));
        stack.push(ErrorStackSegment::StringFrame(
            "Error message: argent: multicall 6:6 failed\nUnknown location (pc=0:586)\n".to_string(),
        ));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            2,
            PreambleType::CallContract,
            contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"),
            class_hash!("0x02e77ee61d4df3d988ee1f42ea5442e913862cc82c2584d212ecda76666498fc"),
            felt!("0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"),
        )));
        stack.push(ErrorStackSegment::StringFrame(
            "Execution failed. Failure reason:\nError in contract (contract address: \
             0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d, class hash: \
             0x02e77ee61d4df3d988ee1f42ea5442e913862cc82c2584d212ecda76666498fc, selector: \
             0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e):\n\
             0x496e70757420746f6f206c6f6e6720666f7220617267756d656e7473 ('Input too long for arguments').\n"
                .replace("             ", ""),
        ));

        RevertError::Execution(stack)
    }

    fn cairo1_revert_summary_error() -> RevertError {
        let mut stack = ErrorStack { header: ErrorStackHeader::Execution, stack: Vec::new() };
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            0,
            PreambleType::CallContract,
            contract_address!("0x578a41eafe7e6f5a34ff42444ca7df1b04516fc2e6d4d9a65e329eeb75109de"),
            class_hash!("0x12276b8ff0f4c1f5c3a087ddc53a263fda97a5ee784f66bcda65467be5a98c"),
            felt!("0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 2929)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:56)\nUnknown location \
                 (pc=0:1187)\nUnknown location (pc=0:1670)\nUnknown location (pc=0:2289)\n"
                    .replace("                 ", ""),
            ),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            1,
            PreambleType::Constructor,
            contract_address!("0x62d39dd09d4799967ad7201a2a7651ae7c9ace4722182b900329e0817aef9a3"),
            class_hash!("0x12276b8ff0f4c1f5c3a087ddc53a263fda97a5ee784f66bcda65467be5a98c"),
            felt!("0x28ffe4ff0f226a9107253e17a904099aa4f63a02a5621de0576e5aa71bc5194"),
        )));
        stack.push(ErrorStackSegment::Cairo1RevertSummary(Cairo1RevertSummary {
            header: Cairo1RevertHeader::Execution,
            stack: vec![Cairo1RevertFrame {
                contract_address: contract_address!(
                    "0x62d39dd09d4799967ad7201a2a7651ae7c9ace4722182b900329e0817aef9a3"
                ),
                class_hash: Some(class_hash!("0x12276b8ff0f4c1f5c3a087ddc53a263fda97a5ee784f66bcda65467be5a98c")),
                selector: starknet_api::core::EntryPointSelector(felt!(
                    "0x28ffe4ff0f226a9107253e17a904099aa4f63a02a5621de0576e5aa71bc5194"
                )),
            }],
            last_retdata: blockifier::execution::call_info::Retdata(vec![felt!(
                "0x4661696c656420746f20646573657269616c697a6520706172616d202331"
            )]),
        }));

        RevertError::Execution(stack)
    }

    fn nested_library_cairo1_revert_summary_error() -> RevertError {
        let mut stack = ErrorStack { header: ErrorStackHeader::Execution, stack: Vec::new() };
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            0,
            PreambleType::CallContract,
            contract_address!("0x059ca23468e45338238bee2787d4143f42214b479d8c149846c98c3675ae5e62"),
            class_hash!("0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"),
            felt!("0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 12)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:161)\nUnknown location (pc=0:147)\n"
                    .to_string(),
            ),
        }));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            1,
            PreambleType::LibraryCall,
            contract_address!("0x059ca23468e45338238bee2787d4143f42214b479d8c149846c98c3675ae5e62"),
            class_hash!("0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2"),
            felt!("0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"),
        )));
        stack.push(ErrorStackSegment::Vm(VmExceptionFrame {
            pc: Relocatable::from((0, 39)),
            error_attr_value: None,
            traceback: Some(
                "Cairo traceback (most recent call last):\nUnknown location (pc=0:1398)\nUnknown location \
                 (pc=0:1351)\nUnknown location (pc=0:569)\n"
                    .replace("                 ", ""),
            ),
        }));
        stack.push(ErrorStackSegment::StringFrame(
            "Error message: argent: multicall 6:6 failed\nUnknown location (pc=0:586)\n".to_string(),
        ));
        stack.push(ErrorStackSegment::EntryPoint(copy_entry_point_for_test(
            2,
            PreambleType::CallContract,
            contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"),
            class_hash!("0x02e77ee61d4df3d988ee1f42ea5442e913862cc82c2584d212ecda76666498fc"),
            felt!("0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"),
        )));
        stack.push(ErrorStackSegment::Cairo1RevertSummary(Cairo1RevertSummary {
            header: Cairo1RevertHeader::Execution,
            stack: vec![Cairo1RevertFrame {
                contract_address: contract_address!(
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
                ),
                class_hash: Some(class_hash!("0x02e77ee61d4df3d988ee1f42ea5442e913862cc82c2584d212ecda76666498fc")),
                selector: starknet_api::core::EntryPointSelector(felt!(
                    "0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"
                )),
            }],
            last_retdata: blockifier::execution::call_info::Retdata(vec![felt!(
                "0x496e70757420746f6f206c6f6e6720666f7220617267756d656e7473"
            )]),
        }));

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
    fn constructor_deployment_failure_keeps_outer_vm_tracebacks_for_block_hash() {
        let revert_error = constructor_deployment_failure_revert_error();
        let formatted = format_revert_reason_for_block_hash(Some(&revert_error)).unwrap();

        assert_eq!(formatted, revert_error.to_string());
        assert!(formatted.contains("Error at pc=0:7331:"));
        assert!(formatted.contains("Error at pc=0:651:"));
        assert!(formatted.contains("Deployment failed: contract already deployed"));
    }

    #[test]
    fn nested_library_revert_keeps_vm_tracebacks_for_block_hash() {
        let revert_error = nested_library_revert_error();
        let formatted = format_revert_reason_for_block_hash(Some(&revert_error)).unwrap();

        assert_eq!(formatted, revert_error.to_string());
        assert!(formatted.contains("Error at pc=0:12:"));
        assert!(formatted.contains("Error at pc=0:39:"));
        assert!(formatted.contains("argent: multicall 6:6 failed"));
        assert!(formatted.contains("Input too long for arguments"));
    }

    #[test]
    fn nested_library_cairo1_revert_summary_keeps_vm_tracebacks_for_block_hash() {
        let revert_error = nested_library_cairo1_revert_summary_error();
        let formatted = format_revert_reason_for_block_hash(Some(&revert_error)).unwrap();

        assert_eq!(formatted, revert_error.to_string());
        assert!(formatted.contains("Error at pc=0:12:"));
        assert!(formatted.contains("Error at pc=0:39:"));
        assert!(formatted.contains("argent: multicall 6:6 failed"));
        assert!(formatted.contains("Input too long for arguments"));
    }

    #[test]
    fn cairo1_revert_summary_strips_vm_tracebacks_for_block_hash() {
        let revert_error = cairo1_revert_summary_error();
        let formatted = format_revert_reason_for_block_hash(Some(&revert_error)).unwrap();

        assert!(!formatted.contains("Error at pc="));
        assert!(!formatted.contains("Cairo traceback (most recent call last):"));
        assert!(formatted.contains("Execution failed. Failure reason:"));
        assert!(formatted.contains("Failed to deserialize param #1"));
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

    #[test]
    fn constructor_revert_reason_hash_regression() {
        let revert_reason = format_revert_reason_for_block_hash(Some(&constructor_revert_error())).unwrap();
        let revert_reason_hash = starknet_keccak_hash(revert_reason.as_bytes());

        assert_eq!(
            revert_reason_hash,
            Felt::from_hex("0x3d5c1a26ccc599f79dfe517f780f66b8bc318325bc77c9acfafb848de869de4").unwrap()
        );
    }

    #[test]
    fn undeployed_contract_revert_strips_vm_tracebacks_for_block_hash() {
        let revert_error = undeployed_contract_revert_error();
        let raw = revert_error.to_string();
        let formatted = format_revert_reason_for_block_hash(Some(&revert_error)).unwrap();

        // The strip gate must fire for this non-constructor "not deployed" shape.
        match &revert_error {
            RevertError::Execution(stack) => assert!(should_strip_vm_tracebacks(stack)),
            other => panic!("expected execution revert, got {other:?}"),
        }

        // Blockifier's raw string carries the caller's VM traceback; the receipt form drops it.
        assert!(raw.contains("Error at pc="));
        assert!(raw.contains("Cairo traceback (most recent call last):"));
        assert!(!formatted.contains("Error at pc="));
        assert!(!formatted.contains("Cairo traceback (most recent call last):"));
        assert!(formatted.contains("is not deployed."));
        assert!(formatted.len() < raw.len());
    }

    #[test]
    fn transaction_output_uses_stripped_undeployed_revert_reason() {
        let execution_info =
            TransactionExecutionInfo { revert_error: Some(undeployed_contract_revert_error()), ..Default::default() };

        let output = transaction_output_for_block_hash(&execution_info);

        match output.execution_status {
            TransactionExecutionStatus::Reverted(RevertedTransactionExecutionStatus { revert_reason }) => {
                assert!(!revert_reason.contains("Error at pc="));
                assert!(revert_reason.contains("is not deployed."));
            }
            status => panic!("expected reverted execution status, got {:?}", status),
        }
    }

    /// Pins the exact receipt revert-reason bytes for Paradex mocknet block 138087 tx
    /// `0x37e4ace…`. This hash is the `starknet_keccak` of the 701-char canonical receipt string
    /// that reproduces the on-chain `receipt_commitment` 0x286ef01f…aaf2b5 (and hence block hash
    /// 0x43fabc6f…857f50). If this changes, SNOS no longer matches the chain for this shape.
    #[test]
    fn undeployed_contract_revert_reason_hash_regression() {
        let revert_reason = format_revert_reason_for_block_hash(Some(&undeployed_contract_revert_error())).unwrap();
        let revert_reason_hash = starknet_keccak_hash(revert_reason.as_bytes());

        assert_eq!(
            revert_reason_hash,
            Felt::from_hex("0xc31ec2f2982ccf63b72284efb04987782f6bc43b64d0a1fa0092e1e334c67e").unwrap()
        );
    }
}
