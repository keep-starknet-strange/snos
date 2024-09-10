use std::sync::Arc;

use cairo_vm::Felt252;
use rpc_replay::transactions::resource_bounds_core_to_api;
use starknet::core::types::{
    DataAvailabilityMode, DeclareTransaction, DeclareTransactionV0, DeclareTransactionV1, DeclareTransactionV2,
    DeclareTransactionV3, DeployAccountTransaction, DeployAccountTransactionV1, DeployAccountTransactionV3,
    InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction,
    Transaction,
};
use starknet_api::core::{calculate_contract_address, ClassHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_os::io::InternalTransaction;

// entry point for "__execute__"
const EXECUTE_ENTRY_POINT_FELT: Felt252 =
    Felt252::from_hex_unchecked("0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad");

fn da_to_felt(data_availability_mode: DataAvailabilityMode) -> Felt252 {
    match data_availability_mode {
        DataAvailabilityMode::L1 => Felt252::ZERO,
        DataAvailabilityMode::L2 => Felt252::ONE,
    }
}

fn invoke_tx_v0_to_internal_tx(tx: InvokeTransactionV0) -> InternalTransaction {
    InternalTransaction {
        hash_value: tx.transaction_hash,
        max_fee: Some(tx.max_fee),
        signature: Some(tx.signature),
        contract_address: Some(tx.contract_address),
        entry_point_selector: Some(tx.entry_point_selector),
        calldata: Some(tx.calldata),
        version: Some(Felt252::ZERO),
        ..Default::default()
    }
}
fn invoke_tx_v1_to_internal_tx(tx: InvokeTransactionV1) -> InternalTransaction {
    InternalTransaction {
        hash_value: tx.transaction_hash,
        version: Some(Felt252::ONE),
        contract_address: Some(tx.sender_address),
        nonce: Some(tx.nonce),
        sender_address: Some(tx.sender_address),
        entry_point_selector: Some(EXECUTE_ENTRY_POINT_FELT),
        entry_point_type: Some("EXTERNAL".to_string()),
        signature: Some(tx.signature),
        calldata: Some(tx.calldata),
        r#type: "INVOKE_FUNCTION".to_string(),
        max_fee: Some(tx.max_fee),
        ..Default::default()
    }
}

fn invoke_tx_v3_to_internal_tx(tx: InvokeTransactionV3) -> InternalTransaction {
    InternalTransaction {
        hash_value: tx.transaction_hash,
        sender_address: Some(tx.sender_address),
        signature: Some(tx.signature),
        nonce: Some(tx.nonce),
        resource_bounds: Some(resource_bounds_core_to_api(&tx.resource_bounds)),
        tip: Some(Felt252::from(tx.tip)),
        paymaster_data: Some(tx.paymaster_data),
        account_deployment_data: Some(tx.account_deployment_data),
        nonce_data_availability_mode: Some(da_to_felt(tx.nonce_data_availability_mode)),
        fee_data_availability_mode: Some(da_to_felt(tx.fee_data_availability_mode)),
        version: Some(Felt252::THREE),
        contract_address: Some(tx.sender_address),
        entry_point_selector: Some(EXECUTE_ENTRY_POINT_FELT),
        entry_point_type: Some("EXTERNAL".to_string()),
        calldata: Some(tx.calldata),
        ..Default::default()
    }
}

fn invoke_tx_to_internal_tx(invoke_tx: InvokeTransaction) -> InternalTransaction {
    let mut internal_tx = match invoke_tx {
        InvokeTransaction::V0(invoke_v0_tx) => invoke_tx_v0_to_internal_tx(invoke_v0_tx),
        InvokeTransaction::V1(invoke_v1_tx) => invoke_tx_v1_to_internal_tx(invoke_v1_tx),
        InvokeTransaction::V3(invoke_v3_tx) => invoke_tx_v3_to_internal_tx(invoke_v3_tx),
    };
    internal_tx.r#type = "INVOKE_FUNCTION".into();

    internal_tx
}

fn l1handler_to_internal_tx(input: L1HandlerTransaction) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        version: Some(input.version),
        contract_address: Some(input.contract_address),
        nonce: Some(Felt252::from(input.nonce)),
        entry_point_selector: Some(input.entry_point_selector),
        calldata: Some(input.calldata),
        r#type: "L1_HANDLER".to_string(),
        ..Default::default()
    }
}

fn declare_v0_to_internal_tx(input: DeclareTransactionV0) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        class_hash: Some(input.class_hash),
        r#type: "DECLARE".to_string(),
        version: Some(Felt252::ZERO),
        ..Default::default()
    }
}

fn declare_v1_to_internal_tx(input: DeclareTransactionV1) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        class_hash: Some(input.class_hash),
        r#type: "DECLARE".to_string(),
        version: Some(Felt252::ONE),
        ..Default::default()
    }
}

fn declare_v2_to_internal_tx(input: DeclareTransactionV2) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        compiled_class_hash: Some(input.compiled_class_hash),
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        class_hash: Some(input.class_hash),
        r#type: "DECLARE".to_string(),
        version: Some(Felt252::TWO),
        ..Default::default()
    }
}

fn declare_v3_to_internal_tx(input: DeclareTransactionV3) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        compiled_class_hash: Some(input.compiled_class_hash),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        class_hash: Some(input.class_hash),
        resource_bounds: Some(resource_bounds_core_to_api(&input.resource_bounds)),
        tip: Some(Felt252::from(input.tip)),
        paymaster_data: Some(input.paymaster_data.into_iter().map(Felt252::from).collect()),
        account_deployment_data: Some(input.account_deployment_data.into_iter().map(Felt252::from).collect()),
        nonce_data_availability_mode: Some(da_to_felt(input.nonce_data_availability_mode)),
        fee_data_availability_mode: Some(da_to_felt(input.fee_data_availability_mode)),
        r#type: "DECLARE".to_string(),
        version: Some(Felt252::THREE),
        ..Default::default()
    }
}

fn deploy_account_v1_to_internal_tx(input: DeployAccountTransactionV1) -> InternalTransaction {
    let entry_point_selector = Some(Felt252::ZERO);
    InternalTransaction {
        hash_value: input.transaction_hash,
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        contract_address_salt: Some(input.contract_address_salt),
        constructor_calldata: Some(input.constructor_calldata.clone()),
        class_hash: Some(input.class_hash),
        r#type: "DEPLOY_ACCOUNT".to_string(),
        version: Some(Felt252::ONE),
        entry_point_selector,
        contract_address: Some(
            *calculate_contract_address(
                ContractAddressSalt(input.contract_address_salt),
                ClassHash(input.class_hash),
                &Calldata(Arc::new(input.constructor_calldata)),
                Default::default(),
            )
            .unwrap()
            .0
            .key(),
        ),
        ..Default::default()
    }
}

pub fn deploy_account_v3_to_internal_tx(input: DeployAccountTransactionV3) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        contract_address_salt: Some(input.contract_address_salt),
        constructor_calldata: Some(input.constructor_calldata.into_iter().map(Felt252::from).collect()),
        class_hash: Some(input.class_hash),
        resource_bounds: Some(resource_bounds_core_to_api(&input.resource_bounds)),
        tip: Some(Felt252::from(input.tip)),
        paymaster_data: Some(input.paymaster_data.into_iter().map(Felt252::from).collect()),
        nonce_data_availability_mode: Some(da_to_felt(input.nonce_data_availability_mode)),
        fee_data_availability_mode: Some(da_to_felt(input.fee_data_availability_mode)),
        r#type: "DEPLOY_ACCOUNT".to_string(),
        version: Some(Felt252::THREE),
        ..Default::default()
    }
}

pub(crate) fn starknet_rs_tx_to_internal_tx(tx: Transaction) -> InternalTransaction {
    match tx {
        Transaction::Invoke(invoke_tx) => invoke_tx_to_internal_tx(invoke_tx),
        Transaction::L1Handler(l1_handler_tx) => l1handler_to_internal_tx(l1_handler_tx),
        Transaction::Declare(declare_tx) => match declare_tx {
            DeclareTransaction::V0(tx) => declare_v0_to_internal_tx(tx),
            DeclareTransaction::V1(tx) => declare_v1_to_internal_tx(tx),
            DeclareTransaction::V2(tx) => declare_v2_to_internal_tx(tx),
            DeclareTransaction::V3(tx) => declare_v3_to_internal_tx(tx),
        },
        Transaction::Deploy(_deploy_tx) => {
            unimplemented!("we do not plan to support deprecated deploy txs, only deploy_account")
        }
        Transaction::DeployAccount(deploy_account_tx) => match deploy_account_tx {
            DeployAccountTransaction::V1(tx) => deploy_account_v1_to_internal_tx(tx),
            DeployAccountTransaction::V3(tx) => deploy_account_v3_to_internal_tx(tx),
        },
    }
}

#[cfg(test)]
mod tests {
    use starknet::core::types::{ResourceBounds, ResourceBoundsMapping};
    use starknet_types_core::felt::Felt;

    use super::*;

    #[test]
    fn test_l1handler_to_internal_tx() {
        // Prepare the input
        let input = L1HandlerTransaction {
            transaction_hash: Felt::from(1),
            version: Felt::from(0),
            nonce: 42,
            contract_address: Felt::from(2),
            entry_point_selector: Felt::from(3),
            calldata: vec![Felt::from(4), Felt::from(5)],
        };

        // Convert to InternalTransaction
        let result = l1handler_to_internal_tx(input.clone());

        // Check the fields
        assert_eq!(result.hash_value, input.transaction_hash);
        assert_eq!(result.version, Some(input.version));
        assert_eq!(result.contract_address, Some(input.contract_address));
        assert_eq!(result.nonce, Some(Felt252::from(input.nonce)));
        assert_eq!(result.entry_point_selector, Some(input.entry_point_selector));
        assert_eq!(result.calldata, Some(input.calldata.clone()));
        assert_eq!(result.r#type, "L1_HANDLER".to_string());

        // Check defaulted fields
        assert_eq!(result.contract_address_salt, None);
        assert_eq!(result.signature, None);
        assert_eq!(result.class_hash, None);
        assert_eq!(result.compiled_class_hash, None);
        assert_eq!(result.max_fee, None);
        assert_eq!(result.tip, None);
        assert_eq!(result.resource_bounds, None);
        assert_eq!(result.paymaster_data, None);
        assert_eq!(result.nonce_data_availability_mode, None);
        assert_eq!(result.fee_data_availability_mode, None);
        assert_eq!(result.account_deployment_data, None);
        assert_eq!(result.entry_point_type, None);
    }

    #[test]
    fn test_declare_v0_to_internal_tx() {
        // Prepare the input
        let input = DeclareTransactionV0 {
            transaction_hash: Felt::from(1),
            sender_address: Felt::from(2),
            max_fee: Felt::from(1000),
            signature: vec![Felt::from(3), Felt::from(4)],
            class_hash: Felt::from(5),
        };

        // Convert to InternalTransaction
        let result = declare_v0_to_internal_tx(input.clone());

        // Check the fields
        assert_eq!(result.hash_value, input.transaction_hash);
        assert_eq!(result.sender_address, Some(input.sender_address));
        assert_eq!(result.max_fee, Some(input.max_fee));
        assert_eq!(result.signature, Some(input.signature.into_iter().map(Felt252::from).collect()));
        assert_eq!(result.class_hash, Some(input.class_hash));
        assert_eq!(result.r#type, "DECLARE".to_string());

        // Check defaulted fields
        assert_eq!(result.contract_address, None);
        assert_eq!(result.contract_address_salt, None);
        assert_eq!(result.constructor_calldata, None);
        assert_eq!(result.nonce, None);
        assert_eq!(result.entry_point_selector, None);
        assert_eq!(result.compiled_class_hash, None);
        assert_eq!(result.tip, None);
        assert_eq!(result.resource_bounds, None);
        assert_eq!(result.paymaster_data, None);
        assert_eq!(result.nonce_data_availability_mode, None);
        assert_eq!(result.fee_data_availability_mode, None);
        assert_eq!(result.account_deployment_data, None);
        assert_eq!(result.entry_point_type, None);
    }
    #[test]
    fn test_declare_v1_to_internal_tx() {
        // Prepare the input
        let input = DeclareTransactionV1 {
            transaction_hash: Felt::from(1),
            sender_address: Felt::from(2),
            max_fee: Felt::from(1000),
            signature: vec![Felt::from(3), Felt::from(4)],
            nonce: Felt::from(5),
            class_hash: Felt::from(6),
        };

        // Convert to InternalTransaction
        let result = declare_v1_to_internal_tx(input.clone());

        // Check the fields
        assert_eq!(result.hash_value, input.transaction_hash);
        assert_eq!(result.sender_address, Some(input.sender_address));
        assert_eq!(result.max_fee, Some(input.max_fee));
        assert_eq!(result.signature, Some(input.signature.into_iter().map(Felt252::from).collect()));
        assert_eq!(result.nonce, Some(input.nonce));
        assert_eq!(result.class_hash, Some(input.class_hash));
        assert_eq!(result.r#type, "DECLARE".to_string());

        // Check defaulted fields
        assert_eq!(result.contract_address, None);
        assert_eq!(result.contract_address_salt, None);
        assert_eq!(result.constructor_calldata, None);
        assert_eq!(result.entry_point_selector, None);
        assert_eq!(result.compiled_class_hash, None);
        assert_eq!(result.tip, None);
        assert_eq!(result.resource_bounds, None);
        assert_eq!(result.paymaster_data, None);
        assert_eq!(result.nonce_data_availability_mode, None);
        assert_eq!(result.fee_data_availability_mode, None);
        assert_eq!(result.account_deployment_data, None);
        assert_eq!(result.entry_point_type, None);
    }
    #[test]
    fn test_declare_v2_to_internal_tx() {
        // Prepare the input
        let input = DeclareTransactionV2 {
            transaction_hash: Felt::from(1),
            sender_address: Felt::from(2),
            compiled_class_hash: Felt::from(3),
            max_fee: Felt::from(1000),
            signature: vec![Felt::from(4), Felt::from(5)],
            nonce: Felt::from(6),
            class_hash: Felt::from(7),
        };

        // Convert to InternalTransaction
        let result = declare_v2_to_internal_tx(input.clone());

        // Check the fields
        assert_eq!(result.hash_value, input.transaction_hash);
        assert_eq!(result.sender_address, Some(input.sender_address));
        assert_eq!(result.compiled_class_hash, Some(input.compiled_class_hash));
        assert_eq!(result.max_fee, Some(input.max_fee));
        assert_eq!(result.signature, Some(input.signature.into_iter().map(Felt252::from).collect()));
        assert_eq!(result.nonce, Some(input.nonce));
        assert_eq!(result.class_hash, Some(input.class_hash));
        assert_eq!(result.r#type, "DECLARE".to_string());

        // Check defaulted fields
        assert_eq!(result.contract_address, None);
        assert_eq!(result.contract_address_salt, None);
        assert_eq!(result.constructor_calldata, None);
        assert_eq!(result.entry_point_selector, None);
        assert_eq!(result.tip, None);
        assert_eq!(result.resource_bounds, None);
        assert_eq!(result.paymaster_data, None);
        assert_eq!(result.nonce_data_availability_mode, None);
        assert_eq!(result.fee_data_availability_mode, None);
        assert_eq!(result.account_deployment_data, None);
        assert_eq!(result.entry_point_type, None);
    }
    #[test]
    fn test_declare_v3_to_internal_tx() {
        // Prepare the input
        let input = DeclareTransactionV3 {
            transaction_hash: Felt::from(1),
            sender_address: Felt::from(2),
            compiled_class_hash: Felt::from(3),
            signature: vec![Felt::from(4), Felt::from(5)],
            nonce: Felt::from(6),
            class_hash: Felt::from(7),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds { max_amount: 100, max_price_per_unit: 1 },
                l2_gas: ResourceBounds { max_amount: 100, max_price_per_unit: 1 },
            },
            tip: 100,
            paymaster_data: vec![Felt::from(8), Felt::from(9)],
            account_deployment_data: vec![Felt::from(10), Felt::from(11)],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L2,
        };

        // Convert to InternalTransaction
        let result = declare_v3_to_internal_tx(input.clone());

        // Check the fields
        assert_eq!(result.hash_value, input.transaction_hash);
        assert_eq!(result.sender_address, Some(input.sender_address));
        assert_eq!(result.compiled_class_hash, Some(input.compiled_class_hash));
        assert_eq!(result.signature, Some(input.signature.into_iter().map(Felt252::from).collect()));
        assert_eq!(result.nonce, Some(input.nonce));
        assert_eq!(result.class_hash, Some(input.class_hash));
        assert_eq!(result.resource_bounds, Some(resource_bounds_core_to_api(&input.resource_bounds)));
        assert_eq!(result.tip, Some(Felt252::from(input.tip)));
        assert_eq!(result.paymaster_data, Some(input.paymaster_data.into_iter().map(Felt252::from).collect()));
        assert_eq!(
            result.account_deployment_data,
            Some(input.account_deployment_data.into_iter().map(Felt252::from).collect())
        );
        assert_eq!(result.nonce_data_availability_mode, Some(da_to_felt(input.nonce_data_availability_mode)));
        assert_eq!(result.fee_data_availability_mode, Some(da_to_felt(input.fee_data_availability_mode)));
        assert_eq!(result.r#type, "DECLARE".to_string());

        // Check defaulted fields
        assert_eq!(result.contract_address, None);
        assert_eq!(result.contract_address_salt, None);
        assert_eq!(result.constructor_calldata, None);
        assert_eq!(result.entry_point_selector, None);
        assert_eq!(result.max_fee, None);
        assert_eq!(result.entry_point_type, None);
    }
    #[test]
    fn test_deploy_account_v1_to_internal_tx() {
        // Prepare the input
        let input = DeployAccountTransactionV1 {
            transaction_hash: Felt::from(1),
            max_fee: Felt::from(1000),
            signature: vec![Felt::from(2), Felt::from(3)],
            nonce: Felt::from(4),
            contract_address_salt: Felt::from(5),
            constructor_calldata: vec![Felt::from(6), Felt::from(7)],
            class_hash: Felt::from(8),
        };

        // Convert to InternalTransaction
        let result = deploy_account_v1_to_internal_tx(input.clone());

        // Check the fields
        assert_eq!(result.hash_value, input.transaction_hash);
        assert_eq!(result.max_fee, Some(input.max_fee));
        assert_eq!(result.signature, Some(input.signature.into_iter().map(Felt252::from).collect()));
        assert_eq!(result.nonce, Some(input.nonce));
        assert_eq!(result.contract_address_salt, Some(input.contract_address_salt));
        assert_eq!(
            result.constructor_calldata,
            Some(input.constructor_calldata.into_iter().map(Felt252::from).collect())
        );
        assert_eq!(result.class_hash, Some(input.class_hash));
        assert_eq!(result.r#type, "DEPLOY_ACCOUNT".to_string());
        assert!(result.contract_address.is_some());
        assert_eq!(result.entry_point_selector, Some(Felt::ZERO));

        // Check defaulted fields
        assert_eq!(result.contract_hash, None);
        assert_eq!(result.compiled_class_hash, None);

        assert_eq!(result.tip, None);
        assert_eq!(result.resource_bounds, None);
        assert_eq!(result.paymaster_data, None);
        assert_eq!(result.nonce_data_availability_mode, None);
        assert_eq!(result.fee_data_availability_mode, None);
        assert_eq!(result.account_deployment_data, None);
        assert_eq!(result.entry_point_type, None);
    }

    #[test]
    fn test_deploy_account_v3_to_internal_tx() {
        // Prepare the input
        let input = DeployAccountTransactionV3 {
            transaction_hash: Felt::from(1),
            signature: vec![Felt::from(2), Felt::from(3)],
            nonce: Felt::from(4),
            contract_address_salt: Felt::from(5),
            constructor_calldata: vec![Felt::from(6), Felt::from(7)],
            class_hash: Felt::from(8),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds { max_amount: 100, max_price_per_unit: 1 },
                l2_gas: ResourceBounds { max_amount: 100, max_price_per_unit: 1 },
            },
            tip: 100,
            paymaster_data: vec![Felt::from(9), Felt::from(10)],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L2,
        };

        // Convert to InternalTransaction
        let result = deploy_account_v3_to_internal_tx(input.clone());

        // Check the fields
        assert_eq!(result.hash_value, input.transaction_hash);
        assert_eq!(result.signature, Some(input.signature.into_iter().map(Felt252::from).collect()));
        assert_eq!(result.nonce, Some(input.nonce));
        assert_eq!(result.contract_address_salt, Some(input.contract_address_salt));
        assert_eq!(
            result.constructor_calldata,
            Some(input.constructor_calldata.into_iter().map(Felt252::from).collect())
        );
        assert_eq!(result.class_hash, Some(input.class_hash));
        assert_eq!(result.resource_bounds, Some(resource_bounds_core_to_api(&input.resource_bounds)));
        assert_eq!(result.tip, Some(Felt252::from(input.tip)));
        assert_eq!(result.paymaster_data, Some(input.paymaster_data.into_iter().map(Felt252::from).collect()));
        assert_eq!(result.nonce_data_availability_mode, Some(da_to_felt(input.nonce_data_availability_mode)));
        assert_eq!(result.fee_data_availability_mode, Some(da_to_felt(input.fee_data_availability_mode)));
        assert_eq!(result.r#type, "DEPLOY_ACCOUNT".to_string());

        // Check defaulted fields
        assert_eq!(result.contract_address, None);
        assert_eq!(result.contract_hash, None);
        assert_eq!(result.compiled_class_hash, None);
        assert_eq!(result.entry_point_selector, None);
        assert_eq!(result.max_fee, None);
        assert_eq!(result.account_deployment_data, None);
        assert_eq!(result.entry_point_type, None);
    }
}
