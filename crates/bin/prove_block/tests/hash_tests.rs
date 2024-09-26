use std::io::Read;

use flate2::read::GzDecoder;
use pathfinder_gateway_types::class_hash::compute_class_hash;
use rpc_client::RpcClient;
use rstest::rstest;
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use starknet_core::types::contract::legacy::{
    LegacyContractClass, LegacyEntrypointOffset, RawLegacyAbiEntry, RawLegacyConstructor, RawLegacyEntryPoint,
    RawLegacyEntryPoints, RawLegacyEvent, RawLegacyFunction, RawLegacyL1Handler, RawLegacyMember, RawLegacyStruct,
};
use starknet_core::types::{
    LegacyContractAbiEntry, LegacyContractEntryPoint, LegacyEntryPointsByType, LegacyFunctionAbiEntry,
    LegacyFunctionAbiType, LegacyStructMember,
};
use starknet_os_types::compiled_class::GenericCompiledClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_types_core::felt::Felt;

const PATHFINDER_RPC_URL: &str = "http://81.16.176.130:9545";
// # These blocks verify the following issues:
// # * Block number 78720 : Class hash computation works fine
// # * Block number 30000 : Class hash computation mismatch
#[rstest]
// Contract address 0x41a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf
#[case::correct_hash_computation("0x07b3e05f48f0c69e4a65ce5e076a66271a527aff2c34ce1083ec6e1526997a69", 78720)]
// Contract address 0x7a3c142b1ef242f093642604c2ac2259da0efa3a0517715c34a722ba2ecd048
#[case::correct_hash_computation("0x5c478ee27f2112411f86f207605b2e2c58cdb647bac0df27f660ef2252359c6", 30000)]
#[tokio::test(flavor = "multi_thread")]
async fn test_recompute_class_hash(#[case] class_hash_str: String, #[case] block_number: u64) {
    let class_hash = Felt::from_hex(&class_hash_str).unwrap();
    let block_id = BlockId::Number(block_number);

    let rpc_client = RpcClient::new(PATHFINDER_RPC_URL);
    let contract_class = rpc_client.starknet_rpc().get_class(block_id, class_hash).await.unwrap();

    let compiled_class = if let starknet::core::types::ContractClass::Legacy(legacy_cc) = contract_class {
        let compiled_class = GenericDeprecatedCompiledClass::try_from(legacy_cc).unwrap();
        GenericCompiledClass::Cairo0(compiled_class)
    } else {
        panic!("Test intended to test Legacy contracts");
    };

    let recomputed_class_hash = Felt::from(compiled_class.class_hash().unwrap());

    println!("Class hash: {:#x}", class_hash);
    println!("Recomputed class hash: {:#x}", recomputed_class_hash);

    assert_eq!(class_hash, recomputed_class_hash);
}

// Keep only Pathfinder classes
#[rstest]
// Contract address 0x41a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf
#[case::correct_hash_computation("0x07b3e05f48f0c69e4a65ce5e076a66271a527aff2c34ce1083ec6e1526997a69", 78720)]
// Contract address 0x7a3c142b1ef242f093642604c2ac2259da0efa3a0517715c34a722ba2ecd048
#[case::correct_hash_computation("0x5c478ee27f2112411f86f207605b2e2c58cdb647bac0df27f660ef2252359c6", 30000)]
#[tokio::test(flavor = "multi_thread")]
async fn test_recompute_class_hash2(#[case] class_hash_str: String, #[case] block_number: u64) {
    let class_hash = Felt::from_hex(&class_hash_str).unwrap();
    let block_id = BlockId::Number(block_number);

    let rpc_client = RpcClient::new(PATHFINDER_RPC_URL);
    let contract_class = rpc_client.starknet_rpc().get_class(block_id, class_hash).await.unwrap();

    let compressed_legacy_contract_class =
        if let starknet::core::types::ContractClass::Legacy(legacy_cc) = contract_class {
            legacy_cc
        } else {
            panic!("Test intended to test Legacy contracts");
        };

    let legacy_contract_class = {
        let mut program_str = String::new();
        let mut decoder = GzDecoder::new(compressed_legacy_contract_class.program.as_slice());
        decoder.read_to_string(&mut program_str).unwrap();

        let program: starknet_core::types::contract::legacy::LegacyProgram =
            serde_json::from_str(&program_str).unwrap();
        let abi = compressed_legacy_contract_class
            .abi
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(raw_legacy_abi_entry_from_legacy_contract_abi_entry)
            .collect::<Vec<_>>();

        LegacyContractClass {
            abi,
            entry_points_by_type: raw_legacy_entrypoints_from_legacy_entrypoints(
                compressed_legacy_contract_class.entry_points_by_type.clone(),
            ),
            program,
        }
    };

    let serialized_class = serde_json::to_vec(&legacy_contract_class).unwrap();
    let recomputed_class_hash =
        Felt::from_bytes_be(&compute_class_hash(&serialized_class).unwrap().hash().0.to_be_bytes());

    println!("Class hash: {:#x}", class_hash);
    println!("Recomputed class hash: {:#x}", recomputed_class_hash);

    assert_eq!(class_hash, recomputed_class_hash);

    // let recompressed_legacy_class = legacy_contract_class.compress().unwrap();
    // assert_eq!(compressed_legacy_contract_class, recompressed_legacy_class);
}

fn raw_abi_entry_from_legacy_function_abi_entry(entry: LegacyFunctionAbiEntry) -> RawLegacyAbiEntry {
    match entry.r#type {
        LegacyFunctionAbiType::Function => RawLegacyAbiEntry::Function(RawLegacyFunction {
            inputs: entry.inputs,
            name: entry.name,
            outputs: entry.outputs,
            state_mutability: entry.state_mutability,
        }),
        LegacyFunctionAbiType::Constructor => RawLegacyAbiEntry::Constructor(RawLegacyConstructor {
            inputs: entry.inputs,
            name: entry.name,
            outputs: entry.outputs,
        }),
        LegacyFunctionAbiType::L1Handler => RawLegacyAbiEntry::L1Handler(RawLegacyL1Handler {
            inputs: entry.inputs,
            name: entry.name,
            outputs: entry.outputs,
        }),
    }
}

fn raw_legacy_member_from_legacy_struct_member(member: LegacyStructMember) -> RawLegacyMember {
    RawLegacyMember { name: member.name, offset: member.offset, r#type: member.r#type }
}

/// Implementation of From<LegacyContractAbiEntry> for RawLegacyAbiEntry,
/// as it is missing from starknet-rs and we need it to interpret compressed legacy contracts.
fn raw_legacy_abi_entry_from_legacy_contract_abi_entry(
    legacy_contract_abi_entry: LegacyContractAbiEntry,
) -> RawLegacyAbiEntry {
    match legacy_contract_abi_entry {
        LegacyContractAbiEntry::Function(entry) => raw_abi_entry_from_legacy_function_abi_entry(entry),
        LegacyContractAbiEntry::Struct(entry) => RawLegacyAbiEntry::Struct(RawLegacyStruct {
            members: entry.members.into_iter().map(raw_legacy_member_from_legacy_struct_member).collect(),
            name: entry.name,
            size: entry.size,
        }),
        LegacyContractAbiEntry::Event(entry) => {
            RawLegacyAbiEntry::Event(RawLegacyEvent { data: entry.data, keys: entry.keys, name: entry.name })
        }
    }
}

fn raw_legacy_entrypoint_from_legacy_entrypoint(legacy_entry_point: LegacyContractEntryPoint) -> RawLegacyEntryPoint {
    RawLegacyEntryPoint {
        offset: LegacyEntrypointOffset::U64AsInt(legacy_entry_point.offset),
        selector: legacy_entry_point.selector,
    }
}

/// Implementation of From<LegacyEntryPointsByType> for RawLegacyEntryPoints,
/// as it is missing from starknet-rs and we need it to interpret compressed legacy contracts.
fn raw_legacy_entrypoints_from_legacy_entrypoints(
    legacy_entry_points_by_type: LegacyEntryPointsByType,
) -> RawLegacyEntryPoints {
    RawLegacyEntryPoints {
        constructor: legacy_entry_points_by_type
            .constructor
            .into_iter()
            .map(raw_legacy_entrypoint_from_legacy_entrypoint)
            .collect(),
        external: legacy_entry_points_by_type
            .external
            .into_iter()
            .map(raw_legacy_entrypoint_from_legacy_entrypoint)
            .collect(),
        l1_handler: legacy_entry_points_by_type
            .l1_handler
            .into_iter()
            .map(raw_legacy_entrypoint_from_legacy_entrypoint)
            .collect(),
    }
}
