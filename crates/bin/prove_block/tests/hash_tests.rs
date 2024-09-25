use rpc_client::RpcClient;
use rstest::rstest;
use starknet::core::types::BlockId;
use starknet::providers::Provider;
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
