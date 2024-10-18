use rpc_client::pathfinder::proofs::ProofVerificationError;
use rpc_client::RpcClient;
use rstest::rstest;
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use starknet_os_types::compiled_class::GenericCompiledClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_types_core::felt::Felt;

#[rstest]
// Contract address 0x41a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf
#[case::correct_hash_computation_0("0x07b3e05f48f0c69e4a65ce5e076a66271a527aff2c34ce1083ec6e1526997a69", 78720)]
// Contract address 0x7a3c142b1ef242f093642604c2ac2259da0efa3a0517715c34a722ba2ecd048
#[case::correct_hash_computation_1("0x5c478ee27f2112411f86f207605b2e2c58cdb647bac0df27f660ef2252359c6", 30000)]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_recompute_class_hash(#[case] class_hash_str: String, #[case] block_number: u64) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
    let class_hash = Felt::from_hex(&class_hash_str).unwrap();
    let block_id = BlockId::Number(block_number);

    let rpc_client = RpcClient::new(&endpoint);
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

#[rstest]
// Class hashes and blocks where ClassProof are non-inclusion proof
#[case::key_not_in_proof("0x05dec330eebf36c8672b60db4a718d44762d3ae6d1333e553197acb47ee5a062", 56354)]
#[case::key_not_in_proof("0x05dec330eebf36c8672b60db4a718d44762d3ae6d1333e553197acb47ee5a062", 56355)]
#[case::key_not_in_proof("0x062f6d32e5b109af12d1bd916fea424344f51d442953d801f613ca526de9eb7f", 174967)]
#[case::key_not_in_proof("0xbe81515dadb87e4531317998f3b7c6028834315c43506e74b3fe866dfbfa3c", 156854)]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_class_proof_verification_non_inclusion(#[case] class_hash_str: String, #[case] block_number: u64) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
    let class_hash = Felt::from_hex(&class_hash_str).unwrap();
    let rpc_client = RpcClient::new(&endpoint);

    let class_proof = rpc_client.pathfinder_rpc().get_class_proof(block_number, &class_hash).await.unwrap();
    let result = class_proof.verify(class_hash);
    assert!(result.is_err());

    if let ProofVerificationError::NonExistenceProof { key, proof, .. } = result.unwrap_err() {
        assert_eq!(class_hash, key);
        assert_eq!(class_proof.class_proof, proof);
        // In order to get the height we need to follow the same logic from verify function
    } else {
        panic!("This tests is only meant for NonInclusionProof errors");
    }
}

#[rstest]
// Class hashes and blocks where ClassProof are complete and valid
#[case::key_not_in_proof("0x062f6d32e5b109af12d1bd916fea424344f51d442953d801f613ca526de9eb7f", 174968)]
#[case::key_not_in_proof("0xbe81515dadb87e4531317998f3b7c6028834315c43506e74b3fe866dfbfa3c", 156855)]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_class_proof_verification_ok(#[case] class_hash_str: String, #[case] block_number: u64) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");
    let class_hash = Felt::from_hex(&class_hash_str).unwrap();
    let rpc_client = RpcClient::new(&endpoint);

    let class_proof = rpc_client.pathfinder_rpc().get_class_proof(block_number, &class_hash).await.unwrap();
    assert!(class_proof.verify(class_hash).is_ok());
}
