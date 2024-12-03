use blockifier::state::cached_state::CachedState;
use cairo_vm::Felt252;
use prove_block::reexecute::{format_commitment_facts, reexecute_transactions_with_blockifier};
use prove_block::rpc_utils::{get_starknet_version, get_storage_proofs};
use prove_block::state_utils::get_formatted_state_update;
use rpc_client::RpcClient;
use rpc_replay::block_context::build_block_context;
use rpc_replay::rpc_state_reader::AsyncRpcStateReader;
use rpc_replay::transactions::starknet_rs_to_blockifier;
use rstest::rstest;
use starknet::core::types::{BlockId, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs};
use starknet::providers::Provider;
use starknet_os::config::STORED_BLOCK_HASH_BUFFER;
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os_types::chain_id::chain_id_from_felt;

#[rstest]
#[case::key_not_found_in_preimage_2(237037)]
#[ignore = "Requires a running Pathfinder node"]
#[tokio::test(flavor = "multi_thread")]
async fn test_key_not_in_preimage_global(#[case] block_number: u64) {
    let endpoint = std::env::var("PATHFINDER_RPC_URL").expect("Missing PATHFINDER_RPC_URL in env");

    let block_id = BlockId::Number(block_number);
    let previous_block_id = BlockId::Number(block_number - 1);

    let rpc_client = RpcClient::new(&endpoint);

    let chain_id = chain_id_from_felt(rpc_client.starknet_rpc().chain_id().await.unwrap());

    let block_with_txs = match rpc_client.starknet_rpc().get_block_with_txs(block_id).await.unwrap() {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    let starknet_version = get_starknet_version(&block_with_txs);

    let older_block_number =
        if block_number <= STORED_BLOCK_HASH_BUFFER { 1 } else { block_number - STORED_BLOCK_HASH_BUFFER };

    let older_block =
        match rpc_client.starknet_rpc().get_block_with_tx_hashes(BlockId::Number(older_block_number)).await.unwrap() {
            MaybePendingBlockWithTxHashes::Block(block_with_txs_hashes) => block_with_txs_hashes,
            MaybePendingBlockWithTxHashes::PendingBlock(_) => {
                panic!("Block is still pending!");
            }
        };
    let old_block_number = Felt252::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    let block_context = build_block_context(chain_id.clone(), &block_with_txs, starknet_version).unwrap();

    let blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), BlockId::Number(block_number - 1));
    let mut blockifier_state = CachedState::new(blockifier_state_reader);

    let (_processed_state_update, traces) =
        get_formatted_state_update(&rpc_client, previous_block_id, block_id).await.unwrap();

    let mut txs = Vec::new();
    for (tx, trace) in block_with_txs.transactions.iter().zip(traces.iter()) {
        let transaction =
            starknet_rs_to_blockifier(tx, trace, &block_context.block_info().gas_prices, &rpc_client, block_number)
                .await
                .unwrap();
        txs.push(transaction);
    }

    println!("transactions: {:?}", txs);

    let tx_execution_infos =
        reexecute_transactions_with_blockifier(&mut blockifier_state, &block_context, old_block_hash, txs).unwrap();

    let storage_proofs = get_storage_proofs(&rpc_client, block_number, &tx_execution_infos, old_block_number)
        .await
        .expect("Failed to fetch storage proofs");

    let previous_storage_proofs = get_storage_proofs(&rpc_client, block_number, &tx_execution_infos, old_block_number)
        .await
        .expect("Failed to fetch storage proofs");

    let previous_contract_proofs: Vec<_> =
        previous_storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let previous_state_commitment_facts = format_commitment_facts::<PedersenHash>(&previous_contract_proofs);

    let current_contract_proofs: Vec<_> = storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let formatted_proofs = format_commitment_facts::<PedersenHash>(&current_contract_proofs);

    let missing_node = Felt252::from_hex_unchecked("0x34f1a3021b450d34bf9ce833b19de68b9f9d565d1951529f1eb4f30dbfc5e1c");
    // println!("formatted proofs: {:?}", formatted_proofs);
    println!("formatted proofs: {:?}", previous_state_commitment_facts);

    assert_eq!(previous_state_commitment_facts.contains_key(&missing_node), true);
}
