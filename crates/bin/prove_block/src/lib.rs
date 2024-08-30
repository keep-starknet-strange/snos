use std::collections::HashMap;

use blockifier::state::cached_state::CachedState;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::Felt252;
use reexecute::{reexecute_transactions_with_blockifier, ProverPerContractStorage};
use rpc_replay::block_context::build_block_context;
use rpc_replay::rpc_state_reader::AsyncRpcStateReader;
use rpc_replay::transactions::starknet_rs_to_blockifier;
use rpc_utils::{get_class_proofs, get_storage_proofs};
use starknet::core::types::{BlockId, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, ProviderError, Url};
use starknet_api::StarknetApiError;
use starknet_os::config::{StarknetGeneralConfig, StarknetOsConfig, STORED_BLOCK_HASH_BUFFER};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::error::SnOsError::{self};
use starknet_os::execution::helper::{ContractStorageMap, ExecutionHelperWrapper};
use starknet_os::io::input::StarknetOsInput;
use starknet_os::io::output::StarknetOsOutput;
use starknet_os::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use starknet_os::starknet::starknet_storage::CommitmentInfo;
use starknet_os::starkware_utils::commitment_tree::base_types::Height;
use starknet_os::starkware_utils::commitment_tree::errors::TreeError;
use starknet_os::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use starknet_os::{config, run_os};
use starknet_os_types::chain_id::chain_id_from_felt;
use starknet_os_types::error::ContractClassError;
use starknet_os_types::starknet_core_addons::LegacyContractDecompressionError;
use starknet_types_core::felt::Felt;
use state_utils::get_formatted_state_update;
use thiserror::Error;

use crate::reexecute::format_commitment_facts;
use crate::rpc_utils::{get_starknet_version, PathfinderClassProof};
use crate::types::starknet_rs_tx_to_internal_tx;

mod reexecute;
mod rpc_utils;
mod state_utils;
mod types;
mod utils;

#[derive(Debug, Error)]
pub enum ProveBlockError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
    #[error("Re-Execution Error: {0}")]
    ReExecutionError(#[from] Box<dyn std::error::Error>),
    #[error("Tree Error: {0}")]
    TreeError(#[from] TreeError),
    #[error("Contract Class Error: {0}")]
    ContractClassError(#[from] ContractClassError),
    #[error("SnOs Error: {0}")]
    SnOsError(#[from] SnOsError),
    #[error("Legacy class decompression Error: {0}")]
    LegacyContractDecompressionError(#[from] LegacyContractDecompressionError),
    #[error("Starknet API Error: {0}")]
    StarknetApiError(StarknetApiError),
}

fn compute_class_commitment(
    previous_class_proofs: &HashMap<Felt, PathfinderClassProof>,
    class_proofs: &HashMap<Felt, PathfinderClassProof>,
) -> CommitmentInfo {
    for (class_hash, previous_class_proof) in previous_class_proofs {
        assert!(previous_class_proof.verify(*class_hash).is_ok());
    }

    for (class_hash, class_proof) in previous_class_proofs {
        assert!(class_proof.verify(*class_hash).is_ok());
    }

    let previous_class_proofs: Vec<_> = previous_class_proofs.values().cloned().collect();
    let class_proofs: Vec<_> = class_proofs.values().cloned().collect();

    let previous_root = previous_class_proofs[0].class_commitment;
    let updated_root = class_proofs[0].class_commitment;

    let previous_class_proofs: Vec<_> = previous_class_proofs.into_iter().map(|proof| proof.class_proof).collect();
    let class_proofs: Vec<_> = class_proofs.into_iter().map(|proof| proof.class_proof).collect();

    let previous_class_commitment_facts = format_commitment_facts::<PoseidonHash>(&previous_class_proofs);
    let current_class_commitment_facts = format_commitment_facts::<PoseidonHash>(&class_proofs);

    let class_commitment_facts: HashMap<_, _> =
        previous_class_commitment_facts.into_iter().chain(current_class_commitment_facts).collect();

    log::debug!("previous class trie root: {}", previous_root.to_hex_string());
    log::debug!("current class trie root: {}", updated_root.to_hex_string());

    CommitmentInfo { previous_root, updated_root, tree_height: 251, commitment_facts: class_commitment_facts }
}

pub async fn prove_block(
    block_number: u64,
    rpc_provider: &str,
    layout: LayoutName,
) -> Result<(CairoPie, StarknetOsOutput), ProveBlockError> {
    let block_id = BlockId::Number(block_number);
    let previous_block_id = BlockId::Number(block_number - 1);

    let provider_url = format!("{}/rpc/v0_7", rpc_provider);
    log::info!("provider url: {}", provider_url);
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
    ));
    let pathfinder_client =
        reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

    // Step 1: build the block context
    let chain_id = chain_id_from_felt(provider.chain_id().await?);
    log::debug!("provider's chain_id: {}", chain_id);

    let block_with_txs = match provider.get_block_with_txs(block_id).await? {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    let starknet_version = get_starknet_version(&block_with_txs);
    log::debug!("Starknet version: {:?}", starknet_version);

    let previous_block = match provider.get_block_with_tx_hashes(previous_block_id).await? {
        MaybePendingBlockWithTxHashes::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxHashes::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    // We only need to get the older block number and hash. No need to fetch all the txs
    let older_block = match provider
        .get_block_with_tx_hashes(BlockId::Number(block_number - STORED_BLOCK_HASH_BUFFER))
        .await
        .unwrap()
    {
        MaybePendingBlockWithTxHashes::Block(block_with_txs_hashes) => block_with_txs_hashes,
        MaybePendingBlockWithTxHashes::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    let block_context = build_block_context(chain_id.clone(), &block_with_txs, starknet_version);

    let old_block_number = Felt252::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    // TODO: nasty clone, the conversion fns don't take references
    let transactions: Vec<_> =
        block_with_txs.transactions.clone().into_iter().map(starknet_rs_tx_to_internal_tx).collect();

    let processed_state_update = get_formatted_state_update(&provider, previous_block_id, block_id).await?;

    let class_hash_to_compiled_class_hash = processed_state_update.class_hash_to_compiled_class_hash;

    // Workaround for JsonRpcClient not implementing Clone
    let provider_for_blockifier = JsonRpcClient::new(HttpTransport::new(
        Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
    ));
    let blockifier_state_reader = AsyncRpcStateReader::new(provider_for_blockifier, BlockId::Number(block_number - 1));

    let mut blockifier_state = CachedState::new(blockifier_state_reader);
    let mut txs = Vec::new();
    for tx in block_with_txs.transactions.iter() {
        let transaction = starknet_rs_to_blockifier(tx, &provider, block_number).await?;
        txs.push(transaction);
    }
    let tx_execution_infos = reexecute_transactions_with_blockifier(&mut blockifier_state, &block_context, txs)?;

    let storage_proofs =
        get_storage_proofs(&pathfinder_client, rpc_provider, block_number, &tx_execution_infos, old_block_number)
            .await
            .expect("Failed to fetch storage proofs");

    let previous_storage_proofs =
        get_storage_proofs(&pathfinder_client, rpc_provider, block_number - 1, &tx_execution_infos, old_block_number)
            .await
            .expect("Failed to fetch storage proofs");

    let default_general_config = StarknetGeneralConfig::default();

    let general_config = StarknetGeneralConfig {
        starknet_os_config: StarknetOsConfig {
            chain_id,
            fee_token_address: block_context.chain_info().fee_token_addresses.strk_fee_token_address,
            deprecated_fee_token_address: block_context.chain_info().fee_token_addresses.eth_fee_token_address,
        },
        ..default_general_config
    };

    let mut contract_states = HashMap::new();
    let mut contract_storages = ContractStorageMap::new();

    // TODO: remove this clone()
    for (contract_address, storage_proof) in storage_proofs.clone() {
        let previous_storage_proof =
            previous_storage_proofs.get(&contract_address).expect("failed to find previous storage proof");
        let contract_storage_root = previous_storage_proof.contract_data.as_ref().unwrap().root.into();
        // let previous_storage_entries =
        // previous_storage_changes_by_contract.get(&contract_address).unwrap();

        log::debug!(
            "Storage root 0x{:x} for contract 0x{:x}",
            Into::<Felt252>::into(contract_storage_root),
            contract_address
        );

        let previous_tree = PatriciaTree { root: contract_storage_root, height: Height(251) };

        let contract_storage = ProverPerContractStorage::new(
            previous_block_id,
            contract_address,
            provider_url.clone(),
            previous_tree.root.into(),
            storage_proof,
            previous_storage_proof.clone(),
        )?;
        contract_storages.insert(contract_address, contract_storage);

        let (previous_class_hash, previous_nonce) = if [Felt252::ZERO, Felt252::ONE].contains(&contract_address) {
            (Felt252::ZERO, Felt252::ZERO)
        } else {
            let previous_class_hash = provider.get_class_hash_at(previous_block_id, contract_address).await?;
            let previous_nonce = provider.get_nonce(previous_block_id, contract_address).await?;
            (previous_class_hash, previous_nonce)
        };

        let contract_state = ContractState {
            contract_hash: previous_class_hash.to_bytes_be().to_vec(),
            storage_commitment_tree: previous_tree,
            nonce: previous_nonce,
        };

        contract_states.insert(contract_address, contract_state);
    }

    let compiled_classes = processed_state_update.compiled_classes;

    // query storage proofs for each accessed contract
    let class_hashes: Vec<&Felt252> = class_hash_to_compiled_class_hash.keys().collect();
    // TODO: we fetch proofs here for block-1, but we probably also need to fetch at the current
    //       block, likely for contracts that are deployed in this block
    let class_proofs = get_class_proofs(&pathfinder_client, rpc_provider, block_number - 1, &class_hashes[..])
        .await
        .expect("Failed to fetch class proofs");
    let previous_class_proofs = get_class_proofs(&pathfinder_client, rpc_provider, block_number - 1, &class_hashes[..])
        .await
        .expect("Failed to fetch class proofs");

    let visited_pcs: HashMap<Felt252, Vec<Felt252>> = blockifier_state
        .visited_pcs
        .iter()
        .map(|(class_hash, visited_pcs)| {
            (class_hash.0, visited_pcs.iter().copied().map(Felt252::from).collect::<Vec<_>>())
        })
        .collect();

    // We can extract data from any storage proof, use the one of the block hash contract
    let block_hash_storage_proof =
        storage_proofs.get(&Felt::ONE).expect("there should be a storage proof for the block hash contract");
    let previous_block_hash_storage_proof = previous_storage_proofs
        .get(&Felt::ONE)
        .expect("there should be a previous storage proof for the block hash contract");

    let previous_contract_trie_root = previous_block_hash_storage_proof.contract_proof[0].hash::<PedersenHash>();
    let current_contract_trie_root = block_hash_storage_proof.contract_proof[0].hash::<PedersenHash>();

    let previous_contract_proofs: Vec<_> =
        previous_storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let previous_state_commitment_facts = format_commitment_facts::<PedersenHash>(&previous_contract_proofs);
    let current_contract_proofs: Vec<_> = storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let current_state_commitment_facts = format_commitment_facts::<PedersenHash>(&current_contract_proofs);

    let global_state_commitment_facts: HashMap<_, _> =
        previous_state_commitment_facts.into_iter().chain(current_state_commitment_facts).collect();

    let contract_state_commitment_info = CommitmentInfo {
        previous_root: previous_contract_trie_root,
        updated_root: current_contract_trie_root,
        tree_height: 251,
        commitment_facts: global_state_commitment_facts,
    };

    let contract_class_commitment_info = compute_class_commitment(&previous_class_proofs, &class_proofs);

    let os_input = StarknetOsInput {
        contract_state_commitment_info,
        contract_class_commitment_info,
        deprecated_compiled_classes: Default::default(),
        compiled_classes,
        compiled_class_visited_pcs: visited_pcs,
        contracts: contract_states,
        class_hash_to_compiled_class_hash,
        general_config,
        transactions,
        new_block_hash: block_with_txs.block_hash,
        prev_block_hash: previous_block.block_hash,
        full_output: false,
    };
    let execution_helper = ExecutionHelperWrapper::<ProverPerContractStorage>::new(
        contract_storages,
        tx_execution_infos,
        &block_context,
        (old_block_number, old_block_hash),
    );

    Ok(run_os(config::DEFAULT_COMPILED_OS, layout, os_input, block_context, execution_helper)?)
}

pub fn debug_prove_error(err: ProveBlockError) -> ProveBlockError {
    if let ProveBlockError::SnOsError(SnOsError::Runner(CairoRunError::VmException(vme))) = &err {
        if let Some(traceback) = vme.traceback.as_ref() {
            log::error!("traceback:\n{}", traceback);
        }
        if let Some(inst_location) = &vme.inst_location {
            log::error!("died at: {}:{}", inst_location.input_file.filename, inst_location.start_line);
            log::error!("inst_location:\n{:?}", inst_location);
        }
    }
    err
}
