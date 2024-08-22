use std::collections::{HashMap, HashSet};
use std::error::Error;

use blockifier::state::cached_state::{CachedState, GlobalContractCache};
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use cairo_vm::Felt252;
use clap::Parser;
use reexecute::{reexecute_transactions_with_blockifier, ProverPerContractStorage};
use rpc_replay::block_context::build_block_context;
use rpc_replay::rpc_state_reader::AsyncRpcStateReader;
use rpc_replay::transactions::starknet_rs_to_blockifier;
use rpc_utils::{get_class_proofs, get_storage_proofs, TrieNode};
use starknet::core::types::{BlockId, MaybePendingBlockWithTxs, MaybePendingStateUpdate};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};
use starknet_os::config::{StarknetGeneralConfig, StarknetOsConfig, SN_SEPOLIA, STORED_BLOCK_HASH_BUFFER};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::error::SnOsError::Runner;
use starknet_os::execution::helper::{ContractStorageMap, ExecutionHelperWrapper};
use starknet_os::io::input::StarknetOsInput;
use starknet_os::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use starknet_os::starknet::business_logic::utils::write_class_facts;
use starknet_os::starknet::starknet_storage::CommitmentInfo;
use starknet_os::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use starknet_os::storage::storage::Fact;
use starknet_os::utils::felt_api2vm;
use starknet_os::{config, run_os};
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_types_core::felt::Felt;
use utils::get_subcalled_contracts_from_tx_traces;

use crate::reexecute::format_commitment_facts;
use crate::rpc_utils::PathfinderClassProof;
use crate::state_utils::build_initial_state;
use crate::types::starknet_rs_tx_to_internal_tx;

mod reexecute;
mod rpc_utils;
mod state_utils;
mod types;
mod utils;

#[derive(Parser, Debug)]
struct Args {
    /// Block to prove.
    #[arg(long = "block-number")]
    block_number: u64,

    /// RPC endpoint to use for fact fetching
    #[arg(long = "rpc-provider", default_value = "http://localhost:9545")]
    rpc_provider: String,
}

fn init_logging() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp(None)
        .try_init()
        .expect("Failed to configure env_logger");
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();

    let args = Args::parse();

    let block_number = args.block_number;
    let layout = LayoutName::starknet_with_keccak;

    let block_id = BlockId::Number(block_number);
    let previous_block_id = BlockId::Number(block_number - 1);

    let provider_url = format!("{}/rpc/v0_7", args.rpc_provider);
    log::info!("provider url: {}", provider_url);
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
    ));
    let pathfinder_client =
        reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

    // Step 1: build the block context
    let chain_id = provider.chain_id().await?.to_string();
    log::debug!("provider's chain_id: {}", chain_id);
    let block_with_txs = match provider.get_block_with_txs(block_id).await? {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };
    let older_block =
        match provider.get_block_with_txs(BlockId::Number(block_number - STORED_BLOCK_HASH_BUFFER)).await.unwrap() {
            MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
            MaybePendingBlockWithTxs::PendingBlock(_) => {
                panic!("Block is still pending!");
            }
        };

    let state_update = match provider.get_state_update(block_id).await.expect("Failed to get state update") {
        MaybePendingStateUpdate::Update(update) => update,
        MaybePendingStateUpdate::PendingUpdate(_) => {
            panic!("Block is still pending!")
        }
    };

    // Extract other contracts used in our block from the block trace
    // We need this to get all the class hashes used and correctly feed address_to_class_hash
    let traces = provider.trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    let contracts_subcalled: HashSet<Felt252> = get_subcalled_contracts_from_tx_traces(&traces);

    let block_context = build_block_context(chain_id.clone(), &block_with_txs);

    let old_block_number = Felt252::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    // TODO: nasty clone, the conversion fns don't take references
    let mut transactions: Vec<_> =
        block_with_txs.transactions.clone().into_iter().map(starknet_rs_tx_to_internal_tx).collect();

    // TODO: these maps that we pass in to build_initial_state() are built only on items from the
    // state diff, but we will need all items accessed in any way during the block (right?) which
    // probably means filling in the missing details with API calls
    let mut address_to_class_hash: HashMap<_, _> = state_update
        .state_diff
        .deployed_contracts
        .iter()
        .map(|contract| (contract.address, contract.class_hash))
        .collect();
    for address in &contracts_subcalled {
        let class_hash = provider.get_class_hash_at(BlockId::Number(block_number), address).await.unwrap();
        address_to_class_hash.insert(*address, class_hash);
    }

    let address_to_nonce = state_update
        .state_diff
        .nonces
        .iter()
        .map(|nonce_update| {
            // derive original nonce
            let num_nonce_bumps =
                Felt252::from(transactions.iter().fold(0, |acc, tx| {
                    acc + if tx.sender_address == Some(nonce_update.contract_address) { 1 } else { 0 }
                }));
            assert!(nonce_update.nonce > num_nonce_bumps);
            let previous_nonce = nonce_update.nonce - num_nonce_bumps;
            (nonce_update.contract_address, previous_nonce)
        })
        .collect();

    let mut class_hash_to_compiled_class_hash: HashMap<_, _> = state_update
        .state_diff
        .declared_classes
        .iter()
        .map(|class| (class.class_hash, class.compiled_class_hash))
        .collect();

    let storage_updates = state_update
        .state_diff
        .storage_diffs
        .iter()
        .map(|diffs| {
            let storage_entries = diffs.storage_entries.iter().map(|e| (e.key, e.value)).collect();
            (diffs.address, storage_entries)
        })
        .collect();

    // TODO: avoid expensive clones here, probably by letting build_initial_state() take references
    let (accessed_contracts, mut initial_state) = build_initial_state(
        &provider,
        block_number,
        address_to_class_hash.clone(),
        address_to_nonce,
        class_hash_to_compiled_class_hash.clone(),
        storage_updates,
    )
    .await?;

    // fill in class hashes for each accessed contract
    for address in &accessed_contracts {
        if *address != Felt252::ONE && !address_to_class_hash.contains_key(address) {
            log::info!("Querying missing class hash for {}", address);
            let class_hash = provider.get_class_hash_at(BlockId::Number(block_number), address).await.unwrap();
            log::info!("Got class hash: {} => {}", address, class_hash);
            address_to_class_hash.insert(*address, class_hash);
        }
    }

    // TODO: clean up...
    // now that we have the class_hash for each contract, fill in the transaction data with the
    // class_hash. when transactions were first processed above, this information wasn't available.
    for transaction in transactions.iter_mut() {
        if let Some(sender_address) = transaction.sender_address {
            let class_hash = address_to_class_hash
                .get(&sender_address)
                .expect("should have a class_hash for each known contract addresses at this point");
            transaction.class_hash = Some(*class_hash);
        } else {
            // TODO: are there txn types which wouldn't have a sender address?
            unimplemented!("Found transaction without sender_address");
        }
    }

    // Workaround for JsonRpcClient not implementing Clone
    let provider_for_blockifier = JsonRpcClient::new(HttpTransport::new(
        Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
    ));
    let blockifier_state_reader = AsyncRpcStateReader::new(provider_for_blockifier, BlockId::Number(block_number - 1));

    let mut blockifier_state = CachedState::new(blockifier_state_reader, GlobalContractCache::new(1024));
    let tx_execution_infos = reexecute_transactions_with_blockifier(
        &mut blockifier_state,
        &block_context,
        block_with_txs.transactions.iter().map(|tx| starknet_rs_to_blockifier(tx).unwrap()).collect(),
    )?;

    if tx_execution_infos.len() != transactions.len() {
        log::warn!(
            "Warning: blockifier reexecution yielded different num execution infos ({}) than transactions ({})",
            tx_execution_infos.len(),
            transactions.len()
        );
    }

    let storage_proofs =
        get_storage_proofs(&pathfinder_client, &args.rpc_provider, block_number, &tx_execution_infos, old_block_number)
            .await
            .expect("Failed to fetch storage proofs");

    let previous_storage_proofs = get_storage_proofs(
        &pathfinder_client,
        &args.rpc_provider,
        block_number - 1,
        &tx_execution_infos,
        old_block_number,
    )
    .await
    .expect("Failed to fetch storage proofs");

    // write facts from proof
    for proof in storage_proofs.values().chain(previous_storage_proofs.values()) {
        if let Some(contract_data) = &proof.contract_data {
            for storage_item_proof in &contract_data.storage_proofs {
                for node in storage_item_proof {
                    match node {
                        TrieNode::Binary { left, right } => {
                            // log::info!("writing binary node...");
                            let fact = BinaryNodeFact::new((*left).into(), (*right).into())?;
                            fact.set_fact(&mut initial_state.ffc).await?;
                        }
                        TrieNode::Edge { child, path } => {
                            // log::info!("writing edge node...");
                            let fact = EdgeNodeFact::new(
                                (*child).into(),
                                NodePath(path.value.to_biguint()),
                                Length(path.len),
                            )?;
                            fact.set_fact(&mut initial_state.ffc).await?;
                        }
                    }
                }
            }
        }
        for node in &proof.contract_proof {
            match node {
                TrieNode::Binary { left, right } => {
                    // log::info!("writing binary node...");
                    let fact = BinaryNodeFact::new((*left).into(), (*right).into())?;
                    fact.set_fact(&mut initial_state.ffc).await?;
                }
                TrieNode::Edge { child, path } => {
                    // log::info!("writing edge node...");
                    let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))?;
                    fact.set_fact(&mut initial_state.ffc).await?;
                }
            }
        }
    }

    let default_general_config = StarknetGeneralConfig::default();

    let general_config = StarknetGeneralConfig {
        starknet_os_config: StarknetOsConfig {
            // TODO: the string given by provider is in decimal, the OS expects hex
            // chain_id: starknet_api::core::ChainId(chain_id.clone()),
            chain_id: starknet_api::core::ChainId(SN_SEPOLIA.to_string()),
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

        // // write storage facts before they're needed (TODO: should probably consolidate all fact writing)
        // for storage_entry in previous_storage_entries {
        //     // for storage_entry in previous_storage_entries.iter().chain(storage_entries.iter()) {
        //     let fact = StorageLeaf::new(storage_entry.value);
        //     fact.set_fact(&mut initial_state.ffc_for_class_hash).await?;
        // }

        let previous_tree = PatriciaTree { root: contract_storage_root, height: Height(251) };

        let previous_storage_proof =
            previous_storage_proofs.get(&contract_address).expect("there should be a previous storage proof");

        let contract_storage = ProverPerContractStorage::new(
            previous_block_id,
            contract_address,
            provider_url.clone(),
            previous_tree.root.into(),
            storage_proof,
            previous_storage_proof.clone(),
        )?;
        contract_storages.insert(contract_address, contract_storage);

        let (class_hash, previous_nonce) = if [Felt252::ZERO, Felt252::ONE].contains(&contract_address) {
            (Felt252::ZERO, Felt252::ZERO)
        } else {
            let class_hash = provider.get_class_hash_at(block_id, contract_address).await?;
            let previous_nonce = provider.get_nonce(previous_block_id, contract_address).await?;
            (class_hash, previous_nonce)
        };

        let contract_state = ContractState {
            contract_hash: class_hash.to_bytes_be().to_vec(),
            storage_commitment_tree: previous_tree,
            nonce: previous_nonce,
        };

        contract_states.insert(contract_address, contract_state);
    }

    // ensure that we have all class_hashes and compiled_class_hashes for any accessed contracts
    let mut accessed_class_hashes = HashSet::<_>::new();
    let mut compiled_classes = HashMap::new();
    for contract_address in &accessed_contracts {
        if let Ok(class_hash) = provider.get_class_hash_at(BlockId::Number(block_number), contract_address).await {
            let contract_class = provider.get_class(BlockId::Number(block_number), class_hash).await?;
            let generic_sierra_cc = match contract_class {
                starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
                    GenericSierraContractClass::from(flattened_sierra_cc)
                }
                starknet::core::types::ContractClass::Legacy(_) => {
                    unimplemented!("Fixme: Support legacy contract class")
                }
            };

            accessed_class_hashes.insert(class_hash);

            let generic_cc = generic_sierra_cc.compile()?;

            let (_contract_class_hash, compiled_contract_hash) =
                write_class_facts(generic_sierra_cc, generic_cc.clone(), &mut initial_state.ffc_for_class_hash).await?;

            class_hash_to_compiled_class_hash.insert(class_hash, compiled_contract_hash.into());
            compiled_classes.insert(compiled_contract_hash.into(), generic_cc.clone());
        } else {
            log::warn!("No class hash available for contract {}", contract_address);
        };
    }

    // query storage proofs for each accessed contract
    let class_hashes: Vec<&Felt252> = class_hash_to_compiled_class_hash.keys().collect();
    // TODO: we fetch proofs here for block-1, but we probably also need to fetch at the current
    //       block, likely for contracts that are deployed in this block
    let class_proofs = get_class_proofs(&pathfinder_client, &args.rpc_provider, block_number - 1, &class_hashes[..])
        .await
        .expect("Failed to fetch class proofs");
    let previous_class_proofs =
        get_class_proofs(&pathfinder_client, &args.rpc_provider, block_number - 1, &class_hashes[..])
            .await
            .expect("Failed to fetch class proofs");

    // write facts from class proof
    for proof in class_proofs.values() {
        for node in &proof.class_proof {
            match node {
                TrieNode::Binary { left, right } => {
                    // log::info!("writing binary node...");
                    let fact = BinaryNodeFact::new((*left).into(), (*right).into())?;

                    fact.set_fact(&mut initial_state.ffc_for_class_hash).await?;
                }
                TrieNode::Edge { child, path } => {
                    // log::info!("writing edge node...");
                    let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))?;
                    fact.set_fact(&mut initial_state.ffc_for_class_hash).await?;
                }
            }
        }
    }

    let visited_pcs: HashMap<Felt252, Vec<Felt252>> = blockifier_state
        .visited_pcs
        .iter()
        .map(|(class_hash, visited_pcs)| {
            (felt_api2vm(class_hash.0), visited_pcs.iter().copied().map(Felt252::from).collect::<Vec<_>>())
        })
        .collect();

    log::debug!("class_hash_to_compiled_class_hash ({}):", class_hash_to_compiled_class_hash.len());
    for (class_hash, compiled_class_hash) in &class_hash_to_compiled_class_hash {
        log::debug!("    0x{:x} => 0x{:x}", class_hash, compiled_class_hash);
    }

    // Pass all contract addresses as expected accessed indices
    // let contract_indices: HashSet<TreeIndex> =
    //     contract_states.keys().chain(contract_storages.keys()).map(|address|
    // address.to_biguint()).collect(); let contract_indices: Vec<TreeIndex> =
    // contract_indices.into_iter().collect();

    // let final_state =
    // initial_state.clone().apply_commitment_state_diff(blockifier_state.to_state_diff()).await?;

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
        block_hash: block_with_txs.block_hash,
    };
    let execution_helper = ExecutionHelperWrapper::<ProverPerContractStorage>::new(
        contract_storages,
        tx_execution_infos,
        &block_context,
        (old_block_number, old_block_hash),
    );

    let result = run_os(config::DEFAULT_COMPILED_OS, layout, os_input, block_context, execution_helper);

    match &result {
        Err(Runner(VmException(vme))) => {
            if let Some(traceback) = vme.traceback.as_ref() {
                log::error!("traceback:\n{}", traceback);
            }
            if let Some(inst_location) = &vme.inst_location {
                log::error!("died at: {}:{}", inst_location.input_file.filename, inst_location.start_line);
                log::error!("inst_location:\n{:?}", inst_location);
            }
        }
        Err(_) => {
            log::error!("exception:\n{:#?}", result);
        }
        _ => {}
    }

    result.unwrap();

    Ok(())
}
