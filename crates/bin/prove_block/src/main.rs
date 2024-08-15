use std::collections::{HashMap, HashSet};
use std::error::Error;

use blockifier::state::cached_state::{CachedState, GlobalContractCache};
use blockifier::state::state_api::State as _;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use cairo_vm::Felt252;
use clap::Parser;
use reexecute::{reexecute_transactions_with_blockifier, ProverPerContractStorage};
use rpc_replay::block_context::build_block_context;
use rpc_replay::rpc_state_reader::AsyncRpcStateReader;
use rpc_replay::transactions::starknet_rs_to_blockifier;
use rpc_utils::{get_class_proofs, get_storage_proofs, process_function_invocations, RpcStorage, TrieNode};
use starknet::core::types::{
    BlockId, ExecuteInvocation, MaybePendingBlockWithTxs, MaybePendingStateUpdate, TransactionTrace,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};
use starknet_os::config::{StarknetGeneralConfig, StarknetOsConfig, SN_SEPOLIA, STORED_BLOCK_HASH_BUFFER};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::error::SnOsError::Runner;
use starknet_os::execution::helper::{ContractStorageMap, ExecutionHelperWrapper};
use starknet_os::io::input::StarknetOsInput;
use starknet_os::starknet::business_logic::fact_state::contract_class_objects::{
    get_ffc_for_contract_class_facts, ContractClassLeaf,
};
use starknet_os::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use starknet_os::starknet::business_logic::fact_state::state::SharedState;
use starknet_os::starknet::business_logic::utils::write_class_facts;
use starknet_os::starknet::starknet_storage::CommitmentInfo;
use starknet_os::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath, TreeIndex};
use starknet_os::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use starknet_os::storage::storage::{Fact, FactFetchingContext};
use starknet_os::utils::felt_api2vm;
use starknet_os::{config, run_os};
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

use crate::rpc_utils::CachedRpcStorage;
use crate::types::starknet_rs_tx_to_internal_tx;

mod reexecute;
mod rpc_utils;
mod types;

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

// build state representing the end of the previous block on which the current
// block can be built.
// inspiration: TestSharedState::apply_state_updates_starknet_api()
//
// Returns:
// * a set of all contracts accessed
// * a SharedState object representing storage for the changes provided
async fn build_initial_state(
    ffc: FactFetchingContext<CachedRpcStorage, PedersenHash>,
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
    address_to_class_hash: HashMap<Felt252, Felt252>,
    address_to_nonce: HashMap<Felt252, Felt252>,
    class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>>,
) -> Result<(HashSet<Felt252>, SharedState<CachedRpcStorage, PedersenHash>), Box<dyn Error>> {
    let shared_state = SharedState::empty(ffc).await?;

    let accessed_addresses_felts: HashSet<_> =
        address_to_class_hash.keys().chain(address_to_nonce.keys()).chain(storage_updates.keys()).collect();
    let accessed_addresses: Vec<TreeIndex> = accessed_addresses_felts.iter().map(|x| x.to_biguint()).collect();

    let mut facts = None;
    let mut ffc = shared_state.ffc;
    let mut current_contract_states: HashMap<TreeIndex, ContractState> =
        shared_state.contract_states.get_leaves(&mut ffc, &accessed_addresses, &mut facts).await?;

    // Update contract storage roots with cached changes.
    let empty_updates = HashMap::new();
    let mut updated_contract_states = HashMap::new();
    for address in accessed_addresses_felts {
        // unwrap() is safe as an entry is guaranteed to be present with `get_leaves()`.
        let tree_index = address.to_biguint();
        let updates = storage_updates.get(address).unwrap_or(&empty_updates);
        let nonce = address_to_nonce.get(address).cloned();
        let mut class_hash = address_to_class_hash.get(address).cloned();
        if class_hash.is_none() {
            log::debug!("contract {} has no contract hash, fetching from RPC", address);
            let resp = provider.get_class_hash_at(BlockId::Number(block_number), address).await;
            class_hash = if let Ok(class_hash) = resp {
                Some(class_hash)
            } else {
                log::warn!("contract {} has no contract hash from RPC either", address);
                None
            };
        }
        let updated_contract_state =
            current_contract_states.remove(&tree_index).unwrap().update(&mut ffc, updates, nonce, class_hash).await?;

        updated_contract_states.insert(tree_index, updated_contract_state);
    }

    // Apply contract changes on global root.
    log::debug!("Updating contract state tree with {} modifications...", accessed_addresses.len());
    let global_state_modifications: Vec<_> = updated_contract_states.into_iter().collect();

    let updated_global_contract_root =
        shared_state.contract_states.update(&mut ffc, global_state_modifications, &mut facts).await?;

    let mut ffc_for_contract_class = get_ffc_for_contract_class_facts(&ffc);

    let updated_contract_classes = match shared_state.contract_classes {
        Some(tree) => {
            log::debug!(
                "Updating contract class tree with {} modifications...",
                class_hash_to_compiled_class_hash.len()
            );
            let modifications: Vec<_> = class_hash_to_compiled_class_hash
                .into_iter()
                .map(|(key, value)| (key.to_biguint(), ContractClassLeaf::create(value)))
                .collect();
            Some(tree.update(&mut ffc_for_contract_class, modifications, &mut facts).await?)
        }
        None => {
            assert_eq!(class_hash_to_compiled_class_hash.len(), 0, "contract_classes must be concrete before update.");
            None
        }
    };

    let accessed_addresses: HashSet<_> = accessed_addresses.into_iter().map(Felt252::from).collect();

    Ok((
        accessed_addresses,
        SharedState {
            contract_states: updated_global_contract_root,
            contract_classes: updated_contract_classes,
            ffc,
            ffc_for_class_hash: ffc_for_contract_class,
            contract_addresses: Default::default(),
        },
    ))
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

    // extract other contracts used in our block from the block trace
    let mut contracts_subcalled = HashSet::new();
    let traces = provider.trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    for trace in traces {
        match trace.trace_root {
            TransactionTrace::Invoke(invoke_trace) => {
                if let Some(inv) = invoke_trace.validate_invocation {
                    process_function_invocations(inv, &mut contracts_subcalled, 0);
                }
                match invoke_trace.execute_invocation {
                    ExecuteInvocation::Success(inv) => {
                        process_function_invocations(inv, &mut contracts_subcalled, 0);
                    }
                    ExecuteInvocation::Reverted(_) => unimplemented!("handle reverted invoke trace"),
                }
                if let Some(inv) = invoke_trace.fee_transfer_invocation {
                    process_function_invocations(inv, &mut contracts_subcalled, 0);
                }
            }
            _ => unimplemented!("process other txn traces"),
        }
    }

    let previous_storage_proofs = get_storage_proofs(
        &pathfinder_client,
        &args.rpc_provider,
        block_number - 1,
        &state_update,
        &contracts_subcalled,
    )
    .await
    .expect("Failed to fetch storage proofs");

    let storage_proofs =
        get_storage_proofs(&pathfinder_client, &args.rpc_provider, block_number, &state_update, &contracts_subcalled)
            .await
            .expect("Failed to fetch storage proofs");

    let block_context = build_block_context(chain_id.clone(), &block_with_txs);

    let old_block_number = Felt252::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    // initialize storage. We use a CachedStorage with a RcpStorage as the main storage, meaning
    // that a DictStorage serves as the cache layer and we will use Pathfinder RPC for cache misses
    let rpc_storage = RpcStorage::new();
    let cached_storage = CachedRpcStorage::new(Default::default(), rpc_storage);

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
            log::debug!(
                "probably-account contract {} nonce: {} - {} => {}",
                nonce_update.contract_address,
                nonce_update.nonce,
                num_nonce_bumps,
                previous_nonce,
            );
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
        FactFetchingContext::new(cached_storage),
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
            log::info!("Filling in class_hash {:x} for txn", class_hash);
            transaction.class_hash = Some(*class_hash);
        } else {
            // TODO: are there txn types which wouldn't have a sender address?
            unimplemented!("Found transaction without sender_address");
        }
    }

    // write facts from proof
    for proof in storage_proofs.values().chain(previous_storage_proofs.values()) {
        log::debug!("writing storage proof...");
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
                            let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))?;
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

    for (contract_address, _storage_proof) in storage_proofs {
        let previous_storage_proof =
            previous_storage_proofs.get(&contract_address).expect("failed to find previous storage proof");

        let previous_tree = PatriciaTree { root: previous_storage_proof.state_commitment.into(), height: Height(251) };

        let contract_storage = ProverPerContractStorage::new(
            previous_block_id,
            contract_address,
            provider_url.clone(),
            previous_tree.clone(),
            initial_state.ffc.clone(),
        ).await?;
        contract_storages.insert(contract_address, contract_storage);

        log::debug!("contract address: {}", contract_address.to_hex_string());
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

    let blockifier_state_reader = AsyncRpcStateReader::new(provider, BlockId::Number(block_number - 1));

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
    let contract_indices: HashSet<TreeIndex> =
        contract_states.keys().chain(contract_storages.keys()).map(|address| address.to_biguint()).collect();
    let contract_indices: Vec<TreeIndex> = contract_indices.into_iter().collect();

    let final_state = initial_state.clone().apply_commitment_state_diff(blockifier_state.to_state_diff()).await?;

    let contract_state_commitment_info = CommitmentInfo::create_from_expected_updated_tree::<_, _, ContractState>(
        initial_state.contract_states.clone(),
        final_state.contract_states.clone(),
        &contract_indices,
        &mut initial_state.ffc,
    )
    .await
    .unwrap_or_else(|e| panic!("Could not create contract state commitment info: {:?}", e));

    let contract_class_commitment_info = CommitmentInfo::create_from_expected_updated_tree::<_, _, ContractClassLeaf>(
        initial_state.contract_classes.clone().expect("previous state should have class trie"),
        final_state.contract_classes.clone().expect("updated state should have class trie"),
        &contract_indices,
        &mut initial_state.ffc_for_class_hash,
    )
    .await
    .unwrap_or_else(|e| panic!("Could not create contract class commitment info: {:?}", e));

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
