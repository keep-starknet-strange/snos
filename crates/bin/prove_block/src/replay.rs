use blockifier::{state::cached_state::{CachedState, GlobalContractCache}, transaction::objects::TransactionExecutionInfo};
use rpc_state_reader::{blockifier_state_reader::{execute_tx_configurable, RpcStateReader}, rpc_state::{BlockValue, RpcChain, RpcState}, rpc_state_errors::RpcStateError};
use starknet_api::block::BlockNumber;

fn parse_network(network: &str) -> RpcChain {
    // TODO: support Sepolia?
    match network.to_lowercase().as_str() {
        "mainnet" => RpcChain::MainNet,
        "testnet" => RpcChain::TestNet,
        "testnet2" => RpcChain::TestNet2,
        _ => panic!("Invalid network name, it should be one of: mainnet, testnet, testnet2"),
    }
}

pub fn build_cached_state(network: &str, block_number: u64) -> CachedState<RpcStateReader> {
    let previous_block_number = BlockNumber(block_number);
    let rpc_chain = parse_network(network);

    let rpc_reader = RpcStateReader(
        RpcState::new_rpc(rpc_chain, previous_block_number.into())
            .expect("failed to create state reader"),
    );

    CachedState::new(rpc_reader, GlobalContractCache::new(128))
}

fn get_transaction_hashes(network: &str, block_number: u64) -> Result<Vec<String>, RpcStateError> {
    let network = parse_network(network);
    let block_value = BlockValue::Number(BlockNumber(block_number));
    let rpc_state = RpcState::new_rpc(network, block_value)?;
    rpc_state.get_transaction_hashes()
}

fn show_execution_data(
    state: &mut CachedState<RpcStateReader>,
    tx_hash: String,
    chain: &str,
    block_number: u64,
) {
    log::info!("starting blockifier reexecution");

    let previous_block_number = BlockNumber(block_number - 1);

    let (execution_info, _trace, rpc_receipt) =
        match execute_tx_configurable(state, &tx_hash, previous_block_number, false, true) {
            Ok(x) => x,
            Err(error_reason) => {
                log::error!("execution failed unexpectedly: {}", error_reason);
                return;
            }
        };

    let execution_status = match &execution_info.revert_error {
        Some(_) => "REVERTED",
        None => "SUCCEEDED",
    };
    let rpc_execution_status = rpc_receipt.execution_status;
    let status_matches = execution_status == rpc_execution_status;

    if !status_matches {
        log::error!("!status_matches, insert useful error debug info here"); // uhh, TODO
        /*
        error!(
            transaction_hash = tx_hash,
            chain = chain,
            execution_status,
            rpc_execution_status,
            execution_error_message = execution_info.revert_error,
            "rpc and execution status diverged"
        )
        */
    } else {
        log::error!("status_matches, insert useful debug info here"); // uhh, TODO
        /*
        info!(
            transaction_hash = tx_hash,
            chain = chain,
            execution_status,
            rpc_execution_status,
            execution_error_message = execution_info.revert_error,
            "execution finished successfully"
        );
        */
    }

    let execution_gas = execution_info.actual_fee;
    let rpc_gas = rpc_receipt.actual_fee;
    log::debug!("exec gas: {:?}, rpc gas: {:?}", execution_gas, rpc_gas);
}

fn get_transaction_execution_info(
    state: &mut CachedState<RpcStateReader>,
    tx_hash: String,
    chain: &str,
    block_number: u64,
) -> TransactionExecutionInfo {
    let previous_block_number = BlockNumber(block_number - 1);
    let (execution_info, _trace, rpc_receipt) =
        match execute_tx_configurable(state, &tx_hash, previous_block_number, false, false) {
            Ok(x) => x,
            Err(error_reason) => {
                panic!("execution failed unexpectedly: {}", error_reason);
            }
        };

    execution_info
}

pub fn reexecute_transactions_with_blockifier(chain: &str, block_number: u64) -> Vec<TransactionExecutionInfo> {
    let mut state = build_cached_state(&chain, block_number - 1);

    let transaction_hashes = get_transaction_hashes(&chain, block_number)
        .expect("Unable to fetch the transaction hashes.");
    let mut tx_execution_infos = Vec::with_capacity(transaction_hashes.len());
    for tx_hash in transaction_hashes {
        // show_execution_data(&mut state, tx_hash, &chain, block_number);
        tx_execution_infos.push(get_transaction_execution_info(&mut state, tx_hash, &chain, block_number));
    }

    tx_execution_infos
}
