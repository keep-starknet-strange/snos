use std::sync::Arc;

use reqwest::Url;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::JsonRpcClient;

use crate::pathfinder::client::PathfinderRpcClient;

struct RpcClientInner {
    /// starknet-rs client, used to access data from endpoints defined in the Starknet RPC spec.
    starknet_client: JsonRpcClient<HttpTransport>,
    /// A Pathfinder-specific client to access endpoints not covered by starknet-rs.
    pathfinder_client: PathfinderRpcClient,
}

impl RpcClientInner {
    fn new(base_url: &str) -> Self {
        let starknet_rpc_url = format!("{}/rpc/v0_8", base_url);
        log::info!("Starknet RPC URL: {}", starknet_rpc_url);
        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse(starknet_rpc_url.as_str())
                .unwrap_or_else(|e| panic!("Could not parse provider URL ({}): {}", starknet_rpc_url, e)),
        ));
        let pathfinder_client = PathfinderRpcClient::new(base_url);

        Self { starknet_client: provider, pathfinder_client }
    }
}

#[derive(Clone)]
pub struct RpcClient {
    inner: Arc<RpcClientInner>,
}

impl RpcClient {
    pub fn new(base_url: &str) -> Self {
        Self { inner: Arc::new(RpcClientInner::new(base_url)) }
    }

    pub fn starknet_rpc(&self) -> &JsonRpcClient<HttpTransport> {
        &self.inner.starknet_client
    }

    pub fn pathfinder_rpc(&self) -> &PathfinderRpcClient {
        &self.inner.pathfinder_client
    }
}
