use std::sync::Arc;

use reqwest::Url;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::JsonRpcClient;

use crate::pathfinder::client::PathfinderRpcClient;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Encountered a request error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Encountered a version error: {0}")]
    VersionError(String),
    #[error("Encountered a custom error: {0}")]
    CustomError(String),
}

#[derive(Debug)]
pub enum ClientVersion {
    Rpcv07(String),
    Rpcv08(String),
}

impl TryFrom<&str> for ClientVersion {
    type Error = ClientError;

    fn try_from(version: &str) -> Result<ClientVersion, ClientError> {
        match version {
            "v0_7" => Ok(ClientVersion::Rpcv07(version.to_owned())),
            "v0_8" => Ok(ClientVersion::Rpcv08(version.to_owned())),
            _ => Err(ClientError::VersionError(format!("Received invalid version: {version:?}"))),
        }
    }
}

struct RpcClientInner {
    /// starknet-rs client, used to access data from endpoints defined in the Starknet RPC spec.
    starknet_client: JsonRpcClient<HttpTransport>,
    /// A Pathfinder-specific client to access endpoints not covered by starknet-rs.
    pathfinder_client: PathfinderRpcClient,
}

impl RpcClientInner {
    fn new(base_url: &str, version: ClientVersion) -> Self {
        let rpc_version = match &version {
            ClientVersion::Rpcv07(rpc_version) => rpc_version,
            ClientVersion::Rpcv08(rpc_version) => rpc_version,
        };

        let starknet_rpc_url = format!("{}/rpc/{}", base_url, rpc_version);
        log::info!("Starknet RPC URL: {}", starknet_rpc_url);
        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse(starknet_rpc_url.as_str())
                .unwrap_or_else(|e| panic!("Could not parse provider URL ({}): {}", starknet_rpc_url, e)),
        ));
        let pathfinder_client = PathfinderRpcClient::new(base_url, version);

        Self { starknet_client: provider, pathfinder_client }
    }
}

#[derive(Clone)]
pub struct RpcClient {
    inner: Arc<RpcClientInner>,
}

impl RpcClient {
    pub fn new(base_url: &str, version: ClientVersion) -> Self {
        Self { inner: Arc::new(RpcClientInner::new(base_url, version)) }
    }

    pub fn starknet_rpc(&self) -> &JsonRpcClient<HttpTransport> {
        &self.inner.starknet_client
    }

    pub fn pathfinder_rpc(&self) -> &PathfinderRpcClient {
        &self.inner.pathfinder_client
    }
}
