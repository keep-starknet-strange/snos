use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use starknet::providers::jsonrpc::{
    HttpTransport, HttpTransportError, JsonRpcError, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport,
};
use starknet::providers::ProviderRequestData;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub const RPC_WITNESS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum StoredResponse {
    Success(serde_json::Value),
    Error { code: i64, message: String, data: Option<serde_json::Value> },
}

impl StoredResponse {
    fn from_rpc(response: JsonRpcResponse<serde_json::Value>) -> Self {
        match response {
            JsonRpcResponse::Success { result, .. } => Self::Success(result),
            JsonRpcResponse::Error { error, .. } => {
                Self::Error { code: error.code, message: error.message, data: error.data }
            }
        }
    }

    fn into_rpc<R: DeserializeOwned>(self, id: u64) -> Result<JsonRpcResponse<R>, WitnessTransportError> {
        match self {
            Self::Success(value) => Ok(JsonRpcResponse::Success {
                id,
                result: serde_json::from_value(value).map_err(WitnessTransportError::Json)?,
            }),
            Self::Error { code, message, data } => {
                Ok(JsonRpcResponse::Error { id, error: JsonRpcError { code, message, data } })
            }
        }
    }
}

/// Portable request/response material required to prepare one or more SNOS blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcWitness {
    pub schema_version: u32,
    pub blocks: Vec<u64>,
    responses: BTreeMap<String, StoredResponse>,
    batch_responses: BTreeMap<String, Vec<StoredResponse>>,
}

impl RpcWitness {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn merge(witnesses: impl IntoIterator<Item = Self>) -> Result<Self, WitnessTransportError> {
        let mut merged = Self {
            schema_version: RPC_WITNESS_SCHEMA_VERSION,
            blocks: Vec::new(),
            responses: BTreeMap::new(),
            batch_responses: BTreeMap::new(),
        };

        for witness in witnesses {
            if witness.schema_version != RPC_WITNESS_SCHEMA_VERSION {
                return Err(WitnessTransportError::UnsupportedSchema(witness.schema_version));
            }
            merged.blocks.extend(witness.blocks);
            merge_entries(&mut merged.responses, witness.responses)?;
            merge_entries(&mut merged.batch_responses, witness.batch_responses)?;
        }
        merged.blocks.sort_unstable();
        merged.blocks.dedup();
        Ok(merged)
    }

    pub fn response_count(&self) -> usize {
        self.responses.len() + self.batch_responses.values().map(Vec::len).sum::<usize>()
    }
}

fn merge_entries<T: PartialEq>(
    target: &mut BTreeMap<String, T>,
    source: BTreeMap<String, T>,
) -> Result<(), WitnessTransportError> {
    for (key, value) in source {
        if target.get(&key).is_some_and(|existing| existing != &value) {
            return Err(WitnessTransportError::ConflictingResponse(key));
        }
        target.insert(key, value);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessTransportError {
    #[error(transparent)]
    Http(#[from] HttpTransportError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("RPC witness is missing request {0}")]
    MissingRequest(String),
    #[error("RPC witness contains conflicting responses for request {0}")]
    ConflictingResponse(String),
    #[error("unsupported RPC witness schema version {0}")]
    UnsupportedSchema(u32),
    #[error("RPC witness recorder mutex poisoned")]
    RecorderPoisoned,
}

#[derive(Debug, Default)]
struct RecordedResponses {
    responses: BTreeMap<String, StoredResponse>,
    batch_responses: BTreeMap<String, Vec<StoredResponse>>,
}

#[derive(Debug, Clone, Default)]
pub struct RpcWitnessRecorder {
    inner: Arc<Mutex<RecordedResponses>>,
}

impl RpcWitnessRecorder {
    pub fn snapshot(&self, blocks: Vec<u64>) -> Result<RpcWitness, WitnessTransportError> {
        let recorded = self.inner.lock().map_err(|_| WitnessTransportError::RecorderPoisoned)?;
        Ok(RpcWitness {
            schema_version: RPC_WITNESS_SCHEMA_VERSION,
            blocks,
            responses: recorded.responses.clone(),
            batch_responses: recorded.batch_responses.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub enum RpcTransport {
    Http(HttpTransport),
    Recording { http: HttpTransport, recorder: RpcWitnessRecorder },
    Witness(Arc<RpcWitness>),
}

impl RpcTransport {
    pub fn recording(http: HttpTransport) -> (Self, RpcWitnessRecorder) {
        let recorder = RpcWitnessRecorder::default();
        (Self::Recording { http, recorder: recorder.clone() }, recorder)
    }

    pub fn witness(witness: RpcWitness) -> Result<Self, WitnessTransportError> {
        if witness.schema_version != RPC_WITNESS_SCHEMA_VERSION {
            return Err(WitnessTransportError::UnsupportedSchema(witness.schema_version));
        }
        Ok(Self::Witness(Arc::new(witness)))
    }
}

fn request_key<P: Serialize>(method: JsonRpcMethod, params: &P) -> Result<String, WitnessTransportError> {
    serde_json::to_string(&(method, params)).map_err(WitnessTransportError::Json)
}

fn batch_key(requests: &[ProviderRequestData]) -> Result<String, WitnessTransportError> {
    serde_json::to_string(requests).map_err(WitnessTransportError::Json)
}

#[async_trait]
impl JsonRpcTransport for RpcTransport {
    type Error = WitnessTransportError;

    async fn send_request<P, R>(&self, method: JsonRpcMethod, params: P) -> Result<JsonRpcResponse<R>, Self::Error>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let key = request_key(method, &params)?;
        match self {
            Self::Http(http) => http.send_request(method, params).await.map_err(Into::into),
            Self::Recording { http, recorder } => {
                let response = http.send_request::<_, serde_json::Value>(method, params).await?;
                let stored = StoredResponse::from_rpc(response);
                recorder
                    .inner
                    .lock()
                    .map_err(|_| WitnessTransportError::RecorderPoisoned)?
                    .responses
                    .insert(key, stored.clone());
                stored.into_rpc(1)
            }
            Self::Witness(witness) => witness
                .responses
                .get(&key)
                .cloned()
                .ok_or_else(|| WitnessTransportError::MissingRequest(key))?
                .into_rpc(1),
        }
    }

    async fn send_requests<R>(&self, requests: R) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync,
    {
        let key = batch_key(requests.as_ref())?;
        match self {
            Self::Http(http) => http.send_requests(requests).await.map_err(Into::into),
            Self::Recording { http, recorder } => {
                let responses = http.send_requests(requests).await?;
                let stored = responses.into_iter().map(StoredResponse::from_rpc).collect::<Vec<_>>();
                recorder
                    .inner
                    .lock()
                    .map_err(|_| WitnessTransportError::RecorderPoisoned)?
                    .batch_responses
                    .insert(key, stored.clone());
                stored.into_iter().enumerate().map(|(id, response)| response.into_rpc(id as u64)).collect()
            }
            Self::Witness(witness) => witness
                .batch_responses
                .get(&key)
                .cloned()
                .ok_or_else(|| WitnessTransportError::MissingRequest(key))?
                .into_iter()
                .enumerate()
                .map(|(id, response)| response.into_rpc(id as u64))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_witness_rejects_conflicting_entries() {
        let mut first = RpcWitness {
            schema_version: RPC_WITNESS_SCHEMA_VERSION,
            blocks: vec![1],
            responses: BTreeMap::new(),
            batch_responses: BTreeMap::new(),
        };
        first.responses.insert("same".into(), StoredResponse::Success(serde_json::json!(1)));
        let mut second = first.clone();
        second.blocks = vec![2];
        second.responses.insert("same".into(), StoredResponse::Success(serde_json::json!(2)));

        assert!(matches!(RpcWitness::merge([first, second]), Err(WitnessTransportError::ConflictingResponse(_))));
    }
}
