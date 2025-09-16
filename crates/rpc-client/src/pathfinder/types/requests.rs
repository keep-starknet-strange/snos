use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    jsonrpc: String,
    id: String,
    method: String,
    params: Value,
}

impl Request {
    pub fn new(method: &str, params: Value) -> Self {
        Self { jsonrpc: String::from("2.0"), id: String::from("1"), method: String::from(method), params }
    }
}
