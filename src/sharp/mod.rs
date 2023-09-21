pub mod pie;

use cairo_vm::vm::runners::cairo_pie::CairoPie;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use uuid::Uuid;

use crate::error::SnOsError;

#[allow(dead_code)]
pub const DEFUALT_SHARP_URL: &str = "https://testnet.provingservice.io";
pub const _LAMBDA_MAX_PIE_MB: u64 = 20_971_520;

#[derive(Debug)]
#[allow(dead_code)]
pub enum CairoJobStatus {
    Unknown,
    NotCreated,
    InProgress,
    Processed,
    Onchain,
    Invalid,
    Failed,
}

#[allow(dead_code)]
impl CairoJobStatus {
    fn as_str(&self) -> &'static str {
        match self {
            CairoJobStatus::Unknown => "UNKNOWN",
            CairoJobStatus::NotCreated => "NOT_CREATED",
            CairoJobStatus::InProgress => "IN_PROGRESS",
            CairoJobStatus::Processed => "PROCESSED",
            CairoJobStatus::Onchain => "ONCHAIN",
            CairoJobStatus::Invalid => "INVALID",
            CairoJobStatus::Failed => "FAILED",
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CairoStatusResponse {
    pub status: Option<String>,
    #[serde(rename = "validation_done")]
    pub validation_done: Option<bool>,
    pub version: Option<u64>,
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct CairoJobResponse {
    pub cairo_job_key: Option<Uuid>,
    pub version: Option<u64>,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    #[serde(rename = "errorType")]
    pub error_type: Option<String>,
    #[serde(rename = "stackTrace")]
    pub stack_trace: Option<Vec<String>>,
}

pub struct SharpClient {
    client: reqwest::blocking::Client,
    sharp_addr: String,
    pie_path: Option<PathBuf>,
}

impl SharpClient {
    pub fn new(sharp_addr: Option<String>, pie_path: Option<PathBuf>) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            sharp_addr: sharp_addr.unwrap_or_default(),
            pie_path,
        }
    }

    pub fn submit_pie(&self, pie_raw: CairoPie) -> Result<CairoJobResponse, SnOsError> {
        let pie_enc = match &self.pie_path {
            Some(pp) => pie::encode_pie(pie_raw, pp.as_path())?,
            None => pie::encode_pie_mem(pie_raw)?,
        };

        let data = json!({ "action": "add_job", "request": { "cairo_pie": pie_enc } });
        println!("DATA: {:?}", data);

        // CAREFUL NOT TO OVERWHELM SHARP DUE TO SHORT BLOCK TIMES
        let resp = self
            .client
            .post(&self.sharp_addr)
            .json(&data)
            .send()
            .map_err(|e| SnOsError::SharpRequest(format!("{e}")))?;

        match resp.status() {
            reqwest::StatusCode::OK => resp
                .json()
                .map_err(|e| SnOsError::SharpRequest(format!("{e}"))),
            _ => Err(SnOsError::SharpRequest("could not submit pie".to_string())),
        }
    }

    pub fn get_status(&self, job_key: &str) -> Result<CairoStatusResponse, SnOsError> {
        let data =
            serde_json::json!({ "action": "get_status", "request": { "cairo_job_key": job_key } });

        let resp = self
            .client
            .post(&self.sharp_addr)
            .json(&data)
            .send()
            .map_err(|e| SnOsError::SharpRequest(format!("{e}")))?;

        match resp.status() {
            reqwest::StatusCode::OK => resp
                .json()
                .map_err(|e| SnOsError::SharpRequest(format!("{e}"))),
            _ => Err(SnOsError::SharpRequest(
                "could not get job status".to_string(),
            )),
        }
    }
}

impl Default for SharpClient {
    fn default() -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            sharp_addr: DEFUALT_SHARP_URL.to_string(),
            pie_path: None,
        }
    }
}
