pub mod pie;

use std::path::PathBuf;

use cairo_vm::vm::runners::cairo_pie::CairoPie;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::error::SnOsError;

#[allow(dead_code)]
pub const DEFUALT_SHARP_URL: &str = "https://testnet.provingservice.io";
pub const _LAMBDA_MAX_PIE_MB: u64 = 20_971_520;

#[derive(Default, Clone, Debug, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CairoJobStatus {
    #[default]
    UNKNOWN,
    NOT_CREATED,
    IN_PROGRESS,
    PROCESSED,
    ONCHAIN,
    INVALID,
    FAILED,
}

#[derive(Default, Clone, Debug, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
pub enum InvalidReason {
    #[default]
    CAIRO_PIE_RUN_FAILURE,
    FAILED_TO_GENERATE_FACT,
    INCOMPATIBLE_PRIME,
    NO_COMPATIBLE_LAYOUT,
    INVALID_BUILTIN_ORDER_DECLERATION,
    INVALID_BUILTIN_USAGE,
    INVALID_CAIRO_PIE_FILE_FORMAT,
    INVALID_CAIRO_PIE_STORAGE_KEY,
    PAGE_SIZE_EXCEEDS_LIMIT,
    SECURITY_CHECK_FAILURE,
}

#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub struct CairoStatusResponse {
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub status: CairoJobStatus,
    pub validation_done: Option<bool>,
    pub error_log: Option<String>,
    pub invalid_reason: Option<InvalidReason>,
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct CairoJobResponse {
    #[serde(default)]
    pub version: u64,
    pub cairo_job_key: Option<Uuid>,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    #[serde(rename = "errorType")]
    pub error_type: Option<String>,
    #[serde(rename = "stackTrace")]
    pub stack_trace: Option<Vec<String>>,
}

pub struct SharpClient {
    client: Client,
    sharp_addr: String,
    pie_path: Option<PathBuf>,
}

pub enum SharpPie {
    EncodedPie(String),
    PieObject(Box<CairoPie>),
}

impl SharpClient {
    pub fn submit_pie(&self, pie: SharpPie) -> Result<CairoJobResponse, SnOsError> {
        let pie_enc = match pie {
            SharpPie::EncodedPie(encoded_pie) => encoded_pie,
            SharpPie::PieObject(pie_object) => match &self.pie_path {
                Some(pp) => pie::encode_pie(*pie_object, pp.as_path())?,
                None => pie::encode_pie_mem(*pie_object)?,
            },
        };

        let data = json!({ "action": "add_job", "request": { "cairo_pie": pie_enc } });

        // CAREFUL NOT TO OVERWHELM SHARP DUE TO SHORT BLOCK TIMES
        let resp = self
            .client
            .post(&self.sharp_addr)
            .json(&data)
            .send()
            .map_err(|e| SnOsError::SharpRequest(format!("{e}")))?;

        match resp.status() {
            reqwest::StatusCode::OK => resp.json().map_err(|e| SnOsError::SharpRequest(format!("{e}"))),
            _ => Err(SnOsError::SharpRequest("could not submit pie".to_string())),
        }
    }

    pub fn get_status(&self, job_key: &Uuid) -> Result<CairoStatusResponse, SnOsError> {
        let data = serde_json::json!({ "action": "get_status", "request": { "cairo_job_key": job_key } });

        let resp = self
            .client
            .post(&self.sharp_addr)
            .json(&data)
            .send()
            .map_err(|e| SnOsError::SharpRequest(format!("{e}")))?;

        match resp.status() {
            reqwest::StatusCode::OK => resp.json().map_err(|e| SnOsError::SharpRequest(format!("{e}"))),
            _ => Err(SnOsError::SharpRequest("could not get job status".to_string())),
        }
    }
    pub fn with_sharp_addr(sharp_addr: &str) -> Self {
        Self { sharp_addr: sharp_addr.to_string(), ..Self::default() }
    }
    pub fn with_pie_path(pie_path: &str) -> Self {
        Self { pie_path: Some(PathBuf::from(pie_path)), ..Self::default() }
    }
}

impl Default for SharpClient {
    fn default() -> Self {
        Self { client: Client::new(), sharp_addr: DEFUALT_SHARP_URL.to_string(), pie_path: None }
    }
}
