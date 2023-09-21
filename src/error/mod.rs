#[derive(thiserror::Error, Clone, Debug)]
pub enum SnOsError {
    #[error("SnOs Error: {0}")]
    CatchAll(String),
    #[error("PIE Parse Error: {0}")]
    PieParsing(String),
    #[error("PIE Zip Error: {0}")]
    PieZipping(String),
    #[error("PIE Encode Error: {0}")]
    PieEncoding(String),
    #[error("SHARP Request Error: {0}")]
    SharpRequest(String),
}
