#[derive(thiserror::Error, Clone, Debug)]
pub enum SnOsError {
    #[error("SnOs Error: {0}.")]
    CatchAll(String),
}
