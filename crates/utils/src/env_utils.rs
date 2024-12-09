use std::env::VarError;

pub fn get_env_var(key: &str) -> Result<String, VarError> {
    std::env::var(key)
}

pub fn get_env_var_or_default(key: &str, default: &str) -> String {
    get_env_var(key).unwrap_or(default.to_string())
}
