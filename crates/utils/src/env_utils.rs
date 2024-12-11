use std::env::VarError;

pub fn get_env_var(key: &str) -> Result<String, VarError> {
    std::env::var(key)
}

pub fn get_env_var_or_default(key: &str, default: &str) -> String {
    get_env_var(key).unwrap_or(default.to_string())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    #[test]
    fn test_get_env_var_existing() {
        let test_key = "TEST_ENV_VAR";
        let test_value = "test_value";
        env::set_var(test_key, test_value);

        let result = get_env_var(test_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_value);

        env::remove_var(test_key);
    }

    #[test]
    fn test_get_env_var_non_existing() {
        let test_key = "NON_EXISTING_VAR";
        env::remove_var(test_key); // Ensure it doesn't exist

        let result = get_env_var(test_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VarError::NotPresent));
    }

    #[test]
    fn test_get_env_var_or_default_existing() {
        let test_key = "TEST_ENV_VAR_DEFAULT";
        let test_value = "actual_value";
        let default_value = "default_value";
        env::set_var(test_key, test_value);

        let result = get_env_var_or_default(test_key, default_value);
        assert_eq!(result, test_value);

        env::remove_var(test_key);
    }

    #[test]
    fn test_get_env_var_or_default_non_existing() {
        let test_key = "NON_EXISTING_VAR_DEFAULT";
        let default_value = "default_value";
        env::remove_var(test_key); // Ensure it doesn't exist

        let result = get_env_var_or_default(test_key, default_value);
        assert_eq!(result, default_value);
    }
}
