use crate::error::PieGenerationError;

/// Configuration for OS hints and execution parameters.
///
/// This struct controls various aspects of the Starknet OS execution, including
/// debug mode, output verbosity, and data availability mode.
///
/// # Examples
///
/// ```rust
/// use generate_pie::OsHintsConfiguration;
///
/// // Use default configuration
/// let config = OsHintsConfiguration::default();
///
/// // Create custom configuration for debugging
/// let debug_config = OsHintsConfiguration {
///     debug_mode: true,
///     full_output: true,
///     use_kzg_da: false,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct OsHintsConfiguration {
    /// Whether to enable debug mode for detailed logging and output.
    pub debug_mode: bool,
    /// Whether to generate full output including intermediate states.
    pub full_output: bool,
    /// Whether to use KZG (Kate-Zaverucha-Goldberg) data availability mode.
    pub use_kzg_da: bool,
}

impl Default for OsHintsConfiguration {
    /// Creates a default configuration with sensible defaults.
    ///
    /// # Returns
    ///
    /// A `OsHintsConfiguration` instance with:
    /// - Debug mode: enabled (for better error reporting)
    /// - Full output: disabled (for performance)
    /// - KZG DA: enabled (modern data availability)
    fn default() -> Self {
        Self { debug_mode: true, full_output: false, use_kzg_da: true }
    }
}

impl OsHintsConfiguration {
    /// Validates the OS hints configuration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the configuration is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns a `PieGenerationError::InvalidConfig` if the configuration is invalid.
    pub fn validate(&self) -> Result<(), PieGenerationError> {
        // Currently no validation needed, but this provides a place for future validation
        Ok(())
    }
}
