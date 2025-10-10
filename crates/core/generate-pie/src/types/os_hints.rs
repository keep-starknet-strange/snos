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
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
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
        Self { debug_mode: true, full_output: true, use_kzg_da: false }
    }
}

impl OsHintsConfiguration {
    pub fn default_with_is_l3(is_l3: bool) -> OsHintsConfiguration {
        if is_l3 {
            Self { debug_mode: true, full_output: true, use_kzg_da: false }
        } else {
            Self { debug_mode: true, full_output: false, use_kzg_da: false }
        }
    }
}
