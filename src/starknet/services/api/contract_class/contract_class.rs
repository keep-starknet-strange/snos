use std::collections::HashMap;

use cairo_vm::serde::deserialize_program::{parse_program_json, ProgramJson};
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::program::Program;
use cairo_vm::Felt252;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use starknet_api::state::EntryPointType;

pub type EntryPointsByType = HashMap<EntryPointType, Vec<CompiledClassEntryPoint>>;

#[derive(Debug, Clone, Deserialize)]

pub struct CompiledClassEntryPoint {
    /// A field element that encodes the signature of the called function.
    selector: Felt252,
    /// The offset of the instruction that should be called within the contract bytecode.
    offset: u64,
    /// Builtins used by the entry point.
    builtins: Option<Vec<BuiltinName>>,
}

/// A variable inside the Cairo code.
#[derive(Debug, Clone, Deserialize)]
pub struct CairoVariable {
    name: String,
    #[serde(rename = "type")]
    type_: String,
}

/// Application Binary Interface (ABI) for one entrypoint of a contract.
#[derive(Debug, Clone, Deserialize)]
pub struct Abi {
    /// Name of the entrypoint.
    name: String,
    /// Input variables.
    inputs: Vec<CairoVariable>,
    /// Output variables.
    outputs: Vec<CairoVariable>,
    #[serde(rename = "stateMutability")]
    state_mutability: Option<String>,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug, Deserialize)]
pub struct DeprecatedCompiledClass {
    #[serde(deserialize_with = "deserialize_program")]
    pub program: Program,
    pub entry_points_by_type: EntryPointsByType,
    pub abi: Option<Vec<Abi>>,
}

fn deserialize_program<'de, D>(deserializer: D) -> Result<Program, D::Error>
where
    D: Deserializer<'de>,
{
    let program_json = ProgramJson::deserialize(deserializer)?;
    parse_program_json(program_json, None).map_err(|e| Error::custom(e.to_string()))
}
