//! # Starknet OS Types
//!
//! This crate provides generic, type-safe abstractions for Starknet contract classes and related types.
//! It supports conversion between different contract class representations used across the Starknet ecosystem.
//!
//! ## Features
//!
//! - **Generic Contract Classes**: Unified interfaces for Cairo 0 and Cairo 1 contract classes
//! - **Lazy Conversion**: Efficient conversion between different contract class formats
//! - **Type Safety**: Strong typing with compile-time guarantees
//! - **Hash Computation**: Built-in class hash computation for all supported formats
//! - **Serialization**: Full serde support for JSON serialization/deserialization
//!
//! ## Modules
//!
//! - [`casm_contract_class`] - Cairo 1 compiled contract classes (CASM)
//! - [`sierra_contract_class`] - Cairo 1 Sierra contract classes
//! - [`deprecated_compiled_class`] - Cairo 0 legacy contract classes
//! - [`compiled_class`] - Generic enum for all contract class types
//! - [`hash`] - Hash types and utilities
//! - [`class_hash_utils`] - Class hash computation utilities
//! - [`chain_id`] - Chain ID conversion utilities
//! - [`error`] - Error types
//! - [`starknet_core_addons`] - Additional utilities for starknet-core types
//!
//! ## Usage
//!
//! ```rust
//! use starknet_os_types::casm_contract_class::GenericCasmContractClass
//! use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
//!
//! // Load a Cairo 1 compiled contract
//! let casm_bytes = include_bytes!("path/to/contract.casm.json");
//! let casm_class = GenericCasmContractClass::from_bytes(casm_bytes.to_vec());
//! let class_hash = casm_class.class_hash()?;
//!
//! // Load a Sierra contract
//! let sierra_bytes = include_bytes!("path/to/contract.sierra");
//! let sierra_class = GenericSierraContractClass::from_bytes(sierra_bytes.to_vec());
//! let compiled = sierra_class.compile()?;
//! ```

pub mod casm_contract_class;
pub mod chain_id;
pub mod class_hash_utils;
pub mod compiled_class;
pub mod deprecated_compiled_class;
pub mod error;
pub mod hash;
pub mod sierra_contract_class;
pub mod starknet_core_addons;
