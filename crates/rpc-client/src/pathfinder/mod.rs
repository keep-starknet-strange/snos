//! Pathfinder-specific RPC client and proof verification utilities.
//!
//! This module provides a specialized RPC client for Pathfinder nodes, which includes
//! endpoints not covered by the standard Starknet RPC specification. It also includes
//! proof verification utilities for validating storage and class proofs.
//!
//! ## Modules
//!
//! - [`client`] - Pathfinder-specific RPC client implementation
//! - [`error`] - Error types for Pathfinder operations
//! - [`types`] - Type definitions for Pathfinder responses
//! - [`constants`] - Constants used throughout the module

pub mod client;
mod constants;
pub mod error;
pub mod types;
