//! API to Blockifier Type Conversion Module
//!
//! This module provides conversion functionality between Starknet RPC API types
//! and Blockifier/Sequencer types. The conversions are necessary because:
//! - RPC API types come from the `starknet` crate (starknet-rs)
//! - Blockifier types come from the `sequencer` crate
//! - Both represent the same Starknet concepts but with different type structures
//!
//! ## Design Principles
//!
//! 1. **From/Into Pattern**: Uses Rust's standard conversion traits where possible
//! 2. **TryFrom/TryInto Pattern**: For fallible conversions
//! 3. **Async When Needed**: Only for conversions requiring RPC calls
//! 4. **Error Propagation**: Comprehensive error handling with context
//! 5. **Zero-Copy**: Avoids unnecessary cloning where possible

use std::sync::Arc;

use async_trait::async_trait;
use blockifier::transaction::account_transaction::AccountTransaction;
use cairo_lang_starknet_classes::contract_class::version_id_from_serialized_sierra_program;
use log::{debug, warn};
use starknet::core::types::{
    BlockId, DataAvailabilityMode, DeclareTransaction, DeclareTransactionV0, DeclareTransactionV1,
    DeclareTransactionV2, DeclareTransactionV3, DeployAccountTransaction, DeployAccountTransactionV1,
    DeployAccountTransactionV3, Felt, InvokeTransaction, InvokeTransactionV1, InvokeTransactionV3,
    L1HandlerTransaction, ResourceBoundsMapping, Transaction, TransactionTrace, TransactionTraceWithHash,
};
use starknet::providers::Provider;
use starknet_api::block::{GasPrice, GasPrices};
use starknet_api::contract_class::{ClassInfo, SierraVersion};
use starknet_api::core::{felt_to_u128, ChainId, PatriciaKey};
use starknet_api::execution_resources::GasAmount;
use starknet_api::transaction::fields::{AllResourceBounds, Fee, ResourceBounds, ValidResourceBounds};
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use thiserror::Error;

use crate::error::ToBlockifierError;
use rpc_client::RpcClient;

// ================================================================================================
// Error Types
// ================================================================================================

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("RPC error: {0}")]
    RpcError(#[from] starknet::providers::ProviderError),
    #[error("Blockifier error: {0}")]
    BlockifierError(#[from] ToBlockifierError),
    #[error("Starknet API error: {0}")]
    StarknetApiError(#[from] starknet_api::StarknetApiError),
    #[error("Unsupported transaction type: {transaction_type}")]
    UnsupportedTransaction { transaction_type: String },
    #[error("Class compilation failed: {reason}")]
    ClassCompilationFailed { reason: String },
    #[error("Field conversion failed: {field}, reason: {reason}")]
    FieldConversionFailed { field: String, reason: String },
}

// ================================================================================================
// Type Definitions
// ================================================================================================

/// Result of transaction conversion containing both API representations.
#[derive(Debug, Clone)]
pub struct TransactionConversionResult {
    /// Starknet API executable transaction
    pub starknet_api_tx: starknet_api::executable_transaction::Transaction,
    /// Blockifier transaction for execution
    pub blockifier_tx: blockifier::transaction::transaction_execution::Transaction,
}

/// Context required for transaction conversions.
#[derive(Clone)]
pub struct ConversionContext<'a> {
    /// Chain ID for the network
    pub chain_id: &'a ChainId,
    /// Block number being processed
    pub block_number: u64,
    /// RPC client for fetching additional data
    pub rpc_client: &'a RpcClient,
    /// Gas prices for the block
    pub gas_prices: &'a GasPrices,
}

impl<'a> ConversionContext<'a> {
    /// Creates a new conversion context with all required parameters.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The chain ID for the network
    /// * `block_number` - The block number being processed
    /// * `rpc_client` - The RPC client for fetching additional data
    /// * `gas_prices` - The gas prices for the block
    ///
    /// # Example
    ///
    /// ```rust
    /// let context = ConversionContext::new(
    ///     &chain_id,
    ///     block_number,
    ///     &rpc_client,
    ///     &gas_prices,
    /// );
    /// ```
    pub fn new(chain_id: &'a ChainId, block_number: u64, rpc_client: &'a RpcClient, gas_prices: &'a GasPrices) -> Self {
        Self { chain_id, block_number, rpc_client, gas_prices }
    }
}

// ================================================================================================
// Core Conversion Traits
// ================================================================================================

/// Trait for fallible conversion to Blockifier types.
///
/// This trait should be used for simple, synchronous conversions that don't require
/// external data fetching.
pub trait TryIntoBlockifierSync<T> {
    type Error;

    fn try_into_blockifier(self) -> Result<T, Self::Error>;
}

/// Trait for async conversions that require external context.
///
/// This trait should be used for conversions that need to fetch additional data
/// from RPC or perform complex operations.
#[async_trait]
pub trait TryIntoBlockifierAsync<T> {
    type Error;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        trace: &TransactionTraceWithHash,
    ) -> Result<T, Self::Error>;
}

// ================================================================================================
// Helper Functions
// ================================================================================================

/// Fetches class information from the RPC client.
///
/// This function retrieves contract class data and converts it to the format
/// expected by Blockifier, handling both Sierra and Legacy classes.
async fn fetch_class_info(
    class_hash: Felt,
    rpc_client: &RpcClient,
    block_number: u64,
) -> Result<ClassInfo, ConversionError> {
    debug!("Fetching class info for hash: {:?} at block: {}", class_hash, block_number);

    let contract_class = rpc_client.starknet_rpc().get_class(BlockId::Number(block_number), class_hash).await?;

    let (blockifier_contract_class, program_length, abi_length, version) = match contract_class {
        starknet::core::types::ContractClass::Sierra(sierra) => {
            debug!("Processing Sierra class");
            let generic_sierra = GenericSierraContractClass::from(sierra.clone());
            let flattened_sierra = generic_sierra.clone().to_starknet_core_contract_class().map_err(|e| {
                ConversionError::ClassCompilationFailed { reason: format!("Failed to flatten Sierra class: {:?}", e) }
            })?;

            let generic_cairo_lang_class = generic_sierra.get_cairo_lang_contract_class().map_err(|e| {
                ConversionError::ClassCompilationFailed { reason: format!("Failed to get Cairo lang class: {:?}", e) }
            })?;

            let (version_id, _) = version_id_from_serialized_sierra_program(&generic_cairo_lang_class.sierra_program)
                .map_err(|e| ConversionError::ClassCompilationFailed {
                reason: format!("Failed to extract version from Sierra program: {:?}", e),
            })?;

            let sierra_version =
                SierraVersion::new(version_id.major as u64, version_id.minor as u64, version_id.patch as u64);

            let compiled_class = generic_sierra.compile().map_err(|e| ConversionError::ClassCompilationFailed {
                reason: format!("Sierra compilation failed: {:?}", e),
            })?;

            let blockifier_class = compiled_class.to_blockifier_contract_class(sierra_version).map_err(|e| {
                ConversionError::ClassCompilationFailed {
                    reason: format!("Failed to convert to blockifier class: {:?}", e),
                }
            })?;

            let contract_class = starknet_api::contract_class::ContractClass::V1(blockifier_class);
            let extracted_version = SierraVersion::extract_from_program(&sierra.sierra_program).map_err(|e| {
                ConversionError::ClassCompilationFailed { reason: format!("Failed to extract Sierra version: {:?}", e) }
            })?;

            (contract_class, flattened_sierra.sierra_program.len(), flattened_sierra.abi.len(), extracted_version)
        }

        starknet::core::types::ContractClass::Legacy(legacy) => {
            debug!("Processing Legacy class");
            let generic_legacy = GenericDeprecatedCompiledClass::try_from(legacy).map_err(|e| {
                ConversionError::ClassCompilationFailed { reason: format!("Failed to convert legacy class: {:?}", e) }
            })?;

            let blockifier_class =
                generic_legacy.to_blockifier_contract_class().map_err(|e| ConversionError::ClassCompilationFailed {
                    reason: format!("Failed to convert legacy to blockifier: {:?}", e),
                })?;

            let contract_class = starknet_api::contract_class::ContractClass::V0(blockifier_class);

            (contract_class, 0, 0, SierraVersion::default())
        }
    };

    ClassInfo::new(&blockifier_contract_class, program_length, abi_length, version)
        .map_err(|e| ConversionError::ClassCompilationFailed { reason: format!("Failed to create ClassInfo: {:?}", e) })
}

/// Creates a transaction conversion result for account transactions.
fn create_account_transaction_result(
    starknet_api_tx: starknet_api::executable_transaction::Transaction,
    account_tx: starknet_api::executable_transaction::AccountTransaction,
) -> TransactionConversionResult {
    let mut txn = AccountTransaction::new_for_sequencing(account_tx);
    txn.execution_flags.charge_fee = false;

    TransactionConversionResult {
        starknet_api_tx,
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::Account(txn),
    }
}

/// Creates a transaction conversion result for L1 handler transactions.
fn create_l1_handler_transaction_result(
    l1_handler_tx: starknet_api::executable_transaction::L1HandlerTransaction,
) -> TransactionConversionResult {
    let starknet_api_tx = starknet_api::executable_transaction::Transaction::L1Handler(l1_handler_tx.clone());

    TransactionConversionResult {
        starknet_api_tx: starknet_api_tx.clone(),
        blockifier_tx: blockifier::transaction::transaction_execution::Transaction::new_for_sequencing(starknet_api_tx),
    }
}

/// Converts a Felt to u128 with proper error context.
#[allow(clippy::result_large_err)]
fn felt_to_u128_safe(felt: &Felt, field_name: &str) -> Result<u128, ConversionError> {
    felt_to_u128(felt).map_err(|e| ConversionError::FieldConversionFailed {
        field: field_name.to_string(),
        reason: format!("Felt to u128 conversion failed: {:?}", e),
    })
}

/// Converts a Felt to PatriciaKey with proper error context.
#[allow(clippy::result_large_err)]
fn felt_to_patricia_key(felt: Felt, field_name: &str) -> Result<PatriciaKey, ConversionError> {
    PatriciaKey::try_from(felt).map_err(|e| ConversionError::FieldConversionFailed {
        field: field_name.to_string(),
        reason: format!("Patricia key conversion failed: {:?}", e),
    })
}

// ================================================================================================
// Simple Type Conversions
// ================================================================================================

impl TryIntoBlockifierSync<ValidResourceBounds> for ResourceBoundsMapping {
    type Error = ConversionError;

    fn try_into_blockifier(self) -> Result<ValidResourceBounds, Self::Error> {
        Ok(ValidResourceBounds::AllResources(AllResourceBounds {
            l1_gas: ResourceBounds {
                max_amount: GasAmount(self.l1_gas.max_amount),
                max_price_per_unit: GasPrice(self.l1_gas.max_price_per_unit),
            },
            l1_data_gas: ResourceBounds {
                max_amount: GasAmount(self.l1_data_gas.max_amount),
                max_price_per_unit: GasPrice(self.l1_data_gas.max_price_per_unit),
            },
            l2_gas: ResourceBounds {
                max_amount: GasAmount(self.l2_gas.max_amount),
                max_price_per_unit: GasPrice(self.l2_gas.max_price_per_unit),
            },
        }))
    }
}

impl TryIntoBlockifierSync<starknet_api::data_availability::DataAvailabilityMode> for DataAvailabilityMode {
    type Error = ConversionError;

    fn try_into_blockifier(self) -> Result<starknet_api::data_availability::DataAvailabilityMode, Self::Error> {
        Ok(match self {
            DataAvailabilityMode::L1 => starknet_api::data_availability::DataAvailabilityMode::L1,
            DataAvailabilityMode::L2 => starknet_api::data_availability::DataAvailabilityMode::L2,
        })
    }
}

// ================================================================================================
// Transaction Conversions
// ================================================================================================

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for InvokeTransactionV1 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting InvokeTransactionV1");

        let api_tx = starknet_api::transaction::InvokeTransaction::V1(starknet_api::transaction::InvokeTransactionV1 {
            max_fee: Fee(felt_to_u128_safe(&self.max_fee, "max_fee")?),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
            nonce: starknet_api::core::Nonce(self.nonce),
            sender_address: starknet_api::core::ContractAddress(felt_to_patricia_key(
                self.sender_address,
                "sender_address",
            )?),
            calldata: starknet_api::transaction::fields::Calldata(Arc::new(self.calldata)),
        });

        let invoke_tx = starknet_api::executable_transaction::InvokeTransaction::create(api_tx, ctx.chain_id)?;
        let account_tx = starknet_api::executable_transaction::AccountTransaction::Invoke(invoke_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for InvokeTransactionV3 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting InvokeTransactionV3");

        let api_tx = starknet_api::transaction::InvokeTransaction::V3(starknet_api::transaction::InvokeTransactionV3 {
            resource_bounds: self.resource_bounds.try_into_blockifier()?,
            tip: starknet_api::transaction::fields::Tip(self.tip),
            signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
            nonce: starknet_api::core::Nonce(self.nonce),
            sender_address: starknet_api::core::ContractAddress(felt_to_patricia_key(
                self.sender_address,
                "sender_address",
            )?),
            calldata: starknet_api::transaction::fields::Calldata(Arc::new(self.calldata)),
            nonce_data_availability_mode: self.nonce_data_availability_mode.try_into_blockifier()?,
            fee_data_availability_mode: self.fee_data_availability_mode.try_into_blockifier()?,
            paymaster_data: starknet_api::transaction::fields::PaymasterData(self.paymaster_data),
            account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
                self.account_deployment_data,
            ),
        });

        let invoke_tx = starknet_api::executable_transaction::InvokeTransaction::create(api_tx, ctx.chain_id)?;
        let account_tx = starknet_api::executable_transaction::AccountTransaction::Invoke(invoke_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for DeclareTransactionV0 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting DeclareTransactionV0");

        let api_tx =
            starknet_api::transaction::DeclareTransaction::V0(starknet_api::transaction::DeclareTransactionV0V1 {
                max_fee: Fee(felt_to_u128_safe(&self.max_fee, "max_fee")?),
                signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
                nonce: starknet_api::core::Nonce(Felt::ZERO), // V0 doesn't have nonce
                class_hash: starknet_api::core::ClassHash(self.class_hash),
                sender_address: starknet_api::core::ContractAddress(felt_to_patricia_key(
                    self.sender_address,
                    "sender_address",
                )?),
            });

        let class_info = fetch_class_info(self.class_hash, ctx.rpc_client, ctx.block_number).await?;
        let declare_tx =
            starknet_api::executable_transaction::DeclareTransaction::create(api_tx, class_info, ctx.chain_id)?;
        let account_tx = starknet_api::executable_transaction::AccountTransaction::Declare(declare_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for DeclareTransactionV1 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting DeclareTransactionV1");

        let api_tx =
            starknet_api::transaction::DeclareTransaction::V1(starknet_api::transaction::DeclareTransactionV0V1 {
                max_fee: Fee(felt_to_u128_safe(&self.max_fee, "max_fee")?),
                signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
                nonce: starknet_api::core::Nonce(self.nonce),
                class_hash: starknet_api::core::ClassHash(self.class_hash),
                sender_address: starknet_api::core::ContractAddress(felt_to_patricia_key(
                    self.sender_address,
                    "sender_address",
                )?),
            });

        let class_info = fetch_class_info(self.class_hash, ctx.rpc_client, ctx.block_number).await?;
        let declare_tx =
            starknet_api::executable_transaction::DeclareTransaction::create(api_tx, class_info, ctx.chain_id)?;
        let account_tx = starknet_api::executable_transaction::AccountTransaction::Declare(declare_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for DeclareTransactionV2 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting DeclareTransactionV2");

        let api_tx =
            starknet_api::transaction::DeclareTransaction::V2(starknet_api::transaction::DeclareTransactionV2 {
                max_fee: Fee(felt_to_u128_safe(&self.max_fee, "max_fee")?),
                signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
                nonce: starknet_api::core::Nonce(self.nonce),
                class_hash: starknet_api::core::ClassHash(self.class_hash),
                compiled_class_hash: starknet_api::core::CompiledClassHash(self.compiled_class_hash),
                sender_address: starknet_api::core::ContractAddress(felt_to_patricia_key(
                    self.sender_address,
                    "sender_address",
                )?),
            });

        let class_info = fetch_class_info(self.class_hash, ctx.rpc_client, ctx.block_number).await?;
        let declare_tx =
            starknet_api::executable_transaction::DeclareTransaction::create(api_tx, class_info, ctx.chain_id)?;
        let account_tx = starknet_api::executable_transaction::AccountTransaction::Declare(declare_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for DeclareTransactionV3 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting DeclareTransactionV3");

        let api_tx =
            starknet_api::transaction::DeclareTransaction::V3(starknet_api::transaction::DeclareTransactionV3 {
                resource_bounds: self.resource_bounds.try_into_blockifier()?,
                tip: starknet_api::transaction::fields::Tip(self.tip),
                signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
                nonce: starknet_api::core::Nonce(self.nonce),
                class_hash: starknet_api::core::ClassHash(self.class_hash),
                compiled_class_hash: starknet_api::core::CompiledClassHash(self.compiled_class_hash),
                sender_address: starknet_api::core::ContractAddress(felt_to_patricia_key(
                    self.sender_address,
                    "sender_address",
                )?),
                nonce_data_availability_mode: self.nonce_data_availability_mode.try_into_blockifier()?,
                fee_data_availability_mode: self.fee_data_availability_mode.try_into_blockifier()?,
                paymaster_data: starknet_api::transaction::fields::PaymasterData(self.paymaster_data),
                account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
                    self.account_deployment_data,
                ),
            });

        let class_info = fetch_class_info(self.class_hash, ctx.rpc_client, ctx.block_number).await?;
        let declare_tx =
            starknet_api::executable_transaction::DeclareTransaction::create(api_tx, class_info, ctx.chain_id)?;
        let account_tx = starknet_api::executable_transaction::AccountTransaction::Declare(declare_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for DeployAccountTransactionV1 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting DeployAccountTransactionV1");

        let api_tx = starknet_api::transaction::DeployAccountTransaction::V1(
            starknet_api::transaction::DeployAccountTransactionV1 {
                max_fee: Fee(felt_to_u128_safe(&self.max_fee, "max_fee")?),
                signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
                nonce: starknet_api::core::Nonce(self.nonce),
                class_hash: starknet_api::core::ClassHash(self.class_hash),
                constructor_calldata: starknet_api::transaction::fields::Calldata(Arc::new(self.constructor_calldata)),
                contract_address_salt: starknet_api::transaction::fields::ContractAddressSalt(
                    self.contract_address_salt,
                ),
            },
        );

        let deploy_account_tx =
            starknet_api::executable_transaction::DeployAccountTransaction::create(api_tx, ctx.chain_id)?;
        let account_tx =
            starknet_api::executable_transaction::AccountTransaction::DeployAccount(deploy_account_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for DeployAccountTransactionV3 {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        _trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting DeployAccountTransactionV3");

        let api_tx = starknet_api::transaction::DeployAccountTransaction::V3(
            starknet_api::transaction::DeployAccountTransactionV3 {
                resource_bounds: self.resource_bounds.try_into_blockifier()?,
                tip: starknet_api::transaction::fields::Tip(self.tip),
                signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(self.signature)),
                nonce: starknet_api::core::Nonce(self.nonce),
                class_hash: starknet_api::core::ClassHash(self.class_hash),
                contract_address_salt: starknet_api::transaction::fields::ContractAddressSalt(
                    self.contract_address_salt,
                ),
                constructor_calldata: starknet_api::transaction::fields::Calldata(Arc::new(self.constructor_calldata)),
                nonce_data_availability_mode: self.nonce_data_availability_mode.try_into_blockifier()?,
                fee_data_availability_mode: self.fee_data_availability_mode.try_into_blockifier()?,
                paymaster_data: starknet_api::transaction::fields::PaymasterData(self.paymaster_data),
            },
        );

        let deploy_account_tx =
            starknet_api::executable_transaction::DeployAccountTransaction::create(api_tx, ctx.chain_id)?;
        let account_tx =
            starknet_api::executable_transaction::AccountTransaction::DeployAccount(deploy_account_tx.clone());
        let starknet_api_tx = starknet_api::executable_transaction::Transaction::Account(account_tx.clone());

        Ok(create_account_transaction_result(starknet_api_tx, account_tx))
    }
}

/// Calculates fee for L1 handler transactions based on execution resources.
fn calculate_l1_handler_fee(trace: &TransactionTraceWithHash, gas_prices: &GasPrices) -> Fee {
    let (l1_gas, l1_data_gas) = match &trace.trace_root {
        TransactionTrace::L1Handler(l1_handler) => {
            (l1_handler.execution_resources.l1_gas, l1_handler.execution_resources.l1_data_gas)
        }
        _ => {
            warn!("Expected L1Handler trace but got different type");
            (0, 0)
        }
    };

    let fee_amount = match (l1_gas, l1_data_gas) {
        // When both values are zero, use a default fee to prevent blockifier execution failure
        // This is a known issue: blockifier requires non-zero fee for L1 handlers
        // See: https://github.com/starkware-libs/sequencer/blob/main/crates/blockifier/src/transaction/transaction_execution.rs
        (0, 0) => {
            debug!("Both L1 gas values are zero, using default fee");
            1_000_000_000_000u128
        }
        (0, l1_data_gas) => gas_prices.eth_gas_prices.l1_data_gas_price.get().0 * l1_data_gas as u128,
        (l1_gas, 0) => gas_prices.strk_gas_prices.l1_gas_price.get().0 * l1_gas as u128,
        (l1_gas, l1_data_gas) => {
            gas_prices.strk_gas_prices.l1_gas_price.get().0 * l1_gas as u128
                + gas_prices.eth_gas_prices.l1_data_gas_price.get().0 * l1_data_gas as u128
        }
    };

    Fee(fee_amount)
}

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for L1HandlerTransaction {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        debug!("Converting L1HandlerTransaction");

        let api_tx = starknet_api::transaction::L1HandlerTransaction {
            version: starknet_api::transaction::TransactionVersion(self.version),
            nonce: starknet_api::core::Nonce(Felt::from(self.nonce)),
            contract_address: starknet_api::core::ContractAddress(felt_to_patricia_key(
                self.contract_address,
                "contract_address",
            )?),
            entry_point_selector: starknet_api::core::EntryPointSelector(self.entry_point_selector),
            calldata: starknet_api::transaction::fields::Calldata(Arc::new(self.calldata)),
        };

        let paid_fee_on_l1 = calculate_l1_handler_fee(trace, ctx.gas_prices);
        let l1_handler_tx =
            starknet_api::executable_transaction::L1HandlerTransaction::create(api_tx, ctx.chain_id, paid_fee_on_l1)?;

        Ok(create_l1_handler_transaction_result(l1_handler_tx))
    }
}

// ================================================================================================
// High-Level Transaction Conversion
// ================================================================================================

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for Transaction {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        trace: &TransactionTraceWithHash,
    ) -> Result<TransactionConversionResult, Self::Error> {
        match self {
            Transaction::Invoke(tx) => match tx {
                InvokeTransaction::V0(_) => {
                    Err(ConversionError::UnsupportedTransaction { transaction_type: "InvokeV0".to_string() })
                }
                InvokeTransaction::V1(tx) => tx.try_into_blockifier_async(ctx, trace).await,
                InvokeTransaction::V3(tx) => tx.try_into_blockifier_async(ctx, trace).await,
            },
            Transaction::Declare(tx) => match tx {
                DeclareTransaction::V0(tx) => tx.try_into_blockifier_async(ctx, trace).await,
                DeclareTransaction::V1(tx) => tx.try_into_blockifier_async(ctx, trace).await,
                DeclareTransaction::V2(tx) => tx.try_into_blockifier_async(ctx, trace).await,
                DeclareTransaction::V3(tx) => tx.try_into_blockifier_async(ctx, trace).await,
            },
            Transaction::L1Handler(tx) => tx.try_into_blockifier_async(ctx, trace).await,
            Transaction::DeployAccount(tx) => match tx {
                DeployAccountTransaction::V1(tx) => tx.try_into_blockifier_async(ctx, trace).await,
                DeployAccountTransaction::V3(tx) => tx.try_into_blockifier_async(ctx, trace).await,
            },
            Transaction::Deploy(_) => {
                Err(ConversionError::UnsupportedTransaction { transaction_type: "Deploy".to_string() })
            }
        }
    }
}
