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

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use blockifier::transaction::account_transaction::AccountTransaction;
use cairo_lang_starknet_classes::contract_class::version_id_from_serialized_sierra_program;
use log::debug;
use starknet::core::types::{
    BlockId, DataAvailabilityMode, DeclareTransaction, DeclareTransactionV0, DeclareTransactionV1,
    DeclareTransactionV2, DeclareTransactionV3, DeployAccountTransaction, DeployAccountTransactionV1,
    DeployAccountTransactionV3, Felt, InvokeTransaction, InvokeTransactionV1, InvokeTransactionV3,
    L1DataAvailabilityMode as CoreL1DataAvailabilityMode, L1HandlerTransaction, ResourceBoundsMapping, Transaction,
    TransactionReceipt,
};
use starknet::providers::Provider;
use starknet_api::block::GasPrice;
use starknet_api::contract_class::{ClassInfo, SierraVersion};
use starknet_api::core::{felt_to_u128, ChainId, PatriciaKey};
use starknet_api::execution_resources::GasAmount;
use starknet_api::transaction::fields::{AllResourceBounds, Fee, ResourceBounds, ValidResourceBounds};
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use thiserror::Error;

use crate::constants::DEFAULT_PAID_FEE_ON_L1;
use crate::error::ToBlockifierError;
use rpc_client::utils::execute_with_retry;
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
    #[error("Missing transaction receipt for {tx_hash:#x}")]
    MissingTransactionReceipt { tx_hash: Felt },
    #[error("Missing proof facts in RPC response for transaction {tx_hash:#x}")]
    MissingProofFacts { tx_hash: Felt },
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
    /// Receipts for the current block keyed by transaction hash
    pub transaction_receipts: &'a HashMap<Felt, TransactionReceipt>,
}

impl<'a> ConversionContext<'a> {
    /// Creates a new conversion context with all required parameters.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The chain ID for the network
    /// * `block_number` - The block number being processed
    /// * `rpc_client` - The RPC client for fetching additional data
    /// * `transaction_receipts` - Receipts for the current block keyed by transaction hash
    /// # Example
    ///
    /// ```rust
    /// let context = ConversionContext::new(
    ///     &chain_id,
    ///     block_number,
    ///     &rpc_client,
    ///     &transaction_receipts,
    /// );
    /// ```
    pub fn new(
        chain_id: &'a ChainId,
        block_number: u64,
        rpc_client: &'a RpcClient,
        transaction_receipts: &'a HashMap<Felt, TransactionReceipt>,
    ) -> Self {
        Self { chain_id, block_number, rpc_client, transaction_receipts }
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

    async fn try_into_blockifier_async(self, ctx: &ConversionContext<'_>) -> Result<T, Self::Error>;
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

    let operation_name = format!("get_class(class_hash: {class_hash:?}, block_number: {block_number})");
    let contract_class = execute_with_retry(&operation_name, || {
        rpc_client.starknet_rpc().get_class(BlockId::Number(block_number), class_hash)
    })
    .await?;

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
    let mut charge_fee = true;
    if account_tx.version().0 == Felt::ZERO {
        charge_fee = false;
    } else {
        match account_tx.resource_bounds() {
            ValidResourceBounds::AllResources(all_resources) => {
                if all_resources.l2_gas.max_amount.0 == 0 {
                    charge_fee = false;
                }
            }
            ValidResourceBounds::L1Gas(l1_gas) => {
                if l1_gas.max_amount.0 == 0 {
                    charge_fee = false;
                }
            }
        }
    }
    let mut txn = AccountTransaction::new_for_sequencing(account_tx);
    txn.execution_flags.charge_fee = charge_fee;

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

fn extract_receipt_fee_amount(receipt: &TransactionReceipt) -> &Felt {
    match receipt {
        TransactionReceipt::Invoke(receipt) => &receipt.actual_fee.amount,
        TransactionReceipt::L1Handler(receipt) => &receipt.actual_fee.amount,
        TransactionReceipt::Declare(receipt) => &receipt.actual_fee.amount,
        TransactionReceipt::Deploy(receipt) => &receipt.actual_fee.amount,
        TransactionReceipt::DeployAccount(receipt) => &receipt.actual_fee.amount,
    }
}

pub(crate) fn transaction_receipt_hash(receipt: &TransactionReceipt) -> Felt {
    match receipt {
        TransactionReceipt::Invoke(receipt) => receipt.transaction_hash,
        TransactionReceipt::L1Handler(receipt) => receipt.transaction_hash,
        TransactionReceipt::Declare(receipt) => receipt.transaction_hash,
        TransactionReceipt::Deploy(receipt) => receipt.transaction_hash,
        TransactionReceipt::DeployAccount(receipt) => receipt.transaction_hash,
    }
}

#[expect(
    clippy::result_large_err,
    reason = "ConversionError is shared across transaction conversions and not worth boxing here"
)]
fn proof_facts_from_rpc(
    tx_hash: Felt,
    proof_facts: Option<Vec<Felt>>,
) -> Result<starknet_api::transaction::fields::ProofFacts, ConversionError> {
    proof_facts.ok_or(ConversionError::MissingProofFacts { tx_hash }).map(Into::into)
}

#[allow(clippy::result_large_err)]
fn fetch_paid_fee_on_l1(
    transaction_receipts: &HashMap<Felt, TransactionReceipt>,
    tx_hash: Felt,
) -> Result<Fee, ConversionError> {
    let receipt = transaction_receipts.get(&tx_hash).ok_or(ConversionError::MissingTransactionReceipt { tx_hash })?;
    let fee_amount = felt_to_u128_safe(extract_receipt_fee_amount(receipt), "actual_fee")?;

    Ok(Fee(if fee_amount == 0 { DEFAULT_PAID_FEE_ON_L1 } else { fee_amount }))
}

pub(crate) fn convert_l1_da_mode(
    mode: CoreL1DataAvailabilityMode,
) -> starknet_api::data_availability::L1DataAvailabilityMode {
    match mode {
        CoreL1DataAvailabilityMode::Blob => starknet_api::data_availability::L1DataAvailabilityMode::Blob,
        CoreL1DataAvailabilityMode::Calldata => starknet_api::data_availability::L1DataAvailabilityMode::Calldata,
    }
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
            proof_facts: proof_facts_from_rpc(self.transaction_hash, self.proof_facts)?,
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

#[async_trait]
impl TryIntoBlockifierAsync<TransactionConversionResult> for L1HandlerTransaction {
    type Error = ConversionError;

    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
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

        let paid_fee_on_l1 = fetch_paid_fee_on_l1(ctx.transaction_receipts, self.transaction_hash)?;
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
    ) -> Result<TransactionConversionResult, Self::Error> {
        match self {
            Transaction::Invoke(tx) => match tx {
                InvokeTransaction::V0(_) => {
                    Err(ConversionError::UnsupportedTransaction { transaction_type: "InvokeV0".to_string() })
                }
                InvokeTransaction::V1(tx) => tx.try_into_blockifier_async(ctx).await,
                InvokeTransaction::V3(tx) => tx.try_into_blockifier_async(ctx).await,
            },
            Transaction::Declare(tx) => match tx {
                DeclareTransaction::V0(tx) => tx.try_into_blockifier_async(ctx).await,
                DeclareTransaction::V1(tx) => tx.try_into_blockifier_async(ctx).await,
                DeclareTransaction::V2(tx) => tx.try_into_blockifier_async(ctx).await,
                DeclareTransaction::V3(tx) => tx.try_into_blockifier_async(ctx).await,
            },
            Transaction::L1Handler(tx) => tx.try_into_blockifier_async(ctx).await,
            Transaction::DeployAccount(tx) => match tx {
                DeployAccountTransaction::V1(tx) => tx.try_into_blockifier_async(ctx).await,
                DeployAccountTransaction::V3(tx) => tx.try_into_blockifier_async(ctx).await,
            },
            Transaction::Deploy(_) => {
                Err(ConversionError::UnsupportedTransaction { transaction_type: "Deploy".to_string() })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet::core::types::{DataAvailabilityMode, ResourceBounds, ResourceBoundsMapping};

    #[tokio::test]
    async fn invoke_v3_conversion_preserves_proof_facts() {
        let chain_id = ChainId::Sepolia;
        let rpc_client = RpcClient::try_new("http://localhost:9545").expect("valid dummy rpc url");
        let transaction_receipts = HashMap::new();
        let ctx = ConversionContext::new(&chain_id, 9112643, &rpc_client, &transaction_receipts);
        let proof_facts = vec![
            Felt::from_hex_unchecked("0x50524f4f4630"),
            Felt::from_hex_unchecked("0x5649525455414c5f534e4f53"),
            Felt::from_hex_unchecked("0x3e98c2d7703b03a7edb73ed7f075f97f1dcbaa8f717cdf6e1a57bf058265473"),
        ];
        let tx_fields = InvokeTransactionV3 {
            transaction_hash: Felt::ZERO,
            sender_address: Felt::from_hex_unchecked(
                "0x041c9dbe8ab9b414fa0ec4d22b7a41d80a3911b77a2c9c819ce949faa5edb9f9",
            ),
            calldata: vec![Felt::ONE, Felt::TWO],
            signature: vec![Felt::from(3_u64)],
            nonce: Felt::from(7_u64),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds { max_amount: 1_000_000, max_price_per_unit: 1 },
                l2_gas: ResourceBounds { max_amount: 2_000_000, max_price_per_unit: 3 },
                l1_data_gas: ResourceBounds { max_amount: 4_000_000, max_price_per_unit: 5 },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            proof_facts: Some(proof_facts.clone()),
        };
        let expected_tx_hash = starknet_api::executable_transaction::InvokeTransaction::create(
            starknet_api::transaction::InvokeTransaction::V3(starknet_api::transaction::InvokeTransactionV3 {
                resource_bounds: tx_fields
                    .resource_bounds
                    .clone()
                    .try_into_blockifier()
                    .expect("valid resource bounds"),
                tip: starknet_api::transaction::fields::Tip(tx_fields.tip),
                signature: starknet_api::transaction::fields::TransactionSignature(Arc::new(
                    tx_fields.signature.clone(),
                )),
                nonce: starknet_api::core::Nonce(tx_fields.nonce),
                sender_address: starknet_api::core::ContractAddress(
                    felt_to_patricia_key(tx_fields.sender_address, "sender_address").expect("valid sender"),
                ),
                calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx_fields.calldata.clone())),
                nonce_data_availability_mode: tx_fields
                    .nonce_data_availability_mode
                    .try_into_blockifier()
                    .expect("valid nonce da mode"),
                fee_data_availability_mode: tx_fields
                    .fee_data_availability_mode
                    .try_into_blockifier()
                    .expect("valid fee da mode"),
                paymaster_data: starknet_api::transaction::fields::PaymasterData(tx_fields.paymaster_data.clone()),
                account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
                    tx_fields.account_deployment_data.clone(),
                ),
                proof_facts: proof_facts.clone().into(),
            }),
            &chain_id,
        )
        .expect("expected tx hash should compute")
        .tx_hash()
        .0;
        let tx = InvokeTransactionV3 { transaction_hash: expected_tx_hash, ..tx_fields };

        let result = tx.clone().try_into_blockifier_async(&ctx).await.expect("conversion should succeed");

        let converted_tx = match result.starknet_api_tx {
            starknet_api::executable_transaction::Transaction::Account(
                starknet_api::executable_transaction::AccountTransaction::Invoke(invoke_tx),
            ) => invoke_tx,
            other => panic!("expected invoke account transaction, got {other:?}"),
        };

        assert_eq!(converted_tx.proof_facts_length(), 3);
        assert_eq!(converted_tx.tx_hash().0, tx.transaction_hash);
    }

    #[tokio::test]
    async fn invoke_v3_conversion_rejects_missing_proof_facts() {
        let chain_id = ChainId::Sepolia;
        let rpc_client = RpcClient::try_new("http://localhost:9545").expect("valid dummy rpc url");
        let transaction_receipts = HashMap::new();
        let ctx = ConversionContext::new(&chain_id, 9112643, &rpc_client, &transaction_receipts);
        let tx = InvokeTransactionV3 {
            transaction_hash: Felt::from(123_u64),
            sender_address: Felt::from_hex_unchecked(
                "0x041c9dbe8ab9b414fa0ec4d22b7a41d80a3911b77a2c9c819ce949faa5edb9f9",
            ),
            calldata: vec![Felt::ONE],
            signature: vec![Felt::TWO],
            nonce: Felt::from(7_u64),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds { max_amount: 1_000_000, max_price_per_unit: 1 },
                l2_gas: ResourceBounds { max_amount: 2_000_000, max_price_per_unit: 3 },
                l1_data_gas: ResourceBounds { max_amount: 4_000_000, max_price_per_unit: 5 },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            proof_facts: None,
        };

        let error = tx.try_into_blockifier_async(&ctx).await.expect_err("missing proof facts must fail");

        assert!(matches!(error, ConversionError::MissingProofFacts { tx_hash } if tx_hash == Felt::from(123_u64)));
    }

    #[tokio::test]
    async fn invoke_v3_conversion_accepts_empty_proof_facts() {
        let chain_id = ChainId::Sepolia;
        let rpc_client = RpcClient::try_new("http://localhost:9545").expect("valid dummy rpc url");
        let transaction_receipts = HashMap::new();
        let ctx = ConversionContext::new(&chain_id, 9112643, &rpc_client, &transaction_receipts);
        let tx = InvokeTransactionV3 {
            transaction_hash: Felt::ZERO,
            sender_address: Felt::from_hex_unchecked(
                "0x041c9dbe8ab9b414fa0ec4d22b7a41d80a3911b77a2c9c819ce949faa5edb9f9",
            ),
            calldata: vec![Felt::ONE],
            signature: vec![Felt::TWO],
            nonce: Felt::from(7_u64),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds { max_amount: 1_000_000, max_price_per_unit: 1 },
                l2_gas: ResourceBounds { max_amount: 2_000_000, max_price_per_unit: 3 },
                l1_data_gas: ResourceBounds { max_amount: 4_000_000, max_price_per_unit: 5 },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            proof_facts: Some(vec![]),
        };

        let result = tx.try_into_blockifier_async(&ctx).await.expect("empty proof facts should be accepted");

        let converted_tx = match result.starknet_api_tx {
            starknet_api::executable_transaction::Transaction::Account(
                starknet_api::executable_transaction::AccountTransaction::Invoke(invoke_tx),
            ) => invoke_tx,
            other => panic!("expected invoke account transaction, got {other:?}"),
        };

        assert_eq!(converted_tx.proof_facts_length(), 0);
    }
}
