use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use crate::starknet::business_logic::fact_state::contract_class_objects::{
    CompiledClassFact, ContractClassFact, DeprecatedCompiledClassFact,
};
use crate::storage::storage::{Fact, FactFetchingContext, HashFunctionType, Storage, StorageError};

pub async fn write_class_facts<S, H>(
    ffc: &mut FactFetchingContext<S, H>,
    contract_class: ContractClass,
    compiled_class: CasmContractClass,
) -> Result<(Vec<u8>, Vec<u8>), StorageError>
where
    S: Storage,
    H: HashFunctionType,
{
    let contract_class_fact = ContractClassFact { contract_class };
    let compiled_class_fact = CompiledClassFact { compiled_class };

    let contract_class_hash = contract_class_fact.set_fact(ffc).await?;
    let compiled_class_hash = compiled_class_fact.set_fact(ffc).await?;

    Ok((contract_class_hash, compiled_class_hash))
}

pub async fn write_deprecated_compiled_class_fact<S, H>(
    deprecated_compiled_class: DeprecatedCompiledClass,
    ffc: &mut FactFetchingContext<S, H>,
) -> Result<Vec<u8>, StorageError>
where
    S: Storage,
    H: HashFunctionType,
{
    let deprecated_compiled_class_fact = DeprecatedCompiledClassFact { contract_definition: deprecated_compiled_class };
    deprecated_compiled_class_fact.set_fact(ffc).await
}
