use cairo_lang_starknet_classes::contract_class::ContractClass;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::hash::Hash;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

use crate::starknet::business_logic::fact_state::contract_class_objects::{
    CompiledClassFact, ContractClassFact, DeprecatedCompiledClassFact,
};
use crate::storage::storage::{Fact, FactFetchingContext, HashFunctionType, Storage, StorageError};

pub async fn write_class_facts<S, H>(
    contract_class: GenericSierraContractClass,
    compiled_class: GenericCasmContractClass,
    ffc: &mut FactFetchingContext<S, H>,
) -> Result<(Hash, Hash), StorageError>
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
    deprecated_compiled_class: GenericDeprecatedCompiledClass,
    ffc: &mut FactFetchingContext<S, H>,
) -> Result<Hash, StorageError>
where
    S: Storage,
    H: HashFunctionType,
{
    let deprecated_compiled_class_fact = DeprecatedCompiledClassFact { contract_definition: deprecated_compiled_class };
    deprecated_compiled_class_fact.set_fact(ffc).await
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use rstest::{fixture, rstest};

    use super::*;
    use crate::crypto::pedersen::PedersenHash;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::DbObject;

    #[allow(clippy::upper_case_acronyms)]
    type FFC = FactFetchingContext<DictStorage, PedersenHash>;

    #[fixture]
    fn ffc() -> FFC {
        FFC::new(DictStorage::default())
    }

    #[rstest]
    #[tokio::test]
    async fn test_write_class_facts(mut ffc: FFC) {
        let sierra_bytes = include_bytes!(
            "../../../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo1/compiled/\
             test_contract.sierra"
        );
        let casm_bytes = include_bytes!(
            "../../../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo1/compiled/\
             test_contract.casm.json"
        );

        let contract_class: ContractClass = serde_json::from_slice(sierra_bytes).unwrap();
        let compiled_class = GenericCasmContractClass::from_bytes(casm_bytes.to_vec());

        let (class_hash, compiled_class_hash) =
            write_class_facts(contract_class, compiled_class, &mut ffc).await.unwrap();

        // Check that the data can be fetched from the storage afterward
        let storage = ffc.acquire_storage().await;
        let _stored_contract_class = ContractClassFact::get_or_fail(storage.deref(), &class_hash)
            .await
            .expect("Failed to retrieve contract class");
        let _stored_compiled_class = CompiledClassFact::get_or_fail(storage.deref(), &compiled_class_hash)
            .await
            .expect("Failed to retrieve compiled class");
    }

    #[rstest]
    #[tokio::test]
    async fn test_write_deprecated_compiled_class(mut ffc: FFC) {
        let program_bytes = include_bytes!(
            "../../../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo0/compiled/\
             test_contract_compiled.json"
        );

        let contract_class: GenericDeprecatedCompiledClass = serde_json::from_slice(program_bytes).unwrap();

        let compiled_class_hash = write_deprecated_compiled_class_fact(contract_class, &mut ffc).await.unwrap();

        // Check that the data can be fetched from the storage afterward
        let storage = ffc.acquire_storage().await;
        let _stored_compiled_class = DeprecatedCompiledClassFact::get_or_fail(storage.deref(), &compiled_class_hash)
            .await
            .expect("Failed to retrieve deprecated compiled class");
    }
}
