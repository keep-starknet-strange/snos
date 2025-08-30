use once_cell::sync::OnceCell;
use std::sync::Arc;

use cairo_vm::Felt252;
use serde::ser::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use starknet_core::types::{EntryPointsByType, FlattenedSierraClass};
use starknet_types_core::felt::Felt;

use crate::casm_contract_class::{CairoLangCasmClass, GenericCasmContractClass};
use crate::error::ContractClassError;
use crate::hash::GenericClassHash;

pub type CairoLangSierraContractClass = cairo_lang_starknet_classes::contract_class::ContractClass;
pub type StarknetCoreSierraContractClass = starknet_core::types::FlattenedSierraClass;

/// A generic Sierra contract class that supports conversion to/from the most commonly used
/// contract class types in Starknet and provides utility methods.
///
/// Operations are implemented as lazily as possible, i.e. we only convert
/// between different types if strictly necessary.
/// Fields are boxed in an Arc for cheap cloning.
#[derive(Debug, Clone)]
pub struct GenericSierraContractClass {
    cairo_lang_contract_class: OnceCell<Arc<CairoLangSierraContractClass>>,
    starknet_core_contract_class: OnceCell<Arc<StarknetCoreSierraContractClass>>,
    serialized_class: OnceCell<Vec<u8>>,
    class_hash: OnceCell<GenericClassHash>,
}

impl GenericSierraContractClass {
    pub fn from_bytes(serialized_class: Vec<u8>) -> Self {
        Self {
            cairo_lang_contract_class: Default::default(),
            starknet_core_contract_class: Default::default(),
            serialized_class: OnceCell::from(serialized_class),
            class_hash: OnceCell::new(),
        }
    }

    fn build_cairo_lang_class(&self) -> Result<CairoLangSierraContractClass, ContractClassError> {
        self.get_serialized_contract_class().and_then(|res| {
            let contract_class = serde_json::from_slice(res)?;
            Ok(contract_class)
        })
    }

    pub fn get_serialized_contract_class(&self) -> Result<&Vec<u8>, ContractClassError> {
        self.serialized_class.get_or_try_init(|| serde_json::to_vec(self)).map_err(Into::into)
    }

    fn build_starknet_core_class(&self) -> Result<StarknetCoreSierraContractClass, ContractClassError> {
        let serialized_class = self.get_serialized_contract_class()?;
        let sierra_class: starknet_core::types::contract::SierraClass =
            serde_json::from_slice(serialized_class).map_err(ContractClassError::SerdeError)?;

        sierra_class.flatten().map_err(|e| ContractClassError::SerdeError(serde_json::Error::custom(e)))
    }
    pub fn get_cairo_lang_contract_class(&self) -> Result<&CairoLangSierraContractClass, ContractClassError> {
        self.cairo_lang_contract_class
            .get_or_try_init(|| self.build_cairo_lang_class().map(Arc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn get_starknet_core_contract_class(&self) -> Result<&StarknetCoreSierraContractClass, ContractClassError> {
        self.starknet_core_contract_class
            .get_or_try_init(|| self.build_starknet_core_class().map(Arc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn to_cairo_lang_contract_class(self) -> Result<CairoLangSierraContractClass, ContractClassError> {
        let cairo_lang_class = self.get_cairo_lang_contract_class()?;
        Ok(cairo_lang_class.clone())
    }

    pub fn to_starknet_core_contract_class(self) -> Result<StarknetCoreSierraContractClass, ContractClassError> {
        let blockifier_class = self.get_starknet_core_contract_class()?;
        Ok(blockifier_class.clone())
    }

    fn compute_class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        let starknet_core_contract_class = self.get_starknet_core_contract_class()?;
        let class_hash = starknet_core_contract_class.class_hash();
        Ok(GenericClassHash::new(class_hash.into()))
    }

    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        self.class_hash.get_or_try_init(|| self.compute_class_hash()).copied()
    }

    pub fn compile(&self) -> Result<GenericCasmContractClass, ContractClassError> {
        let cairo_lang_class = self.get_cairo_lang_contract_class()?.clone();
        // Values taken from the defaults of `starknet-sierra-compile`, see here:
        // https://github.com/starkware-libs/cairo/blob/main/crates/bin/starknet-sierra-compile/src/main.rs
        let add_pythonic_hints = false;
        let max_bytecode_size = 180000;
        let casm_contract_class =
            CairoLangCasmClass::from_contract_class(cairo_lang_class, add_pythonic_hints, max_bytecode_size)?;

        Ok(GenericCasmContractClass::from(casm_contract_class))
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlattenedSierraClassWithAbi {
    /// The list of sierra instructions of which the program consists
    pub sierra_program: Vec<Felt>,
    /// The version of the contract class object. Currently, the Starknet os supports version 0.1.0
    pub contract_class_version: String,
    /// Entry points by type
    pub entry_points_by_type: EntryPointsByType,
    /// ABI, deserialized
    pub abi: Option<cairo_lang_starknet_classes::abi::Contract>,
}

#[derive(Debug, Serialize)]
struct ContractClassForPathfinderCompat {
    pub sierra_program: Vec<Felt252>,
    pub contract_class_version: String,
    pub entry_points_by_type: cairo_lang_starknet_classes::contract_class::ContractEntryPoints,
    pub abi: String,
}

impl From<cairo_lang_starknet_classes::contract_class::ContractClass> for ContractClassForPathfinderCompat {
    fn from(value: cairo_lang_starknet_classes::contract_class::ContractClass) -> Self {
        Self {
            sierra_program: value.sierra_program.into_iter().map(|x| Felt252::from(x.value)).collect(),
            contract_class_version: value.contract_class_version,
            entry_points_by_type: value.entry_points_by_type,
            abi: value.abi.map(|abi| abi.json()).unwrap_or_default(),
        }
    }
}

impl TryFrom<&FlattenedSierraClass> for FlattenedSierraClassWithAbi {
    type Error = serde_json::error::Error;

    fn try_from(sierra_class: &FlattenedSierraClass) -> Result<Self, Self::Error> {
        let abi: Option<cairo_lang_starknet_classes::abi::Contract> =
            serde_json::from_str(&sierra_class.abi).unwrap_or_default();

        Ok(Self {
            sierra_program: sierra_class.sierra_program.clone(),
            contract_class_version: sierra_class.contract_class_version.clone(),
            entry_points_by_type: sierra_class.entry_points_by_type.clone(),
            abi,
        })
    }
}

impl Serialize for GenericSierraContractClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(cairo_lang_class) = self.cairo_lang_contract_class.get() {
            cairo_lang_class.serialize(serializer)
        } else if let Some(starknet_core_class) = self.starknet_core_contract_class.get() {
            let class_with_abi = FlattenedSierraClassWithAbi::try_from(starknet_core_class.as_ref())
                .map_err(|e| S::Error::custom(e.to_string()))?;
            class_with_abi.serialize(serializer)
        } else {
            Err(S::Error::custom("No possible serialization"))
        }
    }
}

impl<'de> Deserialize<'de> for GenericSierraContractClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cairo_lang_class = CairoLangSierraContractClass::deserialize(deserializer)?;
        Ok(Self::from(cairo_lang_class))
    }
}

impl From<CairoLangSierraContractClass> for GenericSierraContractClass {
    fn from(cairo_lang_class: CairoLangSierraContractClass) -> Self {
        Self {
            cairo_lang_contract_class: OnceCell::from(Arc::new(cairo_lang_class)),
            starknet_core_contract_class: Default::default(),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl From<StarknetCoreSierraContractClass> for GenericSierraContractClass {
    fn from(starknet_core_class: StarknetCoreSierraContractClass) -> Self {
        Self {
            cairo_lang_contract_class: Default::default(),
            starknet_core_contract_class: OnceCell::from(Arc::new(starknet_core_class)),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl TryFrom<GenericSierraContractClass> for StarknetCoreSierraContractClass {
    type Error = ContractClassError;

    fn try_from(contract_class: GenericSierraContractClass) -> Result<Self, Self::Error> {
        contract_class.to_starknet_core_contract_class()
    }
}
