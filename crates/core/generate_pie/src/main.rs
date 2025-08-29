use cairo_vm::types::layout_name::LayoutName;
use starknet::core::types::Felt;
use starknet_api::core::{ChainId, ClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::CachedStateInput;
use starknet_os::io::os_input::{OsBlockInput, OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput};
use starknet_os::runner::run_os_stateless;
use std::collections::{BTreeMap, HashMap};

fn main() {
    let deprecated_compiled_classes = BTreeMap::new();
    let compiled_classes = BTreeMap::new();
    let block_input = OsBlockInput::default();
    let os_block_inputs = vec![block_input];
    let mut storage_changes: HashMap<ContractAddress, HashMap<StorageKey, Felt>> = HashMap::with_capacity(1);
    let mut inside_storage: HashMap<StorageKey, Felt> = HashMap::with_capacity(1);
    inside_storage.insert(StorageKey::try_from(Felt::ZERO).unwrap(), Felt::ZERO);
    storage_changes.insert(ContractAddress::try_from(Felt::TWO).unwrap(), inside_storage);

    let mut nonce_mapping: HashMap<ContractAddress, Nonce> = HashMap::with_capacity(1);
    nonce_mapping.insert(ContractAddress::try_from(Felt::TWO).unwrap(), Nonce(Felt::ZERO));

    let mut class_mapping: HashMap<ContractAddress, ClassHash> = HashMap::with_capacity(1);
    class_mapping.insert(ContractAddress::try_from(Felt::TWO).unwrap(), ClassHash(Felt::ZERO));
    let cached_state_inputs = vec![CachedStateInput {
        storage: storage_changes,
        address_to_class_hash: class_mapping,
        address_to_nonce: nonce_mapping,
        class_hash_to_compiled_class_hash: HashMap::default(),
    }];

    let os_hints = OsHints {
        os_hints_config: OsHintsConfig {
            debug_mode: true,
            full_output: true,
            use_kzg_da: false,
            chain_info: OsChainInfo {
                chain_id: ChainId::Sepolia,
                strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked("0xabcd"))
                    .expect("issue while converting the contract address"),
            },
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes,
            compiled_classes,
        },
    };

    run_os_stateless(LayoutName::all_cairo, os_hints).expect("Failed to run OS");
}
