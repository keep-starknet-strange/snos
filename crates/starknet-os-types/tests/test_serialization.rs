use rstest::rstest;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sierra_cc_from_json() {
    let class_json = include_bytes!("./class_from_pathfinder.json");
    let generic_sierra_cc = GenericSierraContractClass::from_bytes(class_json.to_vec());
    let _ = generic_sierra_cc.class_hash().unwrap();
}

#[rstest]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sierra_cc_from_cairo_lang_class() {
    let class_json = include_bytes!("./class_from_pathfinder.json");

    let contract_class: starknet_core::types::ContractClass = serde_json::from_slice(class_json)
        .expect("Failed to deserialize JSON to ContractClass");


    let generic_sierra_cc = match contract_class {
        starknet_core::types::ContractClass::Sierra(flattened_sierra_cc) => {
            GenericSierraContractClass::from(flattened_sierra_cc)
        },
        _ => panic!("Expected Sierra variant")
    };

    let _ = generic_sierra_cc.class_hash().unwrap();
}
