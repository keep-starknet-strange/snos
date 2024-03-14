use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::account_transaction::AccountTransaction::{Declare, DeployAccount, Invoke};
use cairo_vm::Felt252;
use starknet_api::hash::StarkFelt;
use starknet_crypto::{FieldElement, pedersen_hash};

use snos::config::SN_GOERLI;
use snos::io::InternalTransaction;

pub fn to_felt252(stark_felt: &StarkFelt) -> Felt252 {
    Felt252::from_hex(&stark_felt.to_string()).expect("Couldn't parse bytes")
}

// const DECLARE_PREFIX: &[u8] = b"declare";
// const DEPLOY_ACCOUNT_PREFIX: &[u8] = b"deploy_account";
const INVOKE_PREFIX: &[u8] = b"invoke";
// const L1_HANDLER_PREFIX: &[u8] = b"l1_handler";

pub fn hash_on_elements(data: Vec<Felt252>) -> Felt252 {
    let mut current_hash = Felt252::ZERO;

    for item in data.iter() {
        current_hash = hash(&current_hash, item);
    }

    let data_len = Felt252::from(data.len());

    let result = hash(&current_hash, &data_len);

    result
}

pub fn hash(a: &Felt252, b: &Felt252) -> Felt252 {
    let a_be_bytes = a.to_bytes_be();
    let b_be_bytes = b.to_bytes_be();
    let (x, y) = (
        FieldElement::from_bytes_be(&a_be_bytes).unwrap(),
        FieldElement::from_bytes_be(&b_be_bytes).unwrap(),
    );

    let result = pedersen_hash(&x, &y);
    Felt252::from_bytes_be(&result.to_bytes_be())
}

fn tx_hash_invoke_v0(contract_address: Felt252,
           entry_point_selector: Felt252,
           calldata: Vec<Felt252>,
            max_fee: Felt252
) -> Felt252 {
    hash_on_elements(vec!(
        Felt252::from_bytes_be_slice(INVOKE_PREFIX),
        Felt252::ZERO,
        contract_address,
        entry_point_selector,
        hash_on_elements(calldata),
        Felt252::from(max_fee),
        Felt252::from(u128::from_str_radix(SN_GOERLI, 16).unwrap())
    ))
}

pub fn to_internal_tx(account_tx: &AccountTransaction) -> InternalTransaction {

    let hash_value: Felt252;
    let version: Option<Felt252>;
    let contract_address: Option<Felt252>;
    let contract_address_salt: Option<Felt252> = None;
    let contract_hash: Option<Felt252> = None;
    let constructor_calldata: Option<Vec<Felt252>> = None;
    let nonce: Option<Felt252> = None;
    let sender_address: Option<Felt252>;
    let entry_point_selector: Option<Felt252>;
    let entry_point_type: Option<String> = Some("EXTERNAL".to_string());
    let signature: Option<Vec<Felt252>>;
    let class_hash: Option<Felt252> = None;
    let calldata: Option<Vec<Felt252>>;
    let paid_on_l1: Option<bool> = None;
    let r#type: String = "INVOKE_FUNCTION".to_string();
    let max_fee: Option<Felt252>;

    match account_tx {
        Declare(_) => panic!("Not implemented"),
        DeployAccount(_) => panic!("Not implemented"),
        Invoke(invoke_tx) => match &invoke_tx.tx {
            starknet_api::transaction::InvokeTransaction::V0(tx) => {
                version = Some(Felt252::ZERO);
                max_fee = Some(tx.max_fee.0.into());
                signature = Some(tx.signature.0.iter().map(|x| to_felt252(x)).collect());
                entry_point_selector = Some(to_felt252(&tx.entry_point_selector.0));
                calldata = Some(tx.calldata.0.iter().map(|x| to_felt252(x.into())).collect());
                contract_address = Some(to_felt252(tx.contract_address.0.key()));
                sender_address = contract_address;
                hash_value = tx_hash_invoke_v0(
                    contract_address.unwrap(),
                    entry_point_selector.unwrap(),
                    calldata.clone().unwrap(),
                    max_fee.unwrap()
                );

            },
            starknet_api::transaction::InvokeTransaction::V1(_) => panic!("Not implemented"),
            starknet_api::transaction::InvokeTransaction::V3(_) => panic!("Not implemented"),
        },
    }

    return InternalTransaction {
        hash_value,
        version,
        contract_address,
        contract_address_salt,
        contract_hash,
        constructor_calldata,
        nonce,
        sender_address,
        entry_point_selector,
        entry_point_type,
        signature,
        class_hash,
        calldata,
        paid_on_l1,
        r#type,
        max_fee
    };
}
