use lazy_static::lazy_static;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};

pub const TESTING_FEE: u128 = 0x10000000000000000000000000;
pub const TESTING_TRANSFER_AMOUNT: u128 = 0x01000000000000000000000000000000;

// -------------------------------Contract Addresses - 0.12.2-------------------------------
lazy_static! {
    pub static ref DUMMY_ACCOUNT_ADDRESS_0_12_2: ContractAddress =
        contract_address!("5ca2b81086d3fbb4f4af2f1deba4b7fd35e8f4b2caee4e056005c51c05c3dd0");
    pub static ref TESTING_1_ADDREESS_0_12_2: ContractAddress =
        contract_address!("46fd0893101585e0c7ebd3caf8097b179f774102d6373760c8f60b1a5ef8c92");
    pub static ref TESTING_2_ADDREESS_0_12_2: ContractAddress =
        contract_address!("4e9665675ca1ac12820b7aff2f44fec713e272efcd3f20aa0fd8ca277f25dc6");
    pub static ref TESTING_3_ADDREESS_0_12_2: ContractAddress =
        contract_address!("74cebec93a58b4400af9c082fb3c5adfa0800ff1489f8fc030076491ff86c48");
    pub static ref TESTING_DELEGATE_ADDREESS_0_12_2: ContractAddress =
        contract_address!("238e6b5dffc9f0eb2fe476855d0cd1e9e034e5625663c7eda2d871bd4b6eac0");
}

// -------------------------------Class Hashes - 0.12.2-------------------------------
pub const TOKEN_FOR_TESTING_HASH_0_12_2: &str = "45000d731e6d5ad0023e448dd15cab6f997b04a39120daf56a8816d9f436376";
pub const DUMMY_ACCOUNT_HASH_0_12_2: &str = "16dc3038da22dde8ad61a786ab9930699cc496c8bccb90d77cc8abee89803f7";
pub const DUMMY_TOKEN_HASH_0_12_2: &str = "7cea4d7710723fa9e33472b6ceb71587a0ce4997ef486638dd0156bdb6c2daa";
pub const TESTING_HASH_0_12_2: &str = "7364bafc3d2c56bc84404a6d8be799f533e518b8808bce86395a9442e1e5160";
pub const TESTING_HASH_2_0_12_2: &str = "49bcc976d628b1b238aefc20e77303a251a14ba6c99cd543a86708513414057";
pub const DELEGATE_PROXY_HASH_0_12_2: &str = "1880d2c303f26b658392a2c92a0677f3939f5fdfb960ecf5912afa06ad0b9d9";

pub const EXPECTED_PREV_ROOT: &str = "473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d";
#[allow(dead_code)]
pub const TESTING_BLOCK_HASH: &str = "59b01ba262c999f2617412ffbba780f80b0103d928cbce1aecbaa50de90abda";
#[allow(dead_code)]
pub const EXPECTED_UPDATED_ROOT: &str = "482c9ce8a99afddc9777ff048520fcbfab6c0389f51584016c80a2e94ab8ca7";
