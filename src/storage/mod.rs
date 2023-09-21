pub mod starknet;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec};

type HashFunctionType = fn(&[u8], &[u8]) -> Vec<u8>;

pub trait Storage: Clone {
    async fn set_value(&self, key: Vec<u8>, value: Vec<u8>);
    async fn get_value(&self, key: Vec<u8>) -> Option<Vec<u8>>;
    async fn del_value(&self, key: Vec<u8>);
}

pub trait DBObject: Serialize + for<'de> Deserialize<'de> + Copy {
    /// Method to get the database key for the object
    fn db_key(suffix: Vec<u8>) -> Vec<u8>;

    /// Asynchronous methods for getting and setting the object in storage
    async fn get<S: Storage>(storage: &S, suffix: &Vec<u8>) -> Option<Self>
    where
        Self: Sized,
    {
        let key = Self::db_key(suffix.clone());
        if let Some(data) = storage.get_value(key).await {
            Some(from_slice(&data).expect("Failed to deserialize data"))
        } else {
            None
        }
    }

    async fn set<S: Storage>(&self, storage: &S, suffix: &Vec<u8>) {
        let key = Self::db_key(suffix.clone());
        let data = to_vec(self).expect("Failed to serialize data");
        storage.set_value(key, data).await;
    }
}

#[derive(Debug, Clone)]
pub struct FactCheckingContext<S: Storage> {
    storage: S,
    hash_func: HashFunctionType,
    n_workers: Option<u32>,
}

pub trait Fact: DBObject {
    ///  A fact is a DB object with a DB key that is a hash of its value.
    ///  Use set_fact() and get() to read and write facts.
    fn _hash(&self, hash_func: HashFunctionType) -> Vec<u8>;

    async fn set_fact<S: Storage>(&self, ffc: FactCheckingContext<S>) -> Vec<u8> {
        let hash_val = self._hash(ffc.hash_func);
        self.set(&ffc.storage, &hash_val);
        hash_val
    }
}
