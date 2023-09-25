pub mod starknet;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec};

use crate::utils::hasher::{pedersen::PedersenHasher, HasherT};

pub trait Storage: Clone {
    async fn set_value(&self, key: Vec<u8>, value: Vec<u8>);
    async fn get_value(&self, key: Vec<u8>) -> Option<Vec<u8>>;
    async fn del_value(&self, key: Vec<u8>);
}

pub trait DBObject: Serialize + for<'de> Deserialize<'de> {
    /// Method to get the database key for the object
    fn db_key(suffix: Vec<u8>) -> Vec<u8>;

    /// Asynchronous methods for getting and setting the object in storage
    async fn get<S: Storage>(storage: &S, suffix: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        let key = Self::db_key(suffix.to_vec());
        storage
            .get_value(key)
            .await
            .map(|data| from_slice(&data).expect("Failed to deserialize data"))
    }

    async fn set<S: Storage>(&self, storage: &S, suffix: &[u8]) {
        let key = Self::db_key(suffix.to_vec());
        let data = to_vec(self).expect("Failed to serialize data");
        storage.set_value(key, data).await;
    }
}

pub const HASH_BYTES: [u8; 4] = 32u32.to_be_bytes();

#[derive(Debug)]
pub struct FactCheckingContext<S: Storage, H: HasherT> {
    pub storage: S,
    pub _n_workers: Option<u32>,
    phantom_data: PhantomData<H>,
}

pub trait Fact: DBObject {
    ///  A fact is a DB object with a DB key that is a hash of its value.
    ///  Use set_fact() and get() to read and write facts.
    fn _hash<H: HasherT>(&self) -> Vec<u8>;

    async fn set_fact<S: Storage, H: HasherT>(&self, ffc: FactCheckingContext<S, H>) -> Vec<u8> {
        let hash_val = self._hash::<PedersenHasher>();
        self.set(&ffc.storage, &hash_val);
        hash_val
    }
}
