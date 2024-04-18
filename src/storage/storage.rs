use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::sync::Arc;

use async_stream::try_stream;
use cairo_vm::Felt252;
use tokio::sync::Mutex;
use tokio_stream::Stream;

use crate::starkware_utils::serializable::{DeserializeError, Serializable, SerializeError};

pub const HASH_BYTES: usize = 32;

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("Content not found in storage")]
    ContentNotFound,

    #[error(transparent)]
    Deserialize(#[from] DeserializeError),

    #[error(transparent)]
    Serialize(#[from] SerializeError),
}

#[allow(async_fn_in_trait)]
pub trait Storage: Sync + Send {
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError>;

    async fn setnx_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        // TODO: it is unclear what this function does differently from `set_value`.
        //       we'll keep it around for now until this is clarified.
        self.set_value(key, value).await
    }

    fn get_value<K: AsRef<[u8]>>(
        &self,
        key: K,
    ) -> impl futures::Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send;

    async fn has_key<K: AsRef<[u8]>>(&self, key: K) -> bool;

    async fn del_value<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), StorageError>;

    /// Writes the given updates to storage.
    /// Raises an exception when one or more of the operations failed;
    /// in this case, the write might not be atomic.
    async fn mset(&mut self, updates: HashMap<Vec<u8>, Vec<u8>>) -> Result<(), StorageError>;

    /// Reads and returns the values of the given keys.
    ///
    /// Returns None for each nonexistent key.
    fn mget<K, I>(&self, keys: I) -> impl Stream<Item = Result<Option<Vec<u8>>, StorageError>>
    where
        K: AsRef<[u8]>,
        I: Iterator<Item = K>;

    fn mget_or_fail<K, I>(&self, keys: I) -> impl Stream<Item = Result<Vec<u8>, StorageError>>
    where
        K: AsRef<[u8]>,
        I: Iterator<Item = K>,
    {
        let stream = self.mget(keys);
        try_stream! {
            for await value in stream {
                let value = value?;
                match value {
                    Some(content) => yield content,
                    None => {return;},
                }
            }
        }
    }
    async fn get_or_fail<K: AsRef<[u8]>>(&self, key: K) -> Result<Vec<u8>, StorageError> {
        match self.get_value(key).await? {
            Some(content) => Ok(content),
            None => Err(StorageError::ContentNotFound),
        }
    }
}

pub trait HashFunctionType {
    fn hash(x: &[u8], y: &[u8]) -> Vec<u8>;

    fn hash_felts(x: Felt252, y: Felt252) -> Felt252 {
        let hash = Self::hash(x.to_bytes_be().as_ref(), y.to_bytes_be().as_ref());
        Felt252::from_bytes_be_slice(&hash)
    }
}

#[allow(async_fn_in_trait)]
pub trait DbObject: Serializable {
    fn db_key(suffix: &[u8]) -> Vec<u8> {
        let prefix = Self::prefix();
        let elements = vec![&prefix, ":".as_bytes(), suffix];
        elements.into_iter().flat_map(|v| v.iter().cloned()).collect()
    }

    fn get<S: Storage>(
        storage: &S,
        suffix: &[u8],
    ) -> impl futures::Future<Output = Result<Option<Self>, StorageError>> + Send {
        async move {
            let key = Self::db_key(suffix);
            match storage.get_value(key).await {
                Ok(Some(data)) => {
                    let value = Self::deserialize(&data)?;
                    Ok(Some(value))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    fn get_or_fail<S: Storage>(
        storage: &S,
        suffix: &[u8],
    ) -> impl futures::Future<Output = Result<Self, StorageError>> + Send {
        async move {
            match Self::get(storage, suffix).await {
                Ok(Some(content)) => Ok(content),
                Ok(None) => Err(StorageError::ContentNotFound),
                Err(e) => Err(e),
            }
        }
    }

    async fn set<S: Storage>(&self, storage: &mut S, suffix: &[u8]) -> Result<(), StorageError> {
        let key = Self::db_key(suffix);
        let value = self.serialize()?;
        storage.set_value(key, value).await?;
        Ok(())
    }

    async fn setnx<S: Storage>(&self, storage: &mut S, suffix: &[u8]) -> Result<(), StorageError> {
        let key = Self::db_key(suffix);
        let value = self.serialize()?;
        storage.setnx_value(key, value).await?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FactFetchingContext<S, H>
where
    S: Storage,
    H: HashFunctionType,
{
    storage: Arc<Mutex<S>>,
    _h: PhantomData<H>,
}

impl<S, H> FactFetchingContext<S, H>
where
    S: Storage,
    H: HashFunctionType,
{
    pub fn new(storage: S) -> Self {
        Self { storage: Arc::new(Mutex::new(storage)), _h: Default::default() }
    }

    pub async fn acquire_storage(&self) -> tokio::sync::MutexGuard<S> {
        self.storage.lock().await
    }
}

#[allow(async_fn_in_trait)]
pub trait Fact<S: Storage, H: HashFunctionType>: DbObject {
    fn hash(&self) -> Vec<u8>;

    async fn set_fact(&self, ffc: &mut FactFetchingContext<S, H>) -> Result<Vec<u8>, StorageError> {
        let hash_val = self.hash();
        let mut storage = ffc.acquire_storage().await;
        self.set(storage.deref_mut(), &hash_val).await?;

        Ok(hash_val)
    }
}
