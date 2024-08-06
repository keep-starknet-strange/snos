use std::marker::PhantomData;
use std::ops::DerefMut;
use std::sync::Arc;

use blockifier::state::errors::StateError;
use cairo_vm::Felt252;
use starknet_os_types::hash::Hash;
use tokio::sync::Mutex;

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

impl From<StorageError> for StateError {
    fn from(storage_error: StorageError) -> Self {
        StateError::StateReadError(format!("Storage error: {}", storage_error))
    }
}

#[allow(async_fn_in_trait)]
pub trait Storage: Sync + Send {
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError>;

    fn get_value(&self, key: &[u8]) -> impl futures::Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send;
}

pub trait HashFunctionType {
    fn hash(x: &[u8], y: &[u8]) -> Hash;

    fn hash_felts(x: Felt252, y: Felt252) -> Felt252 {
        let hash = Self::hash(x.to_bytes_be().as_ref(), y.to_bytes_be().as_ref());
        hash.into()
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
            match storage.get_value(&key).await {
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
}

#[derive(Debug)]
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

    pub fn clone_with_different_hash<NH>(&self) -> FactFetchingContext<S, NH>
    where
        NH: HashFunctionType,
    {
        FactFetchingContext { storage: self.storage.clone(), _h: Default::default() }
    }

    pub async fn acquire_storage(&self) -> tokio::sync::MutexGuard<S> {
        self.storage.lock().await
    }
}

impl<S, H> Clone for FactFetchingContext<S, H>
where
    S: Storage,
    H: HashFunctionType,
{
    fn clone(&self) -> Self {
        Self { storage: self.storage.clone(), _h: Default::default() }
    }
}

#[allow(async_fn_in_trait)]
pub trait Fact<S: Storage, H: HashFunctionType>: DbObject {
    fn hash(&self) -> Hash;

    async fn set_fact(&self, ffc: &mut FactFetchingContext<S, H>) -> Result<Hash, StorageError> {
        let hash_val = self.hash();
        let mut storage = ffc.acquire_storage().await;
        self.set(storage.deref_mut(), &hash_val).await?;

        Ok(hash_val)
    }
}
