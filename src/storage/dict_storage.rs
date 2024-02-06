use std::collections::HashMap;

use async_stream::stream;
use futures_util::{FutureExt, Stream};

use crate::storage::storage::{Storage, StorageError};

/// A dictionary-based storage, for testing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DictStorage {
    db: HashMap<Vec<u8>, Vec<u8>>,
}

impl Storage for DictStorage {
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        self.db.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get_value<K: AsRef<[u8]>>(
        &self,
        key: K,
    ) -> impl futures::Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send {
        let result = Ok(self.db.get(key.as_ref()).cloned());
        async move { result }.boxed()
    }

    async fn has_key<K: AsRef<[u8]>>(&self, key: K) -> bool {
        self.db.contains_key(key.as_ref())
    }

    async fn del_value<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), StorageError> {
        self.db.remove(key.as_ref());
        Ok(())
    }

    async fn mset(&mut self, updates: HashMap<Vec<u8>, Vec<u8>>) -> Result<(), StorageError> {
        for (key, value) in updates {
            self.db.insert(key, value);
        }
        Ok(())
    }
    fn mget<K, I>(&self, keys: I) -> impl Stream<Item = Result<Option<Vec<u8>>, StorageError>>
    where
        K: AsRef<[u8]>,
        I: Iterator<Item = K>,
    {
        stream! {
            for key in keys {
                yield Ok(self.db.get(key.as_ref()).cloned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};
    use tokio_stream::StreamExt;

    use super::*;

    #[fixture]
    fn storage_with_values() -> DictStorage {
        let db =
            HashMap::from([(vec![0], vec![0, 0, 1, 1, 0]), (vec![1], vec![1, 1, 1]), (vec![2], vec![255, 254, 253])]);
        let storage = DictStorage { db };

        storage
    }

    #[rstest]
    #[tokio::test]
    async fn test_has_key(#[from(storage_with_values)] storage: DictStorage) {
        assert!(storage.has_key(vec![0]).await);
        assert!(storage.has_key(vec![1]).await);
        assert!(storage.has_key(vec![2]).await);

        assert!(!storage.has_key(vec![3]).await);
        assert!(!storage.has_key(vec![0, 1, 2]).await);
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_value(#[from(storage_with_values)] storage: DictStorage) {
        assert_eq!(Some(vec![0, 0, 1, 1, 0]), storage.get_value(vec![0]).await.unwrap());
        assert_eq!(Some(vec![1, 1, 1]), storage.get_value(vec![1]).await.unwrap());
        assert_eq!(Some(vec![255, 254, 253]), storage.get_value(vec![2]).await.unwrap());

        assert_eq!(None, storage.get_value(vec![3]).await.unwrap());
        assert_eq!(None, storage.get_value(vec![0, 1, 2]).await.unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_set_value(#[from(storage_with_values)] mut storage: DictStorage) {
        let key = vec![1, 2, 3, 4];
        let value = vec![7; 7];

        storage.set_value(key.clone(), value.clone()).await.unwrap();
        assert_eq!(Some(value), storage.get_value(key).await.unwrap());

        // Overwrite an existing value
        let key = vec![2];
        let value = vec![8; 8];
        storage.set_value(key.clone(), value.clone()).await.unwrap();
        assert_eq!(Some(value), storage.get_value(key).await.unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_del_value(#[from(storage_with_values)] mut storage: DictStorage) {
        // Delete existing key
        let key = vec![2];
        storage.del_value(&key).await.unwrap();
        assert_eq!(None, storage.get_value(&key).await.unwrap());

        // Delete nonexistent key
        let key = vec![1, 2, 3, 4];
        storage.del_value(&key).await.unwrap();
        assert_eq!(None, storage.get_value(&key).await.unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_mset(#[from(storage_with_values)] mut storage: DictStorage) {
        let mut old_values = storage.db.clone();
        let new_values = HashMap::from([(vec![1, 2, 3, 4], vec![3; 3]), (vec![3], vec![32]), (vec![0], vec![0; 100])]);
        storage.mset(new_values.clone()).await.unwrap();

        for (key, value) in new_values.iter() {
            assert_eq!(Some(value), storage.get_value(key).await.unwrap().as_ref());
        }

        // Check that the previous values (minus the ones that were replaced) are still present
        let remaining_values = {
            for key in new_values.keys() {
                old_values.remove(key);
            }
            old_values
        };
        for (key, value) in remaining_values {
            assert_eq!(Some(value), storage.get_value(key).await.unwrap());
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_mget(#[from(storage_with_values)] storage: DictStorage) {
        let storage_content = storage.db.clone();

        let keys = storage_content.keys();
        let values: Vec<_> = storage.mget(keys.clone()).collect().await;

        assert_eq!(keys.len(), values.len());
        for (key, value) in keys.zip(values) {
            let value = value.unwrap();
            assert_eq!(value, storage_content.get(key).cloned());
        }
    }
}
