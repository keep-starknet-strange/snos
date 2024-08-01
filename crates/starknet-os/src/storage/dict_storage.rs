use std::collections::HashMap;

use futures_util::FutureExt;

use crate::storage::storage::{Storage, StorageError};

/// A dictionary-based storage, for testing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DictStorage {
    pub db: HashMap<Vec<u8>, Vec<u8>>,
}

impl Storage for DictStorage {
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        self.db.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get_value(&self, key: &[u8]) -> impl futures::Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send {
        let result = Ok(self.db.get(key).cloned());
        async move { result }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    fn storage_with_values() -> DictStorage {
        let db =
            HashMap::from([(vec![0], vec![0, 0, 1, 1, 0]), (vec![1], vec![1, 1, 1]), (vec![2], vec![255, 254, 253])]);
        DictStorage { db }
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_value(#[from(storage_with_values)] storage: DictStorage) {
        assert_eq!(Some(vec![0, 0, 1, 1, 0]), storage.get_value(&[0]).await.unwrap());
        assert_eq!(Some(vec![1, 1, 1]), storage.get_value(&[1]).await.unwrap());
        assert_eq!(Some(vec![255, 254, 253]), storage.get_value(&[2]).await.unwrap());

        assert_eq!(None, storage.get_value(&[3]).await.unwrap());
        assert_eq!(None, storage.get_value(&[0, 1, 2]).await.unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn test_set_value(#[from(storage_with_values)] mut storage: DictStorage) {
        let key = vec![1, 2, 3, 4];
        let value = vec![7; 7];

        storage.set_value(key.clone(), value.clone()).await.unwrap();
        assert_eq!(Some(value), storage.get_value(&key).await.unwrap());

        // Overwrite an existing value
        let key = vec![2];
        let value = vec![8; 8];
        storage.set_value(key.clone(), value.clone()).await.unwrap();
        assert_eq!(Some(value), storage.get_value(&key).await.unwrap());
    }
}
