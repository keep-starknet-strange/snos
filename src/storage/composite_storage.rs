use crate::storage::storage::{Storage, StorageError};

/// A composite storage is a storage object made of one main and one fallback storages.
/// It will first attempt to look up the main storage then try the fallback one if it could
/// not find any value in the main storage.
pub struct CompositeStorage<M, F>
where
    M: Storage,
    F: Storage,
{
    main: M,
    fallback: F,
}

impl<M, F> CompositeStorage<M, F>
where
    M: Storage,
    F: Storage,
{
    pub fn new(main: M, fallback: F) -> Self {
        Self { main, fallback }
    }
}

impl<M, F> Storage for CompositeStorage<M, F>
where
    M: Storage,
    F: Storage,
{
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        self.main.set_value(key.clone(), value.clone()).await?;
        self.fallback.set_value(key, value).await
    }

    async fn get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        match self.main.get_value(key).await {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) | Err(StorageError::ContentNotFound) => self.fallback.get_value(key).await,
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::storage::composite_storage::CompositeStorage;
    use crate::storage::dict_storage::DictStorage;
    use crate::storage::storage::Storage;

    #[rstest]
    #[tokio::test]
    async fn test_composite_storage() {
        let mut s1 = DictStorage::default();
        let mut s2 = DictStorage::default();

        let key1 = vec![0, 1, 1];
        let key2 = vec![0, 2, 2];
        let value1 = "hello".as_bytes().to_vec();
        let value2 = "goodbye".as_bytes().to_vec();

        s1.set_value(key1.clone(), value1.clone()).await.unwrap();
        s2.set_value(key2.clone(), value2.clone()).await.unwrap();

        let storage = CompositeStorage::new(s1, s2);

        assert_eq!(storage.get_value(&key1).await.unwrap(), Some(value1));
        assert_eq!(storage.get_value(&key2).await.unwrap(), Some(value2));

        let missing_key = vec![0, 3, 3];
        assert_eq!(storage.get_value(&missing_key).await.unwrap(), None);
    }
}
