use crate::storage::composite_storage::CompositeStorage;
use crate::storage::dict_storage::DictStorage;

pub type CachedStorage<S> = CompositeStorage<DictStorage, S>;
