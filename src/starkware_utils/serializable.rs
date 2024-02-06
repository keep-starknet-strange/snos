use heck::ToSnakeCase;

#[derive(thiserror::Error, Debug)]
pub enum SerializeError {
    // Right now we keep the raw serde error available for easier debugging.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Expected value to be at most {0} bytes once serialized")]
    ValueTooLong(usize),
}

#[derive(thiserror::Error, Debug)]
pub enum DeserializeError {
    // Right now we keep the raw serde error available for easier debugging.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Could not find a deserialization method that takes this number of bytes: {0}")]
    NoVariantWithLength(usize),

    #[error("Expected {0} bytes but got {1}")]
    LengthMismatch(usize, usize),
}

pub trait Serializable: Sized {
    fn class_name_prefix() -> Vec<u8> {
        let type_name = std::any::type_name::<Self>().to_string();
        // unwrap() is safe here, there is always at least one element
        let struct_name = type_name.split("::").last().unwrap().to_snake_case();
        struct_name.into_bytes()
    }

    /// Converts the class name to a lower case name with '_' as separators and returns the
    /// bytes version of this name. For example HelloWorldAB -> b'hello_world_a_b'.
    fn prefix() -> Vec<u8> {
        Self::class_name_prefix()
    }

    fn serialize(&self) -> Result<Vec<u8>, SerializeError>;

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError>;
}

impl<T> Serializable for T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let serialized = serde_json::to_string(self)?;
        Ok(serialized.into_bytes())
    }

    fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let value: Self = serde_json::from_reader(data)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MySerializable;

    impl Serializable for MySerializable {
        fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
            panic!("Not implemented, on purpose");
        }

        fn deserialize(_data: &[u8]) -> Result<Self, DeserializeError> {
            panic!("Not implemented, on purpose");
        }
    }

    #[test]
    fn test_class_name_prefix() {
        assert_eq!(MySerializable::class_name_prefix(), "my_serializable".as_bytes());
    }
}
