use std::error::Error;
use std::io::Write;

pub trait SerializationBackend<T> {
    type Error: Error + Sync + Send + 'static;

    fn serialize_into<W: Write>(&self, value: &T, buffer: W) -> Result<(), Self::Error>;
}

pub trait DeserializationBackend<T> {
    type Error: Error + Sync + Send + 'static;

    fn deserialize(&self, bytes: &[u8]) -> Result<T, Self::Error>;
}

#[cfg(feature = "bincode")]
mod bincode;
#[cfg(feature = "bincode")]
pub use self::bincode::Bincode;

#[cfg(feature = "serde_json")]
mod serde_json;
#[cfg(feature = "serde_json")]
pub use self::serde_json::SerdeJson;
