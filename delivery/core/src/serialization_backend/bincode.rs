use std::io::Write;

use bincode::{DefaultOptions, Options};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{DeserializationBackend, SerializationBackend};

#[derive(Debug, Default, Clone)]
pub struct Bincode<O: Options = DefaultOptions> {
    options: O,
}

impl Bincode {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<O: Options> Bincode<O> {
    pub fn with_options(options: O) -> Self {
        Self { options }
    }
}

impl<T> SerializationBackend<T> for Bincode
where
    T: Serialize,
{
    type Error = bincode::Error;

    fn serialize_into<W: Write>(&self, value: &T, writer: W) -> Result<(), Self::Error> {
        self.options.serialize_into(writer, value)
    }
}

impl<T> DeserializationBackend<T> for Bincode
where
    T: DeserializeOwned,
{
    type Error = bincode::Error;

    fn deserialize(&self, bytes: &[u8]) -> Result<T, Self::Error> {
        self.options.deserialize(bytes)
    }
}
