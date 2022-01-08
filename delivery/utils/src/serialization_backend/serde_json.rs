use std::io::Write;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{DeserializationBackend, SerializationBackend};

#[derive(Debug, Default, Copy, Clone)]
pub struct SerdeJson {
    pretty: bool,
}

impl SerdeJson {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pretty_serialization(&mut self, is_pretty: bool) {
        self.pretty = is_pretty
    }
}

impl<T: Serialize> SerializationBackend<T> for SerdeJson {
    type Error = serde_json::Error;

    fn serialize_into<W: Write>(&self, value: &T, writer: W) -> Result<(), Self::Error> {
        if self.pretty {
            serde_json::to_writer_pretty(writer, value)
        } else {
            serde_json::to_writer(writer, value)
        }
    }
}

impl<T: DeserializeOwned> DeserializationBackend<T> for SerdeJson {
    type Error = serde_json::Error;

    fn deserialize(&self, bytes: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(bytes)
    }
}
