mod forward_msg;
mod hello_msg;
mod publish_msg;
mod receive_data;
mod receive_fixed;

pub trait FixedSizeMsg
where
    Self: Sized,
{
    /// Byte array that fits entire message, eg. `[u8; 33]`
    type BytesArray: DefaultArray + AsRef<[u8]> + AsMut<[u8]> + Unpin;
    type ParseError;

    fn parse(raw: &Self::BytesArray) -> Result<Self, Self::ParseError>;
    fn to_bytes(&self) -> Self::BytesArray;
}

pub trait DataMsg {
    type Header: FixedSizeMsg + Unpin;
    type ValidateError;

    fn data_size(&self, header: &Self::Header) -> usize;
    fn validate(&self, header: &Self::Header, data: &[u8]) -> Result<(), Self::ValidateError>;
}

pub trait DefaultArray {
    fn default_array() -> Self;
}

impl<T: Default + Copy, const N: usize> DefaultArray for [T; N] {
    fn default_array() -> Self {
        [T::default(); N]
    }
}
