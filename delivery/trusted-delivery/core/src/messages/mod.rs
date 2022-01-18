use generic_array::{ArrayLength, GenericArray};

mod forward_msg;
mod hello_msg;
mod publish_msg;
// mod receive_data;
// mod receive_fixed;
// mod send_fixed;

pub use self::{forward_msg::*, hello_msg::*, publish_msg::*};

pub trait FixedSizeMessage
where
    Self: Sized + Unpin,
{
    type Size: ArrayLength<u8>;
    type ParseError;

    fn parse(raw: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError>;
    fn to_bytes(&self) -> GenericArray<u8, Self::Size>;
}

pub trait DataMsgParser
where
    Self: Unpin,
{
    type Header: FixedSizeMessage;
    type ValidateError;

    fn data_size(&self, header: &Self::Header) -> usize;
    fn validate(&self, header: &Self::Header, data: &[u8]) -> Result<(), Self::ValidateError>;
}
