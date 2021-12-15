use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use generic_array::GenericArray;
use tokio::io::{self, AsyncRead, ReadBuf};

use thiserror::Error;

use super::{DataMsg, FixedSizeMsg};

pub struct ReceiveData<M: DataMsg, IO> {
    header: Option<M::Header>,
    header_buffer: GenericArray<u8, <M::Header as FixedSizeMsg>::Size>,
    header_received: usize,
    data: Vec<u8>,
    data_received: usize,
    data_limit: usize,
    data_valid: bool,

    channel: IO,
    parser: M,
}

impl<M, IO> ReceiveData<M, IO>
where
    M: DataMsg,
{
    pub fn new(channel: IO, parser: M) -> Self {
        Self::with_capacity(channel, parser, 1000)
    }

    pub fn with_capacity(channel: IO, parser: M, initial_capacity: usize) -> Self {
        Self {
            header: None,
            header_buffer: GenericArray::default(),
            header_received: 0,
            data: vec![0; initial_capacity],
            data_received: 0,
            data_limit: 10_000,
            data_valid: false,
            channel,
            parser,
        }
    }

    pub fn set_data_limit(&mut self, limit: usize) {
        self.data_limit = limit;
    }

    pub fn received(&self) -> Option<(&M::Header, &[u8])> {
        let header = self.header.as_ref()?;
        let data_len = self.parser.data_size(header);
        if self.data_received != data_len || !self.data_valid {
            None
        } else {
            Some((header, &self.data[..data_len]))
        }
    }

    pub fn received_mut(&mut self) -> Option<(&mut M::Header, &mut [u8])> {
        let header = self.header.as_mut()?;
        let data_len = self.parser.data_size(header);
        if self.data_received != data_len || !self.data_valid {
            None
        } else {
            Some((header, &mut self.data[..data_len]))
        }
    }
}

impl<M, IO> Stream for ReceiveData<M, IO>
where
    M: DataMsg,
    IO: AsyncRead + Unpin,
    GenericArray<u8, <M::Header as FixedSizeMsg>::Size>: Unpin,
{
    type Item =
        Result<(), ReceiveDataError<<M::Header as FixedSizeMsg>::ParseError, M::ValidateError>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.data_valid {
            // Discard previously received data
            self.header = None;
            self.header_received = 0;
            self.data_received = 0;
            self.data_valid = false;
        }

        let this = &mut *self;

        while this.header_received < this.header_buffer.len() {
            let mut buf = ReadBuf::new(&mut this.header_buffer[this.header_received..]);
            ready!(Pin::new(&mut this.channel).poll_read(cx, &mut buf))
                .map_err(ReceiveDataError::Io)?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return if this.header_received != 0 {
                    Poll::Ready(Some(Err(ReceiveDataError::Io(
                        io::ErrorKind::UnexpectedEof.into(),
                    ))))
                } else {
                    Poll::Ready(None)
                };
            }
            this.header_received += bytes_received;
        }

        let header = match &this.header {
            Some(header) => header,
            None => {
                let parsed =
                    M::Header::parse(&this.header_buffer).map_err(ReceiveDataError::ParseHeader)?;
                this.header.get_or_insert(parsed)
            }
        };
        let data_len = this.parser.data_size(header);

        if this.data.len() < data_len {
            if this.data_limit < data_len {
                return Poll::Ready(Some(Err(ReceiveDataError::TooLargeMessage {
                    len: data_len,
                    limit: this.data_limit,
                })));
            }
            this.data.resize(data_len, 0);
        }

        while this.data_received < data_len {
            let mut buf = ReadBuf::new(&mut this.data[this.data_received..data_len]);
            ready!(Pin::new(&mut this.channel).poll_read(cx, &mut buf))
                .map_err(ReceiveDataError::Io)?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return Poll::Ready(Some(Err(ReceiveDataError::Io(
                    io::ErrorKind::UnexpectedEof.into(),
                ))));
            }
            this.data_received += bytes_received;
        }

        this.parser
            .validate(header, &this.data[..data_len])
            .map_err(ReceiveDataError::ValidateData)?;
        this.data_valid = true;

        Poll::Ready(Some(Ok(())))
    }
}

#[derive(Debug, Error)]
pub enum ReceiveDataError<HE, DE> {
    #[error("i/o error")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("parse header")]
    ParseHeader(#[source] HE),
    #[error("validate received data")]
    ValidateData(#[source] DE),
    #[error("message is too large: len={len}bytes, limit={limit}bytes")]
    TooLargeMessage { len: usize, limit: usize },
}

#[cfg(test)]
mod test {
    // Receives 1 valid message
    #[test_case(Tough , &[msg(1)], SendAsIs => it all!(received(&[msg(1)]), TerminatedWith::Success); "receives a valid message through tough channel")]
    #[test_case(Small , &[msg(1)], SendAsIs => it all!(received(&[msg(1)]), TerminatedWith::Success); "receives a valid message through small channel")]
    #[test_case(Medium, &[msg(1)], SendAsIs => it all!(received(&[msg(1)]), TerminatedWith::Success); "receives a valid message through medium channel")]
    // Receives 1 malformed message
    #[test_case(Small, &[msg(1).invalid_header()], SendAsIs => it all!(received(&[]), TerminatedWith::Error(ParseHeader)); "receives a message with malformed header")]
    #[test_case(Small, &[msg(1).invalid_data()], SendAsIs => it all!(received(&[]), TerminatedWith::Error(ValidateData)); "receives a message with malformed data")]
    #[test_case(Small, &[msg(1)], Truncate(90) => it all!(received(&[]), TerminatedWith::Error(UnexpectedEof)); "receives a message with truncated header")]
    #[test_case(Small, &[msg(1)], Truncate(10) => it all!(received(&[]), TerminatedWith::Error(UnexpectedEof)); "receives a message with truncated data")]
    // Receives 3 valid messages
    #[test_case(Small , &[msg(1), msg(2), msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2), msg(3)]), TerminatedWith::Success); "receives 3 valid messages through small channel")]
    #[test_case(Medium, &[msg(1), msg(2), msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2), msg(3)]), TerminatedWith::Success); "receives 3 valid messages through medium channel")]
    #[test_case(Large , &[msg(1), msg(2), msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2), msg(3)]), TerminatedWith::Success); "receives 3 valid messages through large channel")]
    // Receives 2 valid message and 1 malformed
    #[test_case(Large, &[msg(1), msg(2), msg(3).invalid_header()], SendAsIs => it all!(received(&[msg(1), msg(2)]), TerminatedWith::Error(ParseHeader)); "receives 2 valid messages and 1 message with malformed header")]
    #[test_case(Large, &[msg(1), msg(2), msg(3).invalid_data()], SendAsIs => it all!(received(&[msg(1), msg(2)]), TerminatedWith::Error(ValidateData)); "receives 2 valid messages and 1 message with malformed data")]
    #[test_case(Large, &[msg(1), msg(2), msg(3)], Truncate(90) => it all!(received(&[msg(1), msg(2)]), TerminatedWith::Error(UnexpectedEof)); "receives 2 valid messages and 1 message with truncated header")]
    #[test_case(Large, &[msg(1), msg(2), msg(3)], Truncate(10) => it all!(received(&[msg(1), msg(2)]), TerminatedWith::Error(UnexpectedEof)); "receives 2 valid messages and 1 message with truncated data")]
    #[tokio::test]
    async fn parse_messages(
        capacity: Capacity,
        messages: &[Msg],
        modify_last_msg: ModifyMsg,
    ) -> ParsedMsgs {
        let (reader, mut writer) = io::duplex(capacity as usize);

        // Writer sends messages to the channel
        let messages = messages.to_vec();
        tokio::spawn(async move {
            let count = messages.len();
            for (i, msg) in messages.iter().enumerate() {
                let mut serialized_msg = msg.header.to_bytes().to_vec();
                serialized_msg.extend_from_slice(&msg.data);

                let modified_msg = if i + 1 != count {
                    &serialized_msg[..]
                } else if let Truncate(n) = modify_last_msg {
                    &serialized_msg[..serialized_msg.len() - n]
                } else {
                    &serialized_msg[..]
                };
                writer.write_all(modified_msg).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });

        // Reader receives messages
        let mut received = vec![];
        let mut reader = ReceiveData::with_capacity(reader, ParseMsg, 0);
        reader.set_data_limit(80);

        while let Some(result) = reader.next().await {
            match result {
                Ok(()) => {
                    let (header, data) = reader.received().unwrap();
                    received.push(Msg {
                        header: header.clone(),
                        data: data.to_vec(),
                    })
                }
                Err(err) => {
                    return ParsedMsgs {
                        received,
                        terminated_with: TerminatedWith::Error(match err {
                            ReceiveDataError::ParseHeader(()) => TerminationError::ParseHeader,
                            ReceiveDataError::ValidateData(()) => TerminationError::ValidateData,
                            ReceiveDataError::Io(err)
                                if err.kind() == io::ErrorKind::UnexpectedEof =>
                            {
                                TerminationError::UnexpectedEof
                            }
                            other => TerminationError::Other(other.to_string()),
                        }),
                    }
                }
            }
        }

        ParsedMsgs {
            received,
            terminated_with: TerminatedWith::Success,
        }
    }

    /// Produces a valid message
    fn msg(i: u8) -> Msg {
        let mut data = vec![i; 80];
        data[0] = 1;
        Msg {
            header: Header {
                is_valid: true,
                middle: [i; 17],
                data_len: 80,
            },
            data,
        }
    }

    use std::convert::TryFrom;
    use std::fmt;

    use hamcrest2::core::MatchResult;
    use hamcrest2::{all, HamcrestMatcher};
    use test_case::test_case;

    use futures::StreamExt;
    use generic_array::typenum::U20;
    use tokio::io::{self, AsyncWriteExt};

    use self::{Capacity::*, ModifyMsg::*, TerminationError::*};
    use super::{ReceiveData, ReceiveDataError};
    use crate::delivery::trusted_delivery::messages::{DataMsg, FixedSizeMsg};
    use generic_array::GenericArray;

    #[derive(Debug, Clone, PartialEq)]
    struct Msg {
        header: Header,
        data: Vec<u8>,
    }

    impl Msg {
        pub fn invalid_header(mut self) -> Self {
            self.header.is_valid = false;
            self
        }
        pub fn invalid_data(mut self) -> Self {
            self.data[0] = 0;
            self
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Header {
        is_valid: bool,
        middle: [u8; 17],
        data_len: u16,
    }

    impl FixedSizeMsg for Header {
        type Size = U20;
        type ParseError = ();

        fn parse(input: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError> {
            if input[0] != 1 {
                // Header is malformed
                return Err(());
            }
            let data_len = <[u8; 2]>::try_from(&input[18..]).unwrap();
            let data_len = u16::from_be_bytes(data_len);
            Ok(Self {
                is_valid: true,
                middle: <[u8; 17]>::try_from(&input[1..18]).unwrap(),
                data_len,
            })
        }

        fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
            let mut msg = GenericArray::<u8, Self::Size>::default();

            msg[0] = u8::from(self.is_valid);
            msg[1..18].copy_from_slice(&self.middle);
            msg[18..].copy_from_slice(&self.data_len.to_be_bytes());

            msg
        }
    }

    struct ParseMsg;
    impl DataMsg for ParseMsg {
        type Header = Header;
        type ValidateError = ();

        fn data_size(&self, header: &Self::Header) -> usize {
            header.data_len.into()
        }

        fn validate(&self, header: &Self::Header, data: &[u8]) -> Result<(), Self::ValidateError> {
            if data.len() != self.data_size(header) || data.is_empty() || data[0] != 1 {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    enum Capacity {
        // Too small
        Tough = 1,
        // Doesn't fit even a header
        Small = 10,
        // Fits a single message
        Medium = 100,
        // Fits several messages
        Large = 250,
    }

    enum ModifyMsg {
        SendAsIs,
        Truncate(usize),
    }

    #[derive(Clone, Debug)]
    struct ParsedMsgs {
        received: Vec<Msg>,
        terminated_with: TerminatedWith,
    }

    #[derive(Clone, Debug, PartialEq)]
    enum TerminatedWith {
        Success,
        Error(TerminationError),
    }

    #[derive(Clone, Debug, PartialEq)]
    enum TerminationError {
        UnexpectedEof,
        ParseHeader,
        ValidateData,
        Other(String),
    }

    fn received(messages: &[Msg]) -> impl HamcrestMatcher<ParsedMsgs> {
        struct Received(Vec<Msg>);
        impl HamcrestMatcher<ParsedMsgs> for Received {
            fn matches(&self, actual: ParsedMsgs) -> MatchResult {
                if self.0 == actual.received {
                    Ok(())
                } else {
                    Err(format!(
                        "received messages: {:?}\nactual messages: {:?}",
                        actual.received, self.0
                    ))
                }
            }
        }
        impl fmt::Display for Received {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "received messages: {:?}", self.0)
            }
        }
        Received(messages.to_vec())
    }
    impl HamcrestMatcher<ParsedMsgs> for TerminatedWith {
        fn matches(&self, actual: ParsedMsgs) -> MatchResult {
            if *self != actual.terminated_with {
                Err(format!(
                    "mismatched termination: expected {:?}, actual {:?}",
                    self, actual.terminated_with
                ))
            } else {
                Ok(())
            }
        }
    }
    impl fmt::Display for TerminatedWith {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                TerminatedWith::Success => write!(f, "successfully terminated"),
                TerminatedWith::Error(TerminationError::UnexpectedEof) => {
                    write!(f, "terminated with i/o error 'unexpected eof'")
                }
                TerminatedWith::Error(TerminationError::ParseHeader) => {
                    write!(f, "terminated with parse header error")
                }
                TerminatedWith::Error(TerminationError::ValidateData) => {
                    write!(f, "terminated with validate data error")
                }
                TerminatedWith::Error(TerminationError::Other(err)) => {
                    write!(f, "terminated with error: {}", err)
                }
            }
        }
    }
}
