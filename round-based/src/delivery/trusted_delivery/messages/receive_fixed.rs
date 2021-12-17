use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use generic_array::GenericArray;
use tokio::io::{self, AsyncRead, ReadBuf};

use thiserror::Error;

use super::FixedSizeMessage;

pub struct ReceiveFixed<M: FixedSizeMessage, IO> {
    channel: IO,
    buffer: GenericArray<u8, M::Size>,
    buffer_written: usize,
}

impl<M, IO> ReceiveFixed<M, IO>
where
    M: FixedSizeMessage,
    IO: AsyncRead + Unpin,
{
    pub fn new(channel: IO) -> Self {
        Self {
            channel,
            buffer: GenericArray::default(),
            buffer_written: 0,
        }
    }

    pub fn into_inner(self) -> IO {
        self.channel
    }
}

impl<M, IO> Stream for ReceiveFixed<M, IO>
where
    M: FixedSizeMessage,
    IO: AsyncRead + Unpin,
    GenericArray<u8, M::Size>: Unpin,
{
    type Item = Result<M, ReceiveFixedError<M::ParseError>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        while this.buffer_written < this.buffer.len() {
            let mut buf = ReadBuf::new(&mut this.buffer[this.buffer_written..]);
            ready!(Pin::new(&mut this.channel).poll_read(cx, &mut buf))
                .map_err(ReceiveFixedError::Io)?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return if this.buffer_written != 0 {
                    Poll::Ready(Some(Err(ReceiveFixedError::Io(
                        io::ErrorKind::UnexpectedEof.into(),
                    ))))
                } else {
                    Poll::Ready(None)
                };
            }
            this.buffer_written += bytes_received;
        }

        this.buffer_written = 0;
        Poll::Ready(Some(
            M::parse(&self.buffer).map_err(ReceiveFixedError::Parse),
        ))
    }
}

#[derive(Debug, Error)]
pub enum ReceiveFixedError<E> {
    #[error("i/o error")]
    Io(
        #[source]
        #[from]
        io::Error,
    ),
    #[error("parse error")]
    Parse(#[source] E),
}

impl<E: std::error::Error + Send + Sync + 'static> From<ReceiveFixedError<E>> for io::Error {
    fn from(err: ReceiveFixedError<E>) -> Error {
        match err {
            ReceiveFixedError::Io(err) => err,
            ReceiveFixedError::Parse(err) => io::Error::new(io::ErrorKind::InvalidData, err),
        }
    }
}

#[cfg(test)]
mod test {
    use std::fmt;

    use futures::StreamExt;
    use generic_array::typenum::U256;
    use tokio::io::{self, AsyncWriteExt};

    use hamcrest2::core::MatchResult;
    use hamcrest2::{all, HamcrestMatcher};
    use test_case::test_case;

    use crate::delivery::trusted_delivery::messages::FixedSizeMessage;

    use super::{ReceiveFixed, ReceiveFixedError};

    use self::{Capacity::*, ModifyMsg::*, TerminationError::*};
    use generic_array::GenericArray;

    // Receiving 1 message
    #[test_case(Medium, &[msg(1)]        , SendAsIs => it all!(received(&[msg(1)]), TerminatedWith::Success); "receives a single message")]
    #[test_case(Small , &[msg(1)]        , SendAsIs => it all!(received(&[msg(1)]), TerminatedWith::Success); "receives a single message through a small channel")]
    #[test_case(Tough , &[msg(1)]        , SendAsIs => it all!(received(&[msg(1)]), TerminatedWith::Success); "receives a single message through a tough channel")]
    #[test_case(Medium, &[invalid_msg(1)], SendAsIs => it all!(received(&[]), TerminatedWith::Error(Parse)) ; "receives an invalid message")]
    #[test_case(Medium, &[msg(1)]        , Truncate(10) => it all!(received(&[]), TerminatedWith::Error(UnexpectedEof)); "channel got closed before receiving complete")]
    // Receiving 3 valid messages
    #[test_case(Medium, &[msg(1), msg(2), msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2), msg(3)]), TerminatedWith::Success); "receives 3 messages through a normal channel")]
    #[test_case(Small , &[msg(1), msg(2), msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2), msg(3)]), TerminatedWith::Success); "receives 3 messages through a small channel")]
    #[test_case(Tough , &[msg(1), msg(2), msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2), msg(3)]), TerminatedWith::Success); "receives 3 messages through a tough channel")]
    #[test_case(Large , &[msg(1), msg(2), msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2), msg(3)]), TerminatedWith::Success); "receives 3 messages through a large channel")]
    // Receiving two valid messages and then one malformed
    #[test_case(Medium, &[msg(1), msg(2), invalid_msg(3)], SendAsIs => it all!(received(&[msg(1), msg(2)]), TerminatedWith::Error(Parse)); "receives two valid messages and one malformed")]
    #[test_case(Medium, &[msg(1), msg(2), msg(3)], Truncate(30) => it all!(received(&[msg(1), msg(2)]), TerminatedWith::Error(UnexpectedEof)); "receives two valid messages and one truncated")]
    #[tokio::test]
    async fn parse_messages(
        capacity: Capacity,
        messages: &[TestMsg],
        modify_last_msg: ModifyMsg,
    ) -> ParsedMsgs {
        let (reader, mut writer) = io::duplex(capacity as usize);

        // Writer sends messages to the channel
        let messages = messages.to_vec();
        tokio::spawn(async move {
            let count = messages.len();
            for (i, msg) in messages.iter().enumerate() {
                let msg_bytes = msg.to_bytes();
                let modified_msg = if i + 1 != count {
                    &msg_bytes.as_ref()[..]
                } else if let Truncate(n) = modify_last_msg {
                    &msg_bytes.as_ref()[..msg_bytes.len() - n]
                } else {
                    &msg_bytes.as_ref()[..]
                };
                writer.write_all(modified_msg).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });

        // Reader receives messages
        let mut received = vec![];
        let mut reader = ReceiveFixed::<TestMsg, _>::new(reader);
        while let Some(result) = reader.next().await {
            match result {
                Ok(msg) => received.push(msg),
                Err(err) => {
                    return ParsedMsgs {
                        received,
                        terminated_with: TerminatedWith::Error(match err {
                            ReceiveFixedError::Parse(()) => Parse,
                            ReceiveFixedError::Io(err)
                                if err.kind() == io::ErrorKind::UnexpectedEof =>
                            {
                                UnexpectedEof
                            }
                            ReceiveFixedError::Io(err) => Other(err.to_string()),
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

    #[derive(Clone, Debug, PartialEq)]
    struct TestMsg(GenericArray<u8, U256>);
    impl FixedSizeMessage for TestMsg {
        type Size = U256;
        type ParseError = ();
        fn parse(raw: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError> {
            if raw.starts_with(b"valid msg") {
                Ok(Self(raw.clone()))
            } else {
                Err(())
            }
        }
        fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
            self.0.clone()
        }
    }

    // Produces a good valid message
    fn msg(fill_byte: u8) -> TestMsg {
        let mut msg = GenericArray::<u8, U256>::default();
        msg[0..9].copy_from_slice(b"valid msg");
        msg[9..].iter_mut().for_each(|x| *x = fill_byte);
        TestMsg(msg)
    }

    /// Produces malformed message that cannot be parsed
    fn invalid_msg(fill_byte: u8) -> TestMsg {
        let mut msg = GenericArray::<u8, U256>::default();
        msg[0..11].copy_from_slice(b"invalid msg");
        msg[9..].iter_mut().for_each(|x| *x = fill_byte);
        TestMsg(msg)
    }

    #[repr(usize)]
    enum Capacity {
        // Sends messages byte by byte
        Tough = 1,
        // Not even close to fit a single message
        Small = 10,
        // Fits single message
        Medium = 256,
        // Fits several messages
        Large = 1000,
    }

    enum ModifyMsg {
        Truncate(usize),
        SendAsIs,
    }

    #[derive(Clone, Debug)]
    struct ParsedMsgs {
        received: Vec<TestMsg>,
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
        Parse,
        Other(String),
    }

    fn received(messages: &[TestMsg]) -> impl HamcrestMatcher<ParsedMsgs> {
        struct Received(Vec<TestMsg>);
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
                TerminatedWith::Error(TerminationError::Parse) => {
                    write!(f, "terminated with parse error")
                }
                TerminatedWith::Error(TerminationError::Other(err)) => {
                    write!(f, "terminated with error: {}", err)
                }
            }
        }
    }
}
