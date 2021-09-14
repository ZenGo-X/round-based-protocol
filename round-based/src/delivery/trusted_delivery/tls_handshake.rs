use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;

pub enum TlsHandshake<H, S> {
    Empty,
    InProgress(H),
    Completed(S),
}

impl<H, S> TlsHandshake<H, S>
where
    H: Future<Output = io::Result<S>> + Unpin,
{
    pub fn poll_handshake<'h>(&'h mut self, cx: &mut Context) -> Poll<io::Result<&'h mut S>> {
        match self {
            TlsHandshake::Empty => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "poll after complete",
            ))),
            TlsHandshake::Completed(stream) => Poll::Ready(Ok(stream)),
            TlsHandshake::InProgress(tls_handshake) => {
                let stream = ready!(Pin::new(tls_handshake).poll(cx))?;
                *self = TlsHandshake::Completed(stream);
                Poll::Ready(Ok(self.expect_completed(
                    "tls handshake guaranteed to be completed by above line",
                )))
            }
        }
    }

    pub fn take_completed(&mut self) -> Result<S, Self> {
        match std::mem::replace(self, TlsHandshake::Empty) {
            TlsHandshake::Completed(stream) => Ok(stream),
            state => Err(state),
        }
    }

    #[track_caller]
    pub fn expect_completed(&mut self, msg: &str) -> &mut S {
        match self {
            TlsHandshake::Completed(stream) => stream,
            TlsHandshake::InProgress(_) => panic!(
                "expected completed handshake, actually it's in progress: {}",
                msg
            ),
            TlsHandshake::Empty => {
                panic!("expected completed handshake, actually it's empty: {}", msg)
            }
        }
    }
}
