mod acceptor;
mod crypto;
mod incoming;
mod outgoing;
mod p2p_handshake;
#[cfg(test)]
mod test_utils;

// pub struct OutgoingDelivery<P, IO> {
//     channel: io::WriteHalf<TlsStream<IO>>,
//     identity_key: SecretKey,
//     parties: P,
// }
//
// pub struct PreparedOutgoing<'b> {
//     header: [u8; 100],
//     header_len: HeaderLength,
//     header_sent: usize,
//     msg: &'b [u8],
//     msg_sent: usize,
// }
//
// #[derive(Clone, Copy, Debug)]
// #[repr(usize)]
// enum HeaderLength {
//     Broadcast = 1 + 64 + 2,
//     P2P = 1 + 33 + 64 + 2,
// }
//
// #[derive(Debug, Error)]
// pub enum SendError {
//     #[error("malformed message")]
//     MalformedMessage(
//         #[from]
//         #[source]
//         MalformedMessage,
//     ),
//     #[error("i/o error")]
//     Io(
//         #[from]
//         #[source]
//         io::Error,
//     ),
// }
//
// #[derive(Debug, Error)]
// pub enum MalformedMessage {
//     #[error("destination party is unknown")]
//     UnknownParty(u16),
//     #[error("message too long: len={len}, limit={}", u16::MAX)]
//     MessageTooLong { len: usize },
// }
//
// impl<P, IO> OutgoingChannel for OutgoingDelivery<P, IO>
// where
//     P: IdentityResolver + Unpin,
//     IO: AsyncRead + AsyncWrite + Unpin,
// {
//     type Error = SendError;
//
//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
//         ready!(Pin::new(&mut self.channel).poll_flush(cx))?;
//         Poll::Ready(Ok(()))
//     }
//
//     fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
//         ready!(Pin::new(&mut self.channel).poll_shutdown(cx))?;
//         Poll::Ready(Ok(()))
//     }
// }
//
// impl<'b, P, IO> DeliverOutgoing<'b, &'b [u8]> for OutgoingDelivery<P, IO>
// where
//     P: IdentityResolver + Unpin,
//     IO: AsyncRead + AsyncWrite + Unpin,
// {
//     type Prepared = PreparedOutgoing<'b>;
//     fn prepare(
//         self: Pin<&Self>,
//         msg: Outgoing<&'b [u8]>,
//     ) -> Result<PreparedOutgoing<'b>, SendError> {
//         let msg_len = u16::try_from(msg.msg.len())
//             .or(Err(MalformedMessage::MessageTooLong { len: msg.msg.len() }))?;
//         let recipient = msg
//             .recipient
//             .map(|idx| {
//                 self.parties
//                     .lookup_party_identity(idx)
//                     .ok_or(MalformedMessage::UnknownParty(idx))
//             })
//             .transpose()?;
//
//         let hashed_msg = Sha256::new()
//             .chain(recipient.map(PublicKey::serialize).unwrap_or([0u8; 33]))
//             .chain(msg.msg)
//             .finalize();
//         let hashed_msg =
//             Message::from_slice(hashed_msg.as_slice()).expect("sha256 output can be signed");
//         let signature = SECP256K1
//             .sign(&hashed_msg, &self.identity_key)
//             .serialize_compact();
//
//         let mut header = [0u8; 100];
//         let header_len;
//         match recipient {
//             Some(recipient) => {
//                 header[0] = 1;
//                 header[1..1 + 33].copy_from_slice(&recipient.serialize());
//                 header[1 + 33..1 + 33 + 64].copy_from_slice(&signature);
//                 header[1 + 33 + 64..1 + 33 + 64 + 2].copy_from_slice(&msg_len.to_be_bytes());
//                 header_len = HeaderLength::P2P;
//             }
//             None => {
//                 header[0] = 0;
//                 header[1..1 + 64].copy_from_slice(&signature);
//                 header[1 + 64..1 + 64 + 2].copy_from_slice(&msg_len.to_be_bytes());
//                 header_len = HeaderLength::Broadcast;
//             }
//         };
//
//         Ok(PreparedOutgoing {
//             header,
//             header_len,
//             header_sent: 0,
//             msg: msg.msg,
//             msg_sent: 0,
//         })
//     }
//
//     fn poll_start_send(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context,
//         msg: &mut PreparedOutgoing<'b>,
//     ) -> Poll<Result<(), SendError>> {
//         let header_len = msg.header_len as usize;
//         while msg.header_sent < header_len {
//             let header = &msg.header[msg.header_sent..header_len];
//             let sent_bytes = ready!(Pin::new(&mut self.channel).poll_write(cx, header))?;
//             msg.header_sent += sent_bytes;
//         }
//
//         while msg.msg_sent < msg.msg.len() {
//             let sent_bytes =
//                 ready!(Pin::new(&mut self.channel).poll_write(cx, &msg.msg[msg.msg_sent..]))?;
//             msg.msg_sent += sent_bytes;
//         }
//
//         Poll::Ready(Ok(()))
//     }
// }
