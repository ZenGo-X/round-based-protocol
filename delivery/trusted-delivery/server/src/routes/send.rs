use std::io;

use rocket::data::{Data, ToByteUnit};
use rocket::http::{ContentType, Status};
use rocket::response::{Responder, Response};
use rocket::{Request, State};
use tokio::io::{AsyncRead, AsyncReadExt};

use generic_array::GenericArray;

use trusted_delivery_core::crypto::default_suite::DefaultSuite;
use trusted_delivery_core::crypto::CryptoSuite;
use trusted_delivery_core::messages::{
    FixedSizeMessage, InvalidPublishMsgHeader, PublishMessageHeader,
};

use super::RoomId;
use crate::db::{Db, MalformedMessage};
use crate::routes::auth::Authenticated;
use crate::routes::verbose_error;

#[rocket::post("/<room_id>/send", data = "<raw_message>")]
pub async fn send(
    db: &State<Db<DefaultSuite>>,
    authenticated: Authenticated<DefaultSuite>,
    room_id: RoomId,
    raw_message: Data<'_>,
) -> (Status, Result<(), String>) {
    let raw_message = raw_message.open(10_000.kilobytes());
    let err = match send_private(&db, &authenticated, room_id, raw_message).await {
        Ok(()) => return (Status::Ok, Ok(())),
        Err(err) => err,
    };

    let code = match &err {
        PublishMessagesError::RoomNotFound => Status::NotFound,
        _ => Status::BadRequest,
    };
    let description = verbose_error(&err);
    (code, Err(description))
}

async fn send_private<C: CryptoSuite, R: AsyncRead + Unpin>(
    db: &Db<C>,
    authenticated: &Authenticated<C>,
    room_id: RoomId,
    mut raw_message: R,
) -> Result<(), PublishMessagesError> {
    // Receive message header
    let mut header_raw =
        GenericArray::<u8, <PublishMessageHeader<C> as FixedSizeMessage>::Size>::default();
    raw_message
        .read_exact(&mut header_raw)
        .await
        .map_err(PublishMessagesError::ReadHeader)?;

    // Parse received header
    let header = PublishMessageHeader::<C>::parse(&header_raw)
        .map_err(PublishMessagesError::MalformedHeader)?;

    // Receive data
    let mut data_buffer = vec![0u8; usize::from(header.data_len)];
    raw_message
        .read_exact(&mut data_buffer)
        .await
        .map_err(PublishMessagesError::ReadMessage)?;

    let writer = db
        .get_room(room_id.0)
        .await
        .ok_or(PublishMessagesError::RoomNotFound)?
        .map(|room| room.add_writer(authenticated.public_key.clone()))
        .unlock_db();

    writer
        .publish_message(header, &data_buffer)
        .await
        .map_err(PublishMessagesError::MalformedMessage)?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
enum PublishMessagesError {
    #[error("room not found")]
    RoomNotFound,
    #[error("receive message header")]
    ReadHeader(#[source] io::Error),
    #[error("malformed header")]
    MalformedHeader(#[source] InvalidPublishMsgHeader),
    #[error("malformed message")]
    MalformedMessage(#[source] MalformedMessage),
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("read message")]
    ReadMessage(#[source] io::Error),
    #[error("message doesn't match provided signature")]
    MismatchedSignature,
}

impl PublishMessagesError {
    pub fn status(&self) -> Status {
        match self {
            PublishMessagesError::RoomNotFound => Status::NotFound,
            _ => Status::BadRequest,
        }
    }
}

impl<'r> Responder<'r, 'static> for PublishMessagesError {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let error_description = self.to_string();
        Response::build()
            .status(self.status())
            .header(ContentType::Plain)
            .sized_body(error_description.len(), io::Cursor::new(error_description))
            .ok()
    }
}
