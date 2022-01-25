use std::io::Cursor;

use rocket::response::stream::ReaderStream;
use rocket::State;
use tokio::io::AsyncRead;

use trusted_delivery_core::crypto::default_suite::DefaultSuite;
use trusted_delivery_core::crypto::CryptoSuite;
use trusted_delivery_core::messages::FixedSizeMessage;

use crate::db::Db;
use crate::routes::auth::Authenticated;
use crate::routes::RoomId;

#[rocket::get("/room/<room_id>/subscribe")]
pub async fn subscribe(
    authenticated: Authenticated<DefaultSuite>,
    db: &State<Db<DefaultSuite>>,
    room_id: RoomId,
) -> ReaderStream![impl AsyncRead] {
    subscribe_private(&authenticated, &db, room_id).await
}

async fn subscribe_private<C: CryptoSuite>(
    authenticated: &Authenticated<C>,
    db: &Db<C>,
    room_id: RoomId,
) -> ReaderStream![impl AsyncRead] {
    let public_key = authenticated.public_key.clone();
    let mut subscription = db
        .get_room_or_create_empty(room_id.0)
        .await
        .map(|room| room.subscribe(public_key))
        .unlock_db();

    ReaderStream! {
        let (header, data) = subscription.next().await;
        let header = header.to_bytes();

        let mut msg = vec![0u8; header.len() + data.len()];
        msg[..header.len()].copy_from_slice(&header);
        msg[header.len()..].copy_from_slice(data);

        yield Cursor::new(msg)
    }
}
