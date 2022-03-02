use generic_array::typenum::Unsigned;
use std::io::Cursor;

use rocket::response::stream::ReaderStream;
use rocket::State;
use tokio::io::AsyncRead;
use tokio::time;

use trusted_delivery_core::crypto::default_suite::DefaultSuite;
use trusted_delivery_core::crypto::CryptoSuite;
use trusted_delivery_core::publish_msg::{ForwardMessageHeader, Header};

use crate::db::Db;
use crate::routes::auth::Authenticated;
use crate::routes::RoomId;

#[rocket::get("/room/<room_id>/subscribe")]
pub async fn subscribe(
    shutdown: rocket::Shutdown,
    authenticated: Authenticated<DefaultSuite>,
    db: &State<Db<DefaultSuite>>,
    room_id: RoomId,
) -> ReaderStream![impl AsyncRead] {
    subscribe_private(shutdown, &authenticated, &db, room_id).await
}

async fn subscribe_private<C: CryptoSuite>(
    mut shutdown: rocket::Shutdown,
    authenticated: &Authenticated<C>,
    db: &Db<C>,
    room_id: RoomId,
) -> ReaderStream![impl AsyncRead] {
    let public_key = authenticated.public_key.clone();
    let mut subscription = db
        .get_room_or_create_empty(room_id.0)
        .await
        .map(|room| {
            println!(
                "Room joined; subscribers={s} writers={w}",
                s = room.subscribers(),
                w = room.writers()
            );
            room.subscribe(public_key)
        })
        .unlock_db();

    let keep_alive_interval = time::Duration::from_secs(1);
    let mut keep_alives = time::interval_at(
        time::Instant::now() + keep_alive_interval,
        keep_alive_interval,
    );
    keep_alives.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    let header_len = <ForwardMessageHeader<C> as Header>::Size::USIZE;
    ReaderStream! {
        loop {
            let (header, data) = tokio::select! {
                message = subscription.next() => message,
                _ = keep_alives.tick() => {
                    yield Cursor::new(vec![0u8; header_len]);
                    continue;
                },
                _ = &mut shutdown => return,
            };
            let header = header.to_bytes();

            let mut msg = vec![0u8; header.len() + data.len()];
            msg[..header.len()].copy_from_slice(&header);
            msg[header.len()..].copy_from_slice(data);

            yield Cursor::new(msg)
        }
    }
}
