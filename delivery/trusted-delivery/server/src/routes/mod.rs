use rocket::request::FromParam;

mod auth;
mod send;

pub struct RoomId([u8; 32]);

impl<'a> FromParam<'a> for RoomId {
    type Error = hex::FromHexError;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        let mut room_id = [0u8; 32];
        hex::decode_to_slice(param, &mut room_id)?;
        Ok(RoomId(room_id))
    }
}

fn verbose_error<E: std::error::Error>(err: &E) -> String {
    let mut s = format!("{}", err);

    let mut child_err = err.source();
    while let Some(err) = child_err {
        s += &format!(": {}", err);
        child_err = err.source();
    }

    s
}
