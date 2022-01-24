use rocket::request::FromParam;

pub type C = trusted_delivery_core::crypto::default_suite::DefaultSuite;

mod auth;

pub struct RoomId([u8; 32]);

impl<'a> FromParam<'a> for RoomId {
    type Error = hex::FromHexError;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        let mut room_id = [0u8; 32];
        hex::decode_to_slice(param, &mut room_id)?;
        Ok(RoomId(room_id))
    }
}
