use rocket::{routes, Build, Rocket};
use trusted_delivery_core::auth::ServerKey;

use trusted_delivery_core::crypto::default_suite::DefaultSuite;

use crate::db::Db;
use crate::routes::auth::Challenges;

mod db;
mod routes;

#[cfg(any(test, feature = "dev"))]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

pub fn rocket() -> Rocket<Build> {
    rocket::build()
        .mount(
            "/",
            routes![
                routes::auth::auth,
                routes::auth::get_challenge,
                routes::send::send,
                routes::subscribe::subscribe
            ],
        )
        .manage(Db::<DefaultSuite>::empty())
        .manage(Challenges::<DefaultSuite>::new())
        .manage(ServerKey::<DefaultSuite>::generate())
}
