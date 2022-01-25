use rocket::{routes, Build, Rocket};

use trusted_delivery_core::crypto::default_suite::DefaultSuite;

use crate::db::Db;
use crate::routes::auth::Challenges;

mod db;
mod routes;

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
}
