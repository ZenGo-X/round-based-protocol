#[rocket::launch]
async fn launch() -> _ {
    trusted_delivery_server::rocket()
}
