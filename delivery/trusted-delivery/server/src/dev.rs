use rocket::{Orbit, Rocket};
use url::Url;

/// Trusted Delivery server for tests
pub struct TestServer {
    port: u16,
    shutdown: Option<rocket::Shutdown>,
    _handle: tokio::task::JoinHandle<Result<(), rocket::Error>>,
}

impl TestServer {
    /// Launches server in the background
    ///
    /// Server takes will take random available TCP port, so several `TestServer`s may co-exist
    /// simultaneously. Retrieve server address via [`.address()`](Self::address) method.
    ///
    /// This function returns when server is ready to accept clients requests.
    pub async fn launch() -> Self {
        let (launched_tx, launched_rx) = tokio::sync::oneshot::channel();

        struct OnLaunch(std::sync::Mutex<Option<tokio::sync::oneshot::Sender<u16>>>);
        impl OnLaunch {
            pub fn new(channel: tokio::sync::oneshot::Sender<u16>) -> Self {
                OnLaunch(From::from(Some(channel)))
            }
        }
        #[rocket::async_trait]
        impl rocket::fairing::Fairing for OnLaunch {
            fn info(&self) -> rocket::fairing::Info {
                rocket::fairing::Info {
                    name: "on launch fairing",
                    kind: rocket::fairing::Kind::Liftoff,
                }
            }
            async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
                let channel = {
                    let mut lock = self.0.lock().unwrap();
                    lock.take()
                };
                if let Some(channel) = channel {
                    let _ = channel.send(rocket.config().port);
                }
            }
        }

        let rocket = crate::rocket()
            .configure(rocket::Config {
                address: std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
                port: 0,
                ..rocket::Config::debug_default()
            })
            .attach(OnLaunch::new(launched_tx))
            .ignite()
            .await
            .unwrap();
        let shutdown = rocket.shutdown();

        let _handle = tokio::spawn(rocket.launch());
        let port = launched_rx.await.unwrap();

        Self {
            port,
            shutdown: Some(shutdown),
            _handle,
        }
    }

    /// Returns address the server listens to
    pub fn address(&self) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}/", self.port)).unwrap()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.take().map(|shutdown| shutdown.notify());
    }
}
