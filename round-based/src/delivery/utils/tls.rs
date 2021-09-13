//! Convenient TLS config builders
//!
//! In this module we provide handy builders that will help you to construct a proper
//! TLS config in a few steps.
//!
//! ## Server config
//! 1. Specify clients root of trust (to enable client authentication), or explicitly
//!    disable client authentication
//! 2. Set server private key and public certificate
//!
//! After completing both steps, you can obtain a resulting config. It will be fixed to
//! support only TLSv1.3 with ciphersuite TLS13_CHACHA20_POLY1305_SHA256. If you skipped
//! one of the steps above, resulting config will be improper, and a server won't be able
//! to accept any connections.
//!
//! ```rust,no_run
//! use round_based::delivery::utils::tls::ServerTlsConfig;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (client_ca, cert, private_key) = unimplemented!();
//!
//! let config = ServerTlsConfig::builder()
//!     .set_clients_ca(&client_ca)?
//!     .set_private_key(cert, private_key)?
//!     .build();
//! # Ok(()) }
//! ```
//!
//! ## Client config
//! 1. Specify server root of trust (i.e. provide CA certificate)
//! 2. Set client private key and public certificate
//!
//! After completing both steps, you can obtain a resulting config. It will be fixed to
//! support only TLSv1.3 with ciphersuite TLS13_CHACHA20_POLY1305_SHA256. If you skipped
//! one of the steps above, resulting config will be improper, and a client won't be able
//! to establish connection with server.
//!
//! ```rust,no_run
//! use round_based::delivery::utils::tls::ClientTlsConfig;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (client_ca, cert, private_key) = unimplemented!();
//!
//! let config = ClientTlsConfig::builder()
//!     .set_server_ca(&client_ca)?
//!     .set_private_key(cert, private_key)?
//!     .build();
//! # Ok(()) }
//! ```
//!
//! ## Custom TLS config
//! If you find these builders limiting, we always provide way around to set custom TLS config.

use std::sync::Arc;

/// Server TLS config
pub struct ServerTlsConfig {
    config: Arc<rustls::ServerConfig>,
}

impl ServerTlsConfig {
    /// Returns an instance of [ServerTlsConfigBuilder] that will help you to construct a proper TLS config
    pub fn builder() -> ServerTlsConfigBuilder {
        ServerTlsConfigBuilder::new()
    }

    /// Returns a shared reference to constructed config
    pub fn to_rustls_config(&self) -> Arc<rustls::ServerConfig> {
        self.config.clone()
    }
}

/// [`ServerTlsConfig`] builder
#[derive(Clone)]
pub struct ServerTlsConfigBuilder {
    config: rustls::ServerConfig,
}

impl ServerTlsConfigBuilder {
    /// Creates incomplete TLS server config
    ///
    /// To complete it, you need to specify private key, and clients CA. Resulting config is fixed
    /// to support only TLSv1.3 with ciphersuite TLS13_CHACHA20_POLY1305_SHA256.
    pub fn new() -> Self {
        let mut config = rustls::ServerConfig::with_ciphersuites(
            rustls::AllowAnyAuthenticatedClient::new(rustls::RootCertStore::empty()),
            &[&rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256],
        );
        config.versions = vec![rustls::ProtocolVersion::TLSv1_3];

        Self { config }
    }

    /// Sets clients root of trust
    ///
    /// Enables client authentication, ie. client must provide a certificate matching given CA.
    pub fn set_clients_ca(mut self, der_cert: &rustls::Certificate) -> Result<Self, webpki::Error> {
        let mut store = rustls::RootCertStore::empty();
        store.add(der_cert)?;
        self.config
            .set_client_certificate_verifier(rustls::AllowAnyAuthenticatedClient::new(store));
        Ok(self)
    }

    /// Disables client authentication
    pub fn disable_client_authentication(mut self) -> Self {
        self.config
            .set_client_certificate_verifier(Arc::new(rustls::NoClientAuth));
        self
    }

    /// Sets server private key and a chain of certificates
    pub fn set_private_key(
        mut self,
        cert: Vec<rustls::Certificate>,
        private_key: rustls::PrivateKey,
    ) -> Result<Self, rustls::TLSError> {
        self.config.set_single_cert(cert, private_key)?;
        Ok(self)
    }

    /// Builds config with given params
    pub fn build(self) -> ServerTlsConfig {
        ServerTlsConfig {
            config: Arc::new(self.config),
        }
    }
}

/// Client TLS config
pub struct ClientTlsConfig {
    config: Arc<rustls::ClientConfig>,
}

impl ClientTlsConfig {
    /// Returns an instance of [ClientTlsConfigBuilder] that will help you to construct a proper TLS config
    pub fn builder() -> ClientTlsConfigBuilder {
        ClientTlsConfigBuilder::new()
    }

    /// Returns a shared reference to constructed config
    pub fn to_rustls_config(&self) -> Arc<rustls::ClientConfig> {
        self.config.clone()
    }
}

/// [`ClientTlsConfig`] builder
pub struct ClientTlsConfigBuilder {
    config: rustls::ClientConfig,
}

impl ClientTlsConfigBuilder {
    /// Creates incomplete TLS client config
    ///
    /// To complete it, you need to specify private key, and server CA. Resulting config is fixed
    /// to support only TLSv1.3 with ciphersuite TLS13_CHACHA20_POLY1305_SHA256.
    pub fn new() -> Self {
        let mut config = rustls::ClientConfig::with_ciphersuites(&[
            &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
        ]);
        config.root_store = rustls::RootCertStore::empty();

        Self { config }
    }

    /// Sets client private key and a chain of certificates
    pub fn set_private_key(
        mut self,
        cert_chain: Vec<rustls::Certificate>,
        private_key: rustls::PrivateKey,
    ) -> Result<Self, rustls::TLSError> {
        self.config
            .set_single_client_cert(cert_chain, private_key)?;
        Ok(self)
    }

    /// Sets server root of trust
    ///
    /// Server must provide a certificate matching given CA
    pub fn set_server_ca(mut self, der_cert: &rustls::Certificate) -> Result<Self, webpki::Error> {
        let mut store = rustls::RootCertStore::empty();
        store.add(der_cert)?;
        self.config.root_store = store;
        Ok(self)
    }

    /// Builds config with given params
    pub fn build(self) -> ClientTlsConfig {
        ClientTlsConfig {
            config: Arc::new(self.config),
        }
    }
}
