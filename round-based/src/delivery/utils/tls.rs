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
//!
//! ## Mocking TLS configs for tests
//! Module [`mock`] contains tools for generating server/client TLS configs in a few lines of code.
//! It generates local CAs, signs certificates, and configure clients to trust server CA and vice-versa.

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

#[cfg(any(test, feature = "unstable"))]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub mod mock {
    //! Tools for generating client/server certificates (testing purposes only)
    //!
    //! ## Example
    //! The code below generates local CAs, and issues two certificates for server and client.
    //! `client_config` is a TLS config that's configured to trust to certificate embedded to
    //! `server_config` and vice-versa. Simply saying, you can use these two configs to establish
    //! a TLS connection.
    //!
    //! ```rust
    //! use round_based::delivery::utils::tls::mock::MockTls;
    //!
    //! let mock_tls = MockTls::generate();
    //! let server_config = mock_tls.issue_server_cert(vec!["my-server.local".to_string()]);
    //! let client_config = mock_tls.issue_client_cert(vec!["".to_string()]);
    //! ```

    use super::{ClientTlsConfig, ServerTlsConfig};

    /// A tool for generating self-signed certificates (testing purposes only)
    pub struct MockTls {
        server_ca: Ca,
        client_ca: Ca,
    }

    impl MockTls {
        pub fn generate() -> Self {
            let server_ca = Ca::generate();
            let client_ca = Ca::generate();

            Self {
                server_ca,
                client_ca,
            }
        }

        pub fn issue_server_cert(
            &self,
            server_host: Vec<String>,
        ) -> MockTlsConfig<ServerTlsConfig> {
            let cert = self
                .server_ca
                .issue_cert(rcgen::ExtendedKeyUsagePurpose::ServerAuth, server_host);
            let cert_chain = vec![rustls::Certificate(
                cert.serialize_der_with_signer(&self.server_ca.certificate)
                    .unwrap(),
            )];
            let private_key = rustls::PrivateKey(cert.serialize_private_key_der());

            let config = ServerTlsConfig::builder()
                .set_clients_ca(&self.client_ca.ca_cert())
                .unwrap()
                .set_private_key(cert_chain.clone(), private_key.clone())
                .unwrap()
                .build();
            MockTlsConfig {
                config,
                cert_chain,
                private_key,
            }
        }

        pub fn issue_client_cert(
            &self,
            client_alt_name: Vec<String>,
        ) -> MockTlsConfig<ClientTlsConfig> {
            let cert = self
                .client_ca
                .issue_cert(rcgen::ExtendedKeyUsagePurpose::ClientAuth, client_alt_name);
            let cert_chain = vec![rustls::Certificate(
                cert.serialize_der_with_signer(&self.client_ca.certificate)
                    .unwrap(),
            )];
            let private_key = rustls::PrivateKey(cert.serialize_private_key_der());

            let config = ClientTlsConfig::builder()
                .set_server_ca(&self.server_ca.ca_cert())
                .unwrap()
                .set_private_key(cert_chain.clone(), private_key.clone())
                .unwrap()
                .build();

            MockTlsConfig {
                config,
                cert_chain,
                private_key,
            }
        }
    }

    struct Ca {
        certificate: rcgen::Certificate,
    }

    impl Ca {
        pub fn generate() -> Self {
            let mut ca_params = rcgen::CertificateParams::default();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            let ca = rcgen::Certificate::from_params(ca_params).unwrap();
            Self { certificate: ca }
        }

        pub fn ca_cert(&self) -> rustls::Certificate {
            rustls::Certificate(self.certificate.serialize_der().unwrap())
        }

        pub fn issue_cert(
            &self,
            purpose: rcgen::ExtendedKeyUsagePurpose,
            alt_names: Vec<String>,
        ) -> rcgen::Certificate {
            let mut cert_params = rcgen::CertificateParams::new(alt_names);
            cert_params.key_usages = vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::KeyAgreement,
            ];
            cert_params.extended_key_usages = vec![purpose];
            rcgen::Certificate::from_params(cert_params).unwrap()
        }
    }

    /// TLS certificate generated by [`MockTls`]
    pub struct MockTlsConfig<C> {
        config: C,
        cert_chain: Vec<rustls::Certificate>,
        private_key: rustls::PrivateKey,
    }
    impl<C> MockTlsConfig<C> {
        pub fn cert_chain(&self) -> &[rustls::Certificate] {
            &self.cert_chain
        }
        pub fn private_key(&self) -> &rustls::PrivateKey {
            &self.private_key
        }
    }
    impl<C> std::ops::Deref for MockTlsConfig<C> {
        type Target = C;
        fn deref(&self) -> &Self::Target {
            &self.config
        }
    }

    #[test]
    fn self_signed_certificates_are_valid() {
        use rustls::ServerCertVerifier;

        let cfg = MockTls::generate();
        let server_cfg = cfg.issue_server_cert(vec!["my-server.local".to_string()]);
        let client_cfg = cfg.issue_client_cert(vec!["party0.local".to_string()]);

        let server_cert_verifier = rustls::WebPKIVerifier::new();
        let mut server_roots = rustls::RootCertStore::empty();
        server_roots.add(&cfg.server_ca.ca_cert()).unwrap();

        server_cert_verifier
            .verify_server_cert(
                &server_roots,
                server_cfg.cert_chain(),
                webpki::DNSNameRef::try_from_ascii(b"my-server.local").unwrap(),
                &[],
            )
            .unwrap();

        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(&cfg.client_ca.ca_cert()).unwrap();
        let client_cert_verifier = rustls::AllowAnyAuthenticatedClient::new(client_roots);
        client_cert_verifier
            .verify_client_cert(&client_cfg.cert_chain, None)
            .unwrap();
    }
}
