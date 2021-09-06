use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io;
use tokio::net;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::delivery::two_party::insecure::{Side, TwoParty};
use phantom_type::PhantomType;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::ops;

pub mod insecure;

pub type TwoPartyServerTls<M> = TwoParty<
    M,
    io::ReadHalf<tokio_rustls::server::TlsStream<net::TcpStream>>,
    io::WriteHalf<tokio_rustls::server::TlsStream<net::TcpStream>>,
>;
pub type TwoPartyClientTls<M> = TwoParty<
    M,
    io::ReadHalf<tokio_rustls::client::TlsStream<net::TcpStream>>,
    io::WriteHalf<tokio_rustls::client::TlsStream<net::TcpStream>>,
>;

pub struct TlsServer<M> {
    listener: net::TcpListener,
    acceptor: TlsAcceptor,

    buffer_capacity: usize,
    msg_len_limit: usize,

    _ph: PhantomType<M>,
}

impl<M> TlsServer<M>
where
    M: Serialize + DeserializeOwned + Clone,
{
    /// Binds a TCP server at given address with given TLS config
    ///
    /// If you need more precise control on socket binding, use [new](Self::new) constructor.
    pub async fn bind<A: net::ToSocketAddrs>(addr: A, config: ServerTlsConfig) -> io::Result<Self> {
        Ok(Self::new(net::TcpListener::bind(addr).await?, config))
    }

    /// Wraps existing TcpListener and TLS config into TlsServer
    ///
    /// If you need to provide custom [rustls::ServerConfig], use [with_acceptor] constructor.
    ///
    /// [with_rustls_config]: Self::with_rustls_config
    pub fn new(listener: net::TcpListener, config: ServerTlsConfig) -> Self {
        Self::with_acceptor(listener, Arc::new(config.config).into())
    }

    /// Wraps existing TcpListener and acceptor into TlsServer
    pub fn with_acceptor(listener: net::TcpListener, acceptor: TlsAcceptor) -> Self {
        Self {
            listener,
            acceptor,

            buffer_capacity: 4096,
            msg_len_limit: 10_000,

            _ph: PhantomType::new(),
        }
    }

    /// Sets internal buffer capacity
    ///
    /// Ideally, capacity should be chosen to fit 2 serialized messages, ie. choose it to be
    /// `2*average_msg_size`. Buffer grows if it's too small to send/receive a single message unless
    /// it exceeds [message size limit].
    ///
    /// [message size limit]: Self::set_message_size_limit
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 4096 bytes.
    pub fn set_buffer_capacity(&mut self, capacity: usize) {
        self.buffer_capacity = capacity
    }

    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(&mut self, limit: usize) {
        self.msg_len_limit = limit;
    }

    pub async fn accept(&mut self) -> io::Result<(TwoPartyServerTls<M>, SocketAddr)> {
        let (conn, addr) = self.listener.accept().await?;
        let tls_conn = self.acceptor.accept(conn).await?;
        let (read, write) = io::split(tls_conn);
        Ok((
            TwoPartyServerTls::new(
                Side::Server,
                read,
                write,
                self.buffer_capacity,
                self.msg_len_limit,
            ),
            addr,
        ))
    }
}
impl<M> ops::Deref for TlsServer<M> {
    type Target = net::TcpListener;
    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}

#[derive(Clone)]
pub struct ServerTlsConfig {
    config: rustls::ServerConfig,
}

impl ServerTlsConfig {
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
}

pub struct ClientBuilder {
    buffer_capacity: usize,
    msg_len_limit: usize,
}

impl ClientBuilder {
    /// Constructs a client builder
    pub fn new() -> Self {
        Self {
            buffer_capacity: 4096,
            msg_len_limit: 10_000,
        }
    }

    /// Sets internal buffer capacity
    ///
    /// Ideally, capacity should be chosen to fit 2 serialized messages, ie. choose it to be
    /// `2*average_msg_size`. Buffer grows if it's too small to send/receive a single message unless
    /// it exceeds [message size limit].
    ///
    /// [message size limit]: Self::set_message_size_limit
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 4096 bytes.
    pub fn set_buffer_capacity(&mut self, capacity: usize) {
        self.buffer_capacity = capacity
    }

    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(&mut self, limit: usize) {
        self.msg_len_limit = limit;
    }

    pub async fn connect<M, A>(
        self,
        domain: webpki::DNSNameRef<'_>,
        addr: A,
        config: ClientTlsConfig,
    ) -> io::Result<TwoPartyClientTls<M>>
    where
        A: net::ToSocketAddrs,
        M: Serialize + DeserializeOwned + Clone,
    {
        let conn = net::TcpStream::connect(addr).await?;
        self.connected(domain, conn, &TlsConnector::from(Arc::new(config.config)))
            .await
    }

    pub async fn connected<M>(
        self,
        domain: webpki::DNSNameRef<'_>,
        conn: net::TcpStream,
        connector: &TlsConnector,
    ) -> io::Result<TwoPartyClientTls<M>>
    where
        M: Serialize + DeserializeOwned + Clone,
    {
        let tls_conn = connector.connect(domain, conn).await?;
        let (read, write) = io::split(tls_conn);
        Ok(TwoPartyClientTls::new(
            Side::Client,
            read,
            write,
            self.buffer_capacity,
            self.msg_len_limit,
        ))
    }
}

pub struct ClientTlsConfig {
    config: rustls::ClientConfig,
}

impl ClientTlsConfig {
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
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use serde::{Deserialize, Serialize};

    use crate::{DeliverOutgoingExt, Delivery, Incoming, Outgoing};

    use super::*;

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct TestMessage(String);

    /// This is a demonstrative test that shows how we can simply deploy a TCP server/client that can
    /// exchange messages
    #[tokio::test]
    async fn exchange_tls_server_client_messages() {
        let certs = generate_test_certificates();

        let server_tls_config = ServerTlsConfig::new()
            .set_clients_ca(&certs.client_ca)
            .unwrap()
            .set_private_key(certs.server_cert_chain, certs.server_private_key)
            .unwrap();
        let clients_tls_config = ClientTlsConfig::new()
            .set_server_ca(&certs.server_ca)
            .unwrap()
            .set_private_key(certs.client_cert_chain, certs.client_private_key)
            .unwrap();

        let mut server = TlsServer::<TestMessage>::bind("127.0.0.1:0", server_tls_config)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // The server
        let server = tokio::spawn(async move {
            let (link, _addr) = server.accept().await.unwrap();
            let (recv, mut send) = link.split();

            // Server sends some messages to the client
            let sending = tokio::spawn(async move {
                let msgs = vec![
                    "Hi, client!".to_string(),
                    "Wanna see some ads?".to_string(),
                    "Bye".to_string(),
                ];
                send.send_all(msgs.iter().map(|msg| Outgoing {
                    recipient: Some(1),
                    msg,
                }))
                .await
                .unwrap();
                // Shutdown the channel
                DeliverOutgoingExt::<TestMessage>::shutdown(&mut send)
                    .await
                    .unwrap();
            });

            // Server receives messages from the client and asserts that they are what we
            // expected to receive
            let receiving = tokio::spawn(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = vec![
                    Incoming {
                        sender: 1,
                        msg: TestMessage("Hi, server!".to_string()),
                    },
                    Incoming {
                        sender: 1,
                        msg: TestMessage("No thanks".to_string()),
                    },
                    Incoming {
                        sender: 1,
                        msg: TestMessage("Bye".to_string()),
                    },
                ];
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        // The client
        let client = tokio::spawn(async move {
            let link = ClientBuilder::new()
                .connect::<TestMessage, _>(
                    webpki::DNSNameRef::try_from_ascii(b"my-server.local").unwrap(),
                    server_addr,
                    clients_tls_config,
                )
                .await
                .unwrap();
            let (recv, mut send) = link.split();

            // Client sends some messages to the server
            let sending = tokio::spawn(async move {
                let msgs = vec![
                    "Hi, server!".to_string(),
                    "No thanks".to_string(),
                    "Bye".to_string(),
                ];
                send.send_all(msgs.iter().map(|msg| Outgoing {
                    recipient: Some(0),
                    msg,
                }))
                .await
                .unwrap();
                // Shutdown the channel
                DeliverOutgoingExt::<TestMessage>::shutdown(&mut send)
                    .await
                    .unwrap();
            });

            // Client receives messages from the server and asserts that they are what we
            // expected to receive
            let receiving = tokio::spawn(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = vec![
                    Incoming {
                        sender: 0,
                        msg: TestMessage("Hi, client!".to_string()),
                    },
                    Incoming {
                        sender: 0,
                        msg: TestMessage("Wanna see some ads?".to_string()),
                    },
                    Incoming {
                        sender: 0,
                        msg: TestMessage("Bye".to_string()),
                    },
                ];
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        client.await.unwrap();
        server.await.unwrap();
    }

    struct Certificates {
        // public
        server_ca: rustls::Certificate,
        client_ca: rustls::Certificate,
        // server
        server_cert_chain: Vec<rustls::Certificate>,
        server_private_key: rustls::PrivateKey,
        // client
        client_cert_chain: Vec<rustls::Certificate>,
        client_private_key: rustls::PrivateKey,
    }

    fn generate_test_certificates() -> Certificates {
        let mut server_ca_params = rcgen::CertificateParams::default();
        server_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        server_ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let server_ca = rcgen::Certificate::from_params(server_ca_params).unwrap();

        let mut client_ca_params = rcgen::CertificateParams::default();
        client_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        client_ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let clients_ca = rcgen::Certificate::from_params(client_ca_params).unwrap();

        let mut server_params = rcgen::CertificateParams::new(vec!["my-server.local".to_string()]);
        server_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyAgreement,
        ];
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server = rcgen::Certificate::from_params(server_params).unwrap();

        let mut client_params = rcgen::CertificateParams::new(vec!["party0.local".to_string()]);
        client_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client = rcgen::Certificate::from_params(client_params).unwrap();

        Certificates {
            server_ca: server_ca.serialize_der().map(rustls::Certificate).unwrap(),
            client_ca: clients_ca.serialize_der().map(rustls::Certificate).unwrap(),
            server_cert_chain: vec![server
                .serialize_der_with_signer(&server_ca)
                .map(rustls::Certificate)
                .unwrap()],
            server_private_key: rustls::PrivateKey(server.serialize_private_key_der()),
            client_cert_chain: vec![client
                .serialize_der_with_signer(&clients_ca)
                .map(rustls::Certificate)
                .unwrap()],
            client_private_key: rustls::PrivateKey(client.serialize_private_key_der()),
        }
    }

    #[test]
    fn self_signed_certificates_are_valid() {
        use rustls::ServerCertVerifier;

        let certs = generate_test_certificates();

        let server_cert_verifier = rustls::WebPKIVerifier::new();
        let mut server_roots = rustls::RootCertStore::empty();
        server_roots.add(&certs.server_ca).unwrap();

        server_cert_verifier
            .verify_server_cert(
                &server_roots,
                &certs.server_cert_chain,
                webpki::DNSNameRef::try_from_ascii(b"my-server.local").unwrap(),
                &[],
            )
            .unwrap();

        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(&certs.client_ca).unwrap();
        let client_cert_verifier = rustls::AllowAnyAuthenticatedClient::new(client_roots);
        client_cert_verifier
            .verify_client_cert(&certs.client_cert_chain, None)
            .unwrap();
    }
}
