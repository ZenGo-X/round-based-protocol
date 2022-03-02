use std::borrow::Cow;

use reqwest::header::HeaderValue;
use reqwest::{Client as HttpClient, StatusCode, Url};

use educe::Educe;
use thiserror::Error;

use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use trusted_delivery_core::auth::{
    AuthReq, AuthResp, SerializableChallenge, Witness, WITNESS_HEADER_NAME,
};
use trusted_delivery_core::crypto::{CryptoSuite, SigningKey};
use trusted_delivery_core::publish_msg::{
    ForwardMessageHeader, Header, InvalidForwardMsgHeader, MessageDestination, PublishMessageHeader,
};
use trusted_delivery_core::RoomId;

#[derive(Debug, Clone)]
pub struct ApiClient<S> {
    /// HTTP client (backed by [reqwest])
    http_client: HttpClient,
    /// API endpoint
    base_url: Url,
    /// Current stage ([not authorized] / [authorized] / [joined room])
    ///
    /// [not authorized]: NotAuthorized
    /// [authorized]: Authorized
    /// [joined room]: JoinedRoom
    stage: S,
}

#[derive(Debug, Clone)]
pub struct NotAuthenticated;
#[derive(Educe)]
#[educe(Debug, Clone)]
pub struct Authenticated<C: CryptoSuite> {
    witness: HeaderValue,
    #[educe(Debug(ignore))]
    signing_key: C::SigningKey,
}
#[derive(Educe)]
#[educe(Debug, Clone)]
pub struct JoinedRoom<C: CryptoSuite> {
    room_id: RoomId,
    auth: Authenticated<C>,
    broadcast_counter: u16,
}

impl ApiClient<NotAuthenticated> {
    pub fn new(http_client: HttpClient, base_url: Url) -> Self {
        Self {
            http_client,
            base_url,
            stage: NotAuthenticated,
        }
    }

    async fn get_challenge(&self) -> Result<SerializableChallenge> {
        let challenge: SerializableChallenge = self
            .http_client
            .get(self.url(Method::GetChallenge)?)
            .send()
            .await
            .map_err(Reason::SendRequest)?
            .json()
            .await
            .map_err(Reason::ReceiveAndParse)?;
        Ok(challenge)
    }

    pub async fn auth<C: CryptoSuite>(
        &self,
        secret_key: C::SigningKey,
    ) -> Result<ApiClient<Authenticated<C>>> {
        let challenge = self.get_challenge().await?;
        let challenge_response = challenge.sign_with::<C>(&secret_key);

        let auth_req = AuthReq::<C> {
            public_key: secret_key.verification_key(),
            challenge,
            response: challenge_response,
        };
        let response = self
            .http_client
            .post(self.url(Method::Auth)?)
            .json(&auth_req)
            .send()
            .await
            .map_err(Reason::SendRequest)?;

        let status = response.status();
        let result: Result<AuthResp<C>, String> =
            response.json().await.map_err(Reason::ReceiveAndParse)?;
        if result.is_ok() != status.is_success() {
            return Err(Reason::Confused {
                status,
                response_err: result.err(),
            }
            .into());
        }
        let witness = result
            .map_err(|description| Reason::ServerReturnedError {
                status,
                description,
            })?
            .witness;

        Ok(ApiClient {
            http_client: self.http_client.clone(),
            base_url: self.base_url.clone(),
            stage: Authenticated::new(secret_key, witness),
        })
    }
}

impl<C: CryptoSuite> ApiClient<Authenticated<C>> {
    pub fn join_room(&self, room_id: RoomId) -> ApiClient<JoinedRoom<C>> {
        ApiClient {
            http_client: self.http_client.clone(),
            base_url: self.base_url.clone(),
            stage: JoinedRoom {
                room_id,
                auth: self.stage.clone(),
                broadcast_counter: 0,
            },
        }
    }

    pub fn identity(&self) -> C::VerificationKey {
        self.stage.signing_key.verification_key()
    }
}

impl<C: CryptoSuite> ApiClient<JoinedRoom<C>> {
    pub async fn send(&mut self, recipient: Option<C::VerificationKey>, data: &[u8]) -> Result<()> {
        let recipient = match recipient {
            Some(recipient) => MessageDestination::OneParty {
                recipient_identity: recipient,
            },
            None => MessageDestination::AllParties {
                sequence_number: self.stage.next_broadcast_counter(),
            },
        };
        let header = PublishMessageHeader::<C>::new(&self.stage.auth.signing_key, recipient, data);

        let mut msg = header.to_bytes().to_vec();
        msg.extend_from_slice(data);

        let response = self
            .http_client
            .post(self.url(Method::Send {
                room_id: self.stage.room_id,
            })?)
            .add_witness_header(&self.stage.auth)
            .body(msg)
            .send()
            .await
            .map_err(Reason::SendRequest)?;
        let status = response.status();
        let result: Result<(), String> = response.json().await.map_err(Reason::ReceiveAndParse)?;
        if result.is_ok() != status.is_success() {
            return Err(Reason::Confused {
                status,
                response_err: result.err(),
            }
            .into());
        }
        result.map_err(|description| Reason::ServerReturnedError {
            status,
            description,
        })?;

        Ok(())
    }

    pub async fn subscribe(&self) -> Result<Subscription<C>> {
        let response = self
            .http_client
            .get(self.url(Method::Subscribe {
                room_id: self.stage.room_id,
            })?)
            .add_witness_header(&self.stage.auth)
            .send()
            .await
            .map_err(Reason::SendRequest)?;
        let status = response.status();

        if !status.is_success() {
            let description = response.text().await.map_err(Reason::ReceiveAndParse)?;
            return Err(Reason::ServerReturnedError {
                status,
                description,
            }
            .into());
        }

        Ok(Subscription {
            response,
            message_received_and_parsed: false,
            parsed_header: None,
            buffer: vec![],
            local_party_identity: self.stage.auth.signing_key.verification_key(),
        })
    }
}

impl<S> ApiClient<S> {
    fn url(&self, method: Method) -> Result<Url> {
        let method = match method {
            Method::Auth => Cow::Borrowed("/auth"),
            Method::GetChallenge => Cow::Borrowed("/auth/challenge"),
            Method::Send { room_id } => {
                Cow::Owned(format!("/room/{room}/send", room = hex::encode(room_id)))
            }
            Method::Subscribe { room_id } => Cow::Owned(format!(
                "/room/{room}/subscribe",
                room = hex::encode(room_id)
            )),
        };
        let url = self
            .base_url
            .join(&method)
            .map_err(|err| Reason::BuildApiUrl { method, err })?;
        Ok(url)
    }
}

impl<C: CryptoSuite> Authenticated<C> {
    fn new(signing_key: C::SigningKey, witness: Witness<C>) -> Self {
        let witness = HeaderValue::try_from(hex::encode(&witness))
            .expect("hex string is a valid header value");
        Self {
            signing_key,
            witness,
        }
    }
}

impl<C: CryptoSuite> JoinedRoom<C> {
    pub fn next_broadcast_counter(&mut self) -> u16 {
        let counter = self.broadcast_counter;
        self.broadcast_counter = self
            .broadcast_counter
            .checked_add(1)
            .expect("broadcast counter overflow");
        counter
    }
}

pub struct Subscription<C: CryptoSuite> {
    response: reqwest::Response,
    message_received_and_parsed: bool,
    parsed_header: Option<ForwardMessageHeader<C>>,
    buffer: Vec<u8>,
    local_party_identity: C::VerificationKey,
}

impl<C: CryptoSuite> Subscription<C> {
    pub async fn next<'s>(
        &'s mut self,
    ) -> Result<Option<(&'s ForwardMessageHeader<C>, &'s mut [u8])>> {
        let header_size = Self::header_size();

        loop {
            // Erase message that was already returned
            if self.message_received_and_parsed {
                let data_len = self
                    .parsed_header
                    .as_ref()
                    .map(|header| usize::from(header.data_len))
                    .expect("header must be parsed at this point");
                self.buffer.copy_within(header_size + data_len.., 0);
                self.buffer
                    .resize(self.buffer.len() - (header_size + data_len), 0);

                self.message_received_and_parsed = false;
                self.parsed_header = None;
            }

            // Receive header
            while self.buffer.len() < header_size {
                if self.receive_more().await?.is_none() {
                    return Ok(None);
                }
            }

            // Parse header
            if self.parsed_header.is_none() {
                let mut header_bytes =
                    GenericArray::<u8, <ForwardMessageHeader<C> as Header>::Size>::default();
                header_bytes.copy_from_slice(&self.buffer[..header_size]);

                // Discard keep-alive messages
                if header_bytes == Self::keep_alive_header() {
                    self.buffer.copy_within(header_size.., 0);
                    self.buffer.resize(self.buffer.len() - header_size, 0);
                    continue;
                }

                self.parsed_header = Some(
                    ForwardMessageHeader::<C>::parse(&header_bytes)
                        .map_err(Reason::ReceivedInvalidHeader)?,
                );
            }
            let data_len = self
                .parsed_header
                .as_ref()
                .map(|header| header.data_len)
                .map(usize::from)
                .expect("header must be parsed at this point");

            // Receive data
            while self.buffer.len() < header_size + data_len {
                if self.receive_more().await?.is_none() {
                    return Ok(None);
                }
            }
            let data = &mut self.buffer[header_size..header_size + data_len];
            self.message_received_and_parsed = true;

            // Ensure that signature is valid
            let header = self
                .parsed_header
                .as_ref()
                .expect("header must be parsed at this point");
            header
                .verify(&self.local_party_identity, data)
                .or(Err(Reason::SignatureNotValid))?;

            return Ok(Some((header, data)));
        }
    }

    async fn receive_more(&mut self) -> Result<Option<()>> {
        let chunk = match self.response.chunk().await.map_err(Reason::ReceiveChunk)? {
            Some(chunk) if !chunk.is_empty() => chunk,
            _ => {
                return if self.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(Reason::UnexpectedEof.into())
                };
            }
        };
        self.buffer.extend_from_slice(&chunk);
        Ok(Some(()))
    }

    fn header_size() -> usize {
        <<ForwardMessageHeader<C> as Header>::Size as Unsigned>::USIZE
    }

    fn keep_alive_header() -> GenericArray<u8, <ForwardMessageHeader<C> as Header>::Size> {
        Default::default()
    }
}

enum Method {
    Auth,
    GetChallenge,
    Send { room_id: RoomId },
    Subscribe { room_id: RoomId },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("build an url for api method {method}")]
    BuildApiUrl {
        method: Cow<'static, str>,
        #[source]
        err: url::ParseError,
    },
    #[error("send request")]
    SendRequest(#[source] reqwest::Error),
    #[error("receive and parse response")]
    ReceiveAndParse(#[source] reqwest::Error),
    #[error("receive chunk")]
    ReceiveChunk(#[source] reqwest::Error),
    #[error("signature doesn't match the message")]
    SignatureNotValid,
    #[error("response is closed unexpectedly")]
    UnexpectedEof,
    #[error("received header is not valid")]
    ReceivedInvalidHeader(#[source] InvalidForwardMsgHeader),
    #[error("confused by server response: status={status:?} but response_err={response_err:?}")]
    Confused {
        status: StatusCode,
        response_err: Option<String>,
    },
    #[error("server returned error ({status:?}): {description}")]
    ServerReturnedError {
        status: StatusCode,
        description: String,
    },
}

trait AddWitnessHeader {
    fn add_witness_header<C: CryptoSuite>(self, auth: &Authenticated<C>) -> Self;
}

impl AddWitnessHeader for reqwest::RequestBuilder {
    fn add_witness_header<C: CryptoSuite>(self, auth: &Authenticated<C>) -> Self {
        self.header(WITNESS_HEADER_NAME, &auth.witness)
    }
}
