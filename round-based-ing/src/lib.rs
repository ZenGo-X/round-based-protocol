use std::sync::Arc;
use std::{fmt, ops};

pub use ecdsa_mpc::algorithms::zkp::ZkpSetup;
pub use ecdsa_mpc::ecdsa::keygen::Message as KeygenMsg;
pub use ecdsa_mpc::ecdsa::signature::Message as SigningMsg;

use curv_kzen::elliptic::curves::secp256_k1::FE as InitialSecret;
use curv_kzen::elliptic::curves::traits::{ECPoint, ECScalar};
use ecdsa_mpc::ecdsa::keygen::{
    self, DecryptionKey, MultiPartyInfo, SecretKeyLoader, SecretKeyLoaderError,
};
use ecdsa_mpc::ecdsa::signature::{self as signing};
use ecdsa_mpc::ecdsa::{InitialKeys, InitialPublicKeys};
use ecdsa_mpc::protocol::PartyIndex;
use ecdsa_mpc::Parameters;
use sorted_vec::SortedVec;

use digest::generic_array::typenum::U32;
use digest::Digest;
use serde::{Deserialize, Serialize};

use round_based::Mpc;

use thiserror::Error;

use crate::debugging::Debugging;
use crate::generic::Parties;

mod debugging;
mod generic;

/// Distributed key generation
pub struct Keygen {
    i: u16,
    min_signers: u16,
    n: u16,
    zkp_setup: Option<ZkpSetup>,
    initial_keys: Option<(
        InitialPublicKeys,
        Arc<Box<dyn SecretKeyLoader + Send + Sync>>,
    )>,
    debugging: Option<tracing::Span>,
}

impl Keygen {
    /// Constructs `Keygen` that can be used to initiate protocol execution
    ///
    /// Takes index of local party `i`, threshold `min_signers` (minimum number of
    /// parties that can perform signing), number of parties `n`.
    ///
    /// Returns error if parameters are not consistent. Params should satisfy
    /// following requirements:
    /// * `n >= 2`
    /// * `0 <= i < n`
    /// * `0 < min_signers <= n`
    pub fn new(i: u16, min_signers: u16, n: u16) -> Result<Self, InvalidKeygenParameters> {
        if n < 2 {
            Err(InvalidKeygenParameters::TooFewParties { n })
        } else if !(0 < min_signers && min_signers <= n) {
            Err(InvalidKeygenParameters::IncorrectThreshold { min_signers, n })
        } else if i >= n {
            Err(InvalidKeygenParameters::IncorrectPartyIndex { i, n })
        } else {
            Ok(Self {
                i,
                min_signers,
                n,
                zkp_setup: None,
                initial_keys: None,
                debugging: None,
            })
        }
    }

    /// Sets ZKP setup
    ///
    /// By default, we generate a new random setup of 2048 bits group order.
    /// Note that this operation is computationally heavy.
    pub fn set_zkp_setup(mut self, setup: ZkpSetup) -> Self {
        self.zkp_setup = Some(setup);
        self
    }

    /// Sets initial keygen keys
    ///
    /// By default, we generate initial keys and store them in memory.
    pub fn set_initial_keys(
        mut self,
        public_keys: InitialPublicKeys,
        keys_loader: Arc<Box<dyn SecretKeyLoader + Send + Sync>>,
    ) -> Self {
        self.initial_keys = Some((public_keys, keys_loader));
        self
    }

    /// Enables logging
    ///
    /// All the logs will be spanned with given `span`
    pub fn enable_logs(mut self, span: tracing::Span) -> Self {
        self.debugging = Some(span);
        self
    }

    /// Carries out key generation
    pub async fn run<M>(
        self,
        party: M,
    ) -> Result<KeyShare, KeygenError<M::ReceiveError, M::SendError>>
    where
        M: Mpc<ProtocolMessage = KeygenMsg>,
    {
        // Construct key parameters
        let parameters = Parameters::new(usize::from(self.min_signers), usize::from(self.n))
            .map_err(BugReason::InvalidParameters)?;

        // Make list of parties
        let parties = (0..self.n)
            .map(|i| party_index_from_u16(i))
            .collect::<Vec<_>>();
        let parties = Parties::try_from(parties).or(Err(BugReason::PartiesListNotSorted))?;

        // Generate initial keys
        let (initial_public_keys, keys_loader) = self.initial_keys.unwrap_or_else(|| {
            let init_keys = InitialKeys::random();
            let initial_public_keys = InitialPublicKeys::from(&init_keys);
            (
                initial_public_keys,
                Arc::new(Box::new(InMemorySecretStorage(init_keys))),
            )
        });
        let zkp_setup = self.zkp_setup.unwrap_or_else(|| ZkpSetup::random(2048));

        // Construct initial keygen state
        let initial_state = keygen::Phase1::new(
            &parameters,
            initial_public_keys,
            Some(zkp_setup),
            parties.as_slice(),
            parties.as_slice()[usize::from(self.i)],
            keys_loader,
            None,
        )
        .map_err(KeygenError::ConstructPhase1)?;

        let share = if let Some(span) = self.debugging {
            generic::execute_ing_protocol(
                party,
                Debugging::new(initial_state).set_span(span),
                self.i,
                parties,
            )
            .await
            .map_err(KeygenError::ProtocolExecution)?
            .multiparty_shared_info
        } else {
            generic::execute_ing_protocol(party, initial_state, self.i, parties)
                .await
                .map_err(KeygenError::ProtocolExecution)?
                .multiparty_shared_info
        };

        let share = KeyShare::try_from(share).map_err(BugReason::IncorrectKeyShare)?;
        Ok(share)
    }
}

/// Key share allowing taking a part in signing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "ecdsa_mpc::ecdsa::keygen::MultiPartyInfo")]
#[serde(try_from = "ecdsa_mpc::ecdsa::keygen::MultiPartyInfo")]
pub struct KeyShare {
    share: ecdsa_mpc::ecdsa::keygen::MultiPartyInfo,
    i: u16,
    min_signers: u16,
    n: u16,
}

impl KeyShare {
    /// Returns index of local party that was used at keygen
    pub fn local_party_index(&self) -> u16 {
        self.i
    }

    /// Returns number of parties holding shares for this key
    pub fn parties_number(&self) -> u16 {
        self.n
    }

    /// Returns minimum number of parties required to perform
    /// signing
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Returns public key of generated distributed key
    pub fn public_key(&self) -> secp256k1::PublicKey {
        self.share.public_key.get_element()
    }
}

impl ops::Deref for KeyShare {
    type Target = ecdsa_mpc::ecdsa::keygen::MultiPartyInfo;

    fn deref(&self) -> &Self::Target {
        &self.share
    }
}

impl TryFrom<ecdsa_mpc::ecdsa::keygen::MultiPartyInfo> for KeyShare {
    type Error = IncorrectKeyShare;

    fn try_from(share: MultiPartyInfo) -> Result<Self, Self::Error> {
        let i =
            party_index_to_u16(&share.own_party_index).ok_or(IncorrectKeyShare::TooLargeIndex {
                i: share.own_party_index,
            })?;
        let min_signers = share.key_params.signers().try_into().map_err(|_| {
            IncorrectKeyShare::TooLargeThreshold {
                min_signers: share.key_params.signers(),
            }
        })?;
        let n = share.key_params.share_count().try_into().map_err(|_| {
            IncorrectKeyShare::TooLargeNumberOfParties {
                n: share.key_params.share_count(),
            }
        })?;
        Ok(Self {
            i,
            min_signers,
            n,
            share,
        })
    }
}

impl From<KeyShare> for ecdsa_mpc::ecdsa::keygen::MultiPartyInfo {
    fn from(KeyShare { share, .. }: KeyShare) -> Self {
        share
    }
}

/// Explains why [`KeyShare`] appears to be invalid
#[derive(Debug, Error)]
pub enum IncorrectKeyShare {
    #[error("local party index is too large (it must fit into u16): {i}")]
    TooLargeIndex { i: PartyIndex },
    #[error("number of parties is too large (it must fit into u16): {n}")]
    TooLargeNumberOfParties { n: usize },
    #[error("threshold is too large (it must fit into u16): {min_signers}")]
    TooLargeThreshold { min_signers: usize },
}

#[derive(Debug, Error)]
pub enum InvalidKeygenParameters {
    #[error("too small number of parties n={n} (required at least 2)")]
    TooFewParties { n: u16 },
    #[error(
        "incorrect threshold min_signers={min_signers}: must be positive, less or equal to n={n}"
    )]
    IncorrectThreshold { min_signers: u16, n: u16 },
    #[error("index of local party i={i} should be less than number of parties n={n}")]
    IncorrectPartyIndex { i: u16, n: u16 },
}

#[derive(Debug, Error)]
pub enum KeygenError<IErr, OErr> {
    #[error("construct keygen initial state")]
    ConstructPhase1(#[source] keygen::KeygenError),
    #[error(transparent)]
    ProtocolExecution(#[from] generic::Error<keygen::ErrorState, IErr, OErr>),
    #[error("bug occurred")]
    Bug(#[source] Bug),
}

#[derive(Debug, Error)]
pub enum SigningError<IErr, OErr> {
    #[error("construct signing initial state")]
    ConstructPhase1(#[source] signing::SigningError),
    #[error(transparent)]
    ProtocolExecution(#[from] generic::Error<signing::ErrorState, IErr, OErr>),
    #[error("resulting signature is not valid")]
    ResultSignatureNotValid(#[source] secp256k1::Error),
    #[error("bug occurred")]
    Bug(#[source] Bug),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Bug(BugReason);

#[derive(Debug, Error)]
enum BugReason {
    #[error("list of parties should be sorted by construction")]
    PartiesListNotSorted,
    #[error("keygen parameters are invalid, though we verified their correctness")]
    InvalidParameters(#[source] keygen::KeygenError),
    #[error("key share appear to be incorrect though it must be validated at this point")]
    IncorrectKeyShare(IncorrectKeyShare),
    #[error("party index overflows u16 though we checked its correctness")]
    PartyIndexOverflowsU16,
}

impl<IErr, OErr> From<BugReason> for KeygenError<IErr, OErr> {
    fn from(bug: BugReason) -> Self {
        KeygenError::Bug(Bug(bug))
    }
}

impl<IErr, OErr> From<BugReason> for SigningError<IErr, OErr> {
    fn from(bug: BugReason) -> Self {
        SigningError::Bug(Bug(bug))
    }
}

impl From<BugReason> for InvalidSigningParameters {
    fn from(bug: BugReason) -> Self {
        InvalidSigningParameters::Bug(Bug(bug))
    }
}

fn party_index_from_u16(index: u16) -> PartyIndex {
    let mut index_bytes = [0u8; 32];
    index_bytes[30..].copy_from_slice(&index.to_be_bytes());
    PartyIndex(index_bytes)
}

fn party_index_to_u16(index: &PartyIndex) -> Option<u16> {
    if index.0[..30] != [0u8; 30] {
        return None;
    }
    let index = <[u8; 2]>::try_from(&index.0[30..]).expect("exactly two bytes are given");
    Some(u16::from_be_bytes(index))
}

/// Signing protocol
pub struct Signing {
    local_party_index: u16,
    key_share: KeyShare,
    msg: Message,
    signers: Parties,
    debugging: Option<tracing::Span>,
}

impl Signing {
    /// Prepares signing protocol for signing a `msg`
    ///
    /// Returns error if signing parameters are not consistent, see [InvalidSigningParameters]
    /// for details.
    pub fn new(
        key_share: KeyShare,
        signers: &SortedVec<u16>,
        msg: Message,
    ) -> Result<Self, InvalidSigningParameters> {
        // Check that number of signers is no less than threshold
        if signers.len() < key_share.share.key_params.signers() {
            return Err(InvalidSigningParameters::TooFewSigners {
                signers: signers.len(),
                min_signers: key_share.min_signers(),
            });
        }

        // Check that every party is known
        let unknown_party = signers.iter().find(|i| **i >= key_share.parties_number());
        if let Some(&party_index) = unknown_party {
            return Err(InvalidSigningParameters::UnknownParty { party_index });
        }

        // Check that local party is in list of signers
        let local_party_index = signers
            .binary_search(&key_share.local_party_index())
            .or(Err(InvalidSigningParameters::PartyNotInSignersList))?;
        let local_party_index = local_party_index
            .try_into()
            .or(Err(BugReason::PartyIndexOverflowsU16))?;

        // Construct list of signers (for ing code)
        let signers = signers
            .iter()
            .map(|i| party_index_from_u16(*i))
            .collect::<Vec<_>>();
        let signers = Parties::try_from(signers).or(Err(BugReason::PartiesListNotSorted))?;

        Ok(Self {
            local_party_index,
            key_share,
            msg,
            signers,
            debugging: None,
        })
    }

    /// Enables logging
    ///
    /// All the logs will be spanned with given `span`
    pub fn enable_logs(mut self, span: tracing::Span) -> Self {
        self.debugging = Some(span);
        self
    }

    /// Carries out threshold signing
    pub async fn run<M>(
        self,
        party: M,
    ) -> Result<secp256k1::Signature, SigningError<M::ReceiveError, M::SendError>>
    where
        M: Mpc<ProtocolMessage = SigningMsg>,
    {
        let i = self.local_party_index();
        let pk = self.key_share.public_key;

        let initial_state = signing::Phase1::new(
            self.msg.0,
            self.key_share.share,
            self.signers.as_slice(),
            None,
        )
        .map_err(SigningError::ConstructPhase1)?;

        let signature = if let Some(span) = self.debugging {
            generic::execute_ing_protocol(
                party,
                Debugging::new(initial_state).set_span(span),
                i,
                self.signers,
            )
            .await?
        } else {
            generic::execute_ing_protocol(party, initial_state, i, self.signers).await?
        };

        let signature = ecdsa_mpc::ecdsa::Signature {
            r: signature.r,
            s: signature.s,
        };
        debug_assert!(signature.verify(&pk, &self.msg.0));

        let mut signature_bytes = [0u8; 64];
        signature_bytes[..32].copy_from_slice(&signature.r.get_element()[..]);
        signature_bytes[32..].copy_from_slice(&signature.s.get_element()[..]);

        let mut signature = secp256k1::Signature::from_compact(&signature_bytes)
            .map_err(SigningError::ResultSignatureNotValid)?;
        signature.normalize_s();

        Ok(signature)
    }

    /// Returns index of local party in the signing protocol
    ///
    /// Party's index in signing protocol is position of that party in list of signers.
    pub fn local_party_index(&self) -> u16 {
        self.local_party_index
    }
}

/// A (hashed) message input to an ECDSA signature
#[derive(Clone, Copy)]
pub struct Message(curv_kzen::FE);

impl Message {
    /// Constructs a message from `hash` output
    ///
    /// `hash` output will be mapped into secp256k1 scalar by converting it into
    /// big integer and taking modulo curve order. If you want to convert
    /// message into scalar manually, use [`Message::from_scalar`].
    pub fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U32>,
    {
        Self::from_32_bytes(&hash.finalize().into())
    }

    /// Constructs a message from hash output of 32 bytes length
    ///
    /// These 32 bytes **must be** an output of cryptographic hash function like sha256
    pub fn from_32_bytes(hash_output: &[u8; 32]) -> Self {
        let scalar = curv_kzen::BigInt::from(hash_output.as_slice());
        let scalar = <curv_kzen::FE as ECScalar<_>>::from(&scalar);
        Self::from_scalar(scalar)
    }

    /// Takes secp256k1 scalar that represents a hashed message
    pub fn from_scalar(scalar: curv_kzen::FE) -> Self {
        Self(scalar)
    }
}

/// Signing parameters are not consistent
#[derive(Debug, Error)]
pub enum InvalidSigningParameters {
    /// Number of signers is less than required threshold
    #[error("number of signers ({signers}) is less than required threshold ({min_signers})")]
    TooFewSigners { signers: usize, min_signers: u16 },
    /// Party listed in signers did not participate in key generation
    #[error(
        "party {party_index} didn't take part in key generation, but appears in list of signers"
    )]
    UnknownParty { party_index: u16 },
    /// Local party is not in the list of signers
    #[error("local party is not in the list of signers")]
    PartyNotInSignersList,
    #[error("bug occurred")]
    Bug(#[source] Bug),
}

struct InMemorySecretStorage(InitialKeys);

impl SecretKeyLoader for InMemorySecretStorage {
    fn get_initial_secret(&self) -> Result<Box<InitialSecret>, SecretKeyLoaderError> {
        Ok(Box::new(self.0.u_i))
    }

    fn get_paillier_secret(&self) -> Result<Box<DecryptionKey>, SecretKeyLoaderError> {
        Ok(Box::new(self.0.paillier_keys.dk.clone()))
    }
}

impl fmt::Debug for InMemorySecretStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InMemorySecretStorage")
    }
}
