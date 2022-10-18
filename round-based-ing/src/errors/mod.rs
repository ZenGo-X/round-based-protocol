use ecdsa_mpc::{
    ecdsa::{keygen, signature as signing},
    protocol::PartyIndex,
};
use thiserror::Error;

use crate::generic;

/// Explains why [`KeyShare`](crate::KeyShare) appears to be invalid
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
        "incorrect threshold: must be 1 < min_signers <= n (min_signers={min_signers}, n={n})"
    )]
    IncorrectThreshold { min_signers: u16, n: u16 },
    #[error("index of local party i={i} should be less than number of parties n={n}")]
    IncorrectPartyIndex { i: round_based::PartyIndex, n: u16 },
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
pub(crate) enum BugReason {
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
    UnknownParty {
        party_index: round_based::PartyIndex,
    },
    /// Local party is not in the list of signers
    #[error("local party is not in the list of signers")]
    PartyNotInSignersList,
    #[error("bug occurred")]
    Bug(#[source] Bug),
}
