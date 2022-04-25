use std::convert::Infallible;

use futures::{sink, stream, Sink, Stream};
use hex_literal::hex;
use matches::assert_matches;
use rand::SeedableRng;

use random_generation_protocol::{
    protocol_of_random_generation, CommitMsg, DecommitMsg, Error, Msg,
};
use round_based::rounds::{CompleteRoundError, RoundInput, Rounds};
use round_based::{Delivery, Incoming, MpcParty, Outgoing};

const PARTY0_SEED: [u8; 32] =
    hex!("6772d079d5c984b3936a291e36b0d3dc6c474e36ed4afdfc973ef79a431ca870");
const PARTY1_COMMITMENT: [u8; 32] =
    hex!("2a8c585d9a80cb78bc226f4ab35a75c8e5834ff77a83f41cf6c893ea0f3b2aed");
const PARTY1_RANDOMNESS: [u8; 32] =
    hex!("12a595f4893fdb4ab9cc38caeec5f7456acb3002ca58457c5056977ce59136a6");
const PARTY2_COMMITMENT: [u8; 32] =
    hex!("01274ef40aece8aa039587cc05620a19b80a5c93fbfb24a9f8e1b77b7936e47d");
const PARTY2_RANDOMNESS: [u8; 32] =
    hex!("6fc78a926c7eebfad4e98e796cd53b771ac5947b460567c7ea441abb957c89c7");
const PROTOCOL_OUTPUT: [u8; 32] =
    hex!("689a9f02229bdb36521275179676641585c4a3ce7b80ace37f0272a65e89a1c3");
const PARTY_OVERWRITES: [u8; 32] =
    hex!("00aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff66778899");

#[tokio::test]
async fn random_generation_completes() {
    let output = run_protocol([
        Ok::<_, Infallible>(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY2_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY1_RANDOMNESS,
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY2_RANDOMNESS,
            }),
        }),
    ])
    .await
    .unwrap();

    assert_eq!(output, PROTOCOL_OUTPUT);
}

#[tokio::test]
async fn protocol_terminates_with_error_if_party_tries_to_overwrite_message_at_round1() {
    let output = run_protocol([
        Ok::<_, Infallible>(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY_OVERWRITES.into(),
            }),
        }),
    ])
    .await;

    assert_matches!(
        output,
        Err(Error::Round1Receive(CompleteRoundError::ProcessMessage(_)))
    )
}

#[tokio::test]
async fn protocol_terminates_with_error_if_party_tries_to_overwrite_message_at_round2() {
    let output = run_protocol([
        Ok::<_, Infallible>(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY2_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY1_RANDOMNESS,
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY_OVERWRITES,
            }),
        }),
    ])
    .await;

    assert_matches!(
        output,
        Err(Error::Round2Receive(CompleteRoundError::ProcessMessage(_)))
    )
}

#[tokio::test]
async fn protocol_terminates_if_received_message_from_unknown_sender_at_round1() {
    let output = run_protocol([Ok::<_, Infallible>(Incoming {
        sender: 3,
        msg: Msg::CommitMsg(CommitMsg {
            commitment: PARTY1_COMMITMENT.into(),
        }),
    })])
    .await;

    assert_matches!(
        output,
        Err(Error::Round1Receive(CompleteRoundError::ProcessMessage(_)))
    )
}

#[tokio::test]
async fn protocol_ignores_message_that_goes_to_completed_round() {
    let output = run_protocol([
        Ok::<_, Infallible>(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY2_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY_OVERWRITES.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY1_RANDOMNESS,
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY2_RANDOMNESS,
            }),
        }),
    ])
    .await
    .unwrap();

    assert_eq!(output, PROTOCOL_OUTPUT);
}

#[tokio::test]
async fn protocol_ignores_io_error_if_it_is_completed() {
    let output = run_protocol([
        Ok(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY2_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY1_RANDOMNESS,
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY2_RANDOMNESS,
            }),
        }),
        Err(DummyError),
    ])
    .await
    .unwrap();

    assert_eq!(output, PROTOCOL_OUTPUT);
}

#[tokio::test]
async fn protocol_terminates_with_error_if_io_error_happens_at_round2() {
    let output = run_protocol([
        Ok(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY2_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY1_RANDOMNESS,
            }),
        }),
        Err(DummyError),
        Ok(Incoming {
            sender: 2,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY2_RANDOMNESS,
            }),
        }),
    ])
    .await;

    assert_matches!(output, Err(Error::Round2Receive(CompleteRoundError::Io(_))));
}

#[tokio::test]
async fn protocol_terminates_with_error_if_io_error_happens_at_round1() {
    let output = run_protocol([
        Err(DummyError),
        Ok(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY2_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY1_RANDOMNESS,
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY2_RANDOMNESS,
            }),
        }),
    ])
    .await;

    assert_matches!(output, Err(Error::Round1Receive(CompleteRoundError::Io(_))));
}

#[tokio::test]
async fn protocol_terminates_with_error_if_unexpected_eof_happens_at_round2() {
    let output = run_protocol([
        Ok::<_, Infallible>(Incoming {
            sender: 1,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY1_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 2,
            msg: Msg::CommitMsg(CommitMsg {
                commitment: PARTY2_COMMITMENT.into(),
            }),
        }),
        Ok(Incoming {
            sender: 1,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: PARTY1_RANDOMNESS,
            }),
        }),
    ])
    .await;

    assert_matches!(
        output,
        Err(Error::Round2Receive(CompleteRoundError::UnexpectedEof))
    );
}

#[tokio::test]
async fn all_non_completed_rounds_are_terminated_with_unexpected_eof_error_if_incoming_channel_suddenly_closed(
) {
    let mut rounds = Rounds::builder();
    let round1 = rounds.add_round(RoundInput::<CommitMsg>::new(0, 3));
    let round2 = rounds.add_round(RoundInput::<DecommitMsg>::new(0, 3));
    let mut rounds = rounds.listen(stream::empty::<Result<Incoming<Msg>, Infallible>>());

    assert_matches!(
        rounds.complete(round1).await,
        Err(CompleteRoundError::UnexpectedEof)
    );
    assert_matches!(
        rounds.complete(round2).await,
        Err(CompleteRoundError::UnexpectedEof)
    );
}

async fn run_protocol<E, I>(incomings: I) -> Result<[u8; 32], Error<E, Infallible>>
where
    I: IntoIterator<Item = Result<Incoming<Msg>, E>>,
    I::IntoIter: Send + 'static,
    E: std::error::Error + Send + Sync + Unpin + 'static,
{
    let rng = rand_chacha::ChaCha8Rng::from_seed(PARTY0_SEED);

    let party = MpcParty::connected(MockedDelivery::new(stream::iter(incomings), sink::drain()));
    protocol_of_random_generation(party, 0, 3, rng).await
}

struct MockedDelivery<I, O> {
    incoming: I,
    outgoing: O,
}

impl<I, O> MockedDelivery<I, O> {
    pub fn new(incoming: I, outgoing: O) -> Self {
        Self { incoming, outgoing }
    }
}

impl<M, I, O, IErr, OErr> Delivery<M> for MockedDelivery<I, O>
where
    I: Stream<Item = Result<Incoming<M>, IErr>> + Send + Unpin + 'static,
    O: Sink<Outgoing<M>, Error = OErr> + Send + Unpin,
    IErr: std::error::Error + Send + 'static,
    OErr: std::error::Error,
{
    type Send = O;
    type Receive = I;
    type SendError = OErr;
    type ReceiveError = IErr;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.incoming, self.outgoing)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("dummy error")]
struct DummyError;
