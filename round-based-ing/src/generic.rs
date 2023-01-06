use std::fmt;

use round_based::{Delivery, Incoming, MessageDestination, Mpc, MpcParty, Outgoing};

use ecdsa_mpc::protocol::{Address, InputMessage, OutputMessage, PartyIndex};
use ecdsa_mpc::state_machine::{self, State, Transition};

use drain_filter_polyfill::VecExt;
use futures::{SinkExt, StreamExt};
use thiserror::Error;
use tracing::{error, trace, trace_span, warn};

pub async fn execute_ing_protocol<S, T, M>(
    protocol_name: &'static str,
    party: M,
    initial_state: S,
    party_index: round_based::PartyIndex,
    parties: Parties,
) -> Result<T::FinalState, Error<T::ErrorState, M::ReceiveError, M::SendError>>
where
    S: State<T> + Send,
    T: StateMachineTraits,
    T::ErrorState: fmt::Debug,
    M: Mpc<ProtocolMessage = T::Msg>,
    T::Msg: MessageRound,
{
    let span = trace_span!("MPC protocol execution", protocol = %protocol_name, i = party_index);
    trace!(parent: &span, "Starting the protocol");

    let MpcParty { delivery, .. } = party.into_party();
    let (mut incomings, mut outgoings) = delivery.split();

    let mut state: Box<dyn State<T> + Send> = Box::new(initial_state);
    let mut out_of_order_messages: Vec<Incoming<T::Msg>> = vec![];

    for round_i in 1u16.. {
        trace!(parent: &span, i = round_i, "Proceeding to round `i`");

        if let Some(msgs_to_send) = state.start() {
            for msg in msgs_to_send {
                let msg = match convert_output_message_to_outgoing(&parties, msg) {
                    Ok(m) => m,
                    Err(UnknownDestination { recipient }) => {
                        warn!(
                            parent: &span,
                            ?recipient,
                            "Protocol wants to send message to the party that doesn't take part in computation. Ignore that message."
                        );
                        continue;
                    }
                };
                if msg.recipient == MessageDestination::OneParty(party_index) {
                    warn!(
                        parent: &span,
                        "Protocol wants to send message to itself. Ignore that message."
                    );
                    continue;
                }
                trace!(
                    parent: &span,
                    recipient = ?msg.recipient,
                    "Sending message to `recipient`"
                );
                outgoings.feed(msg).await.map_err(Error::SendMessage)?;
            }
            outgoings.flush().await.map_err(Error::SendMessage)?;
        }

        let mut out_of_order_messages_for_this_round = out_of_order_messages
            .drain_filter(|incoming| incoming.msg.round() == round_i)
            .collect::<Vec<_>>();
        out_of_order_messages_for_this_round.reverse();

        let mut received_msgs = vec![];
        while !state.is_input_complete(&received_msgs) {
            let incoming = if let Some(msg) = out_of_order_messages_for_this_round.pop() {
                trace!(parent: &span, "Retrieved out of order message");
                msg
            } else {
                incomings
                    .next()
                    .await
                    .ok_or(Error::UnexpectedEof)?
                    .map_err(Error::ReceiveNextMessage)?
            };
            let sender = incoming.sender;

            trace!(
                parent: &span,
                sender = incoming.sender,
                is_broadcast = incoming.is_broadcast(),
                message_round = incoming.msg.round(),
                "Received message from `sender`"
            );

            if sender == party_index {
                trace!(
                    parent: &span,
                    "Message was sent by this party - ignoring it"
                );
                continue;
            }
            if incoming.msg.round() < round_i {
                warn!(
                    parent: &span,
                    "Received message from previous round. Ignore that message."
                );
                continue;
            }
            if incoming.msg.round() > round_i {
                trace!(
                    parent: &span,
                    "Received out of order message, save it to process later"
                );
                out_of_order_messages.push(incoming);
                continue;
            }

            let msg = convert_incoming_to_input_message(&parties, incoming)?;
            if !state.is_message_expected(&msg, &received_msgs) {
                error!(
                    parent: &span,
                    "State machine reported that message was not expected, aborting"
                );
                return Err(Error::ReceivedUnexpectedMessage { sender });
            }
            received_msgs.push(msg);
        }

        match state.consume(received_msgs) {
            Transition::NewState(new_state) => {
                state = new_state;
                continue;
            }
            Transition::FinalState(Ok(output)) => {
                trace!(parent: &span, "Protocol terminated successfully");
                return Ok(output);
            }
            Transition::FinalState(Err(err)) => {
                error!(parent: &span, ?err, "Protocol terminated with error");
                return Err(Error::ProtocolError(err));
            }
        }
    }

    Err(BugReason::NoResult)?
}

fn convert_output_message_to_outgoing<M>(
    parties: &Parties,
    msg: OutputMessage<M>,
) -> Result<Outgoing<M>, UnknownDestination> {
    let recipient = match msg.recipient {
        Address::Peer(index) => {
            let index = parties
                .find(&index)
                .ok_or(UnknownDestination { recipient: index })?;
            MessageDestination::OneParty(index)
        }
        Address::Broadcast => MessageDestination::AllParties,
    };

    Ok(Outgoing {
        recipient,
        msg: msg.body,
    })
}

fn convert_incoming_to_input_message<M>(
    parties: &Parties,
    incoming: Incoming<M>,
) -> Result<InputMessage<M>, UnknownSender> {
    Ok(InputMessage {
        sender: *parties.get(incoming.sender).ok_or(UnknownSender {
            sender: incoming.sender,
        })?,
        body: incoming.msg,
    })
}

#[derive(Debug, Error)]
pub enum Error<PErr, IErr, OErr> {
    #[error("protocol terminated with error: {0:?}")]
    ProtocolError(PErr),
    #[error("receiving next message resulted into error")]
    ReceiveNextMessage(#[source] IErr),
    #[error("received unexpected message from party {sender}")]
    ReceivedUnexpectedMessage { sender: round_based::PartyIndex },
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("cannot send a message")]
    SendMessage(#[source] OErr),
    #[error(transparent)]
    UnknownSender(#[from] UnknownSender),
    #[error("bug occurred")]
    Bug(#[source] Bug),
}

#[derive(Debug, Error)]
#[error("protocol message is addressed to unknown party: {recipient:?}")]
struct UnknownDestination {
    recipient: PartyIndex,
}

#[derive(Debug, Error)]
#[error("received message from unknown party {sender}")]
pub struct UnknownSender {
    sender: round_based::PartyIndex,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Bug(BugReason);

#[derive(Debug, Error)]
enum BugReason {
    #[error("for loop yielded no result")]
    NoResult,
}

impl<PErr, IErr, OErr> From<BugReason> for Error<PErr, IErr, OErr> {
    fn from(err: BugReason) -> Self {
        Error::Bug(Bug(err))
    }
}

/// Extension of [`StateMachineTraits`](ecdsa_mpc::state_machine::StateMachineTraits)
///
/// Ensures that input message is of type [`InputMessage<Msg>`], and output message is [`OutputMessage<Msg>`]
///
/// [`InputMessage<Msg>`]: ecdsa_mpc::protocol::InputMessage
/// [`OutputMessage<Msg>`]: ecdsa_mpc::protocol::OutputMessage
pub trait StateMachineTraits:
    state_machine::StateMachineTraits<
    InMsg = InputMessage<<Self as StateMachineTraits>::Msg>,
    OutMsg = OutputMessage<<Self as StateMachineTraits>::Msg>,
>
{
    type Msg;
}

impl<T, M> StateMachineTraits for T
where
    T: state_machine::StateMachineTraits<InMsg = InputMessage<M>, OutMsg = OutputMessage<M>>,
{
    type Msg = M;
}

/// List of parties taking part in computation
///
/// Wraps `list` of parties, such as:
/// * `list.len()` is number of parties taking part in computation (must fit into [u16])
/// * `list[i]` corresponds to [`PartyIndex`] of i-th party
/// * Indexes in the `list` must appear in ascending order
#[derive(Debug, Clone)]
pub struct Parties(Vec<PartyIndex>);

impl Parties {
    /// Number of parties taking part in computation
    #[allow(dead_code)]
    pub fn len(&self) -> u16 {
        self.0
            .len()
            .try_into()
            .expect("len is guaranteed to fit into u16")
    }

    /// Finds position of `party_index` in the list
    pub fn find(&self, party_index: &PartyIndex) -> Option<u16> {
        self.0
            .binary_search(party_index)
            .ok()
            .map(|pos| pos.try_into().expect("index is guaranteed to fit into u16"))
    }

    /// Retrieves party index corresponding to i-th party
    pub fn get(&self, index: u16) -> Option<&PartyIndex> {
        self.0.get(usize::from(index))
    }

    /// Returns wrapped list of parties indexes
    pub fn as_slice(&self) -> &[PartyIndex] {
        &self.0
    }
}

impl TryFrom<Vec<PartyIndex>> for Parties {
    type Error = InvalidPartiesList;

    fn try_from(list: Vec<PartyIndex>) -> Result<Self, Self::Error> {
        if !is_strictly_sorted(&list) {
            Err(InvalidPartiesList::NotSorted)
        } else if u16::try_from(list.len()).is_err() {
            Err(InvalidPartiesList::TooLarge)
        } else {
            Ok(Self(list))
        }
    }
}

fn is_strictly_sorted<T: Ord>(list: &[T]) -> bool {
    for window in list.windows(2) {
        if !(window[0] < window[1]) {
            return false;
        }
    }
    true
}

#[derive(Debug, Error)]
pub enum InvalidPartiesList {
    #[error("list of parties is not in ascending order")]
    NotSorted,
    #[error("list of parties too large: it must fit into u16")]
    TooLarge,
}

pub trait MessageRound {
    fn round(&self) -> u16;
}

impl MessageRound for ecdsa_mpc::ecdsa::messages::keygen::Message {
    fn round(&self) -> u16 {
        match self {
            Self::R1(..) => 1,
            Self::R2(..) => 2,
            Self::R3(..) => 3,
            Self::R4(..) => 4,
        }
    }
}

impl MessageRound for ecdsa_mpc::ecdsa::messages::signing::Message {
    fn round(&self) -> u16 {
        match self {
            Self::R1(..) => 1,
            Self::R2(..) => 2,
            Self::R2b(..) => 3,
            Self::R3(..) => 4,
            Self::R4(..) => 5,
            Self::R5(..) => 6,
            Self::R6(..) => 7,
            Self::R7(..) => 8,
            Self::R8(..) => 9,
            Self::R9(..) => 10,
        }
    }
}

/// Encodes party index `i: u16` in [`PartyIndex`]
///
/// Party index is an unique identifier of the party that we use to determine message origin/destination.
/// ING lib uses 32 bytes identifier, which is by design should be party public identity. However,
/// `round-based` lib uses different approach: we identify parties with party index `i` (`0 <= i < n` where
/// `n` is number of parties).
///
/// For that purposes, we provide conversion functions: [party_index_from_u16] encodes party index `i: u16`
/// in ING [`PartyIndex`], and [party_index_to_u16] decodes party index `i: u16` from ING [`PartyIndex`].
pub fn party_index_from_u16(index: round_based::PartyIndex) -> PartyIndex {
    let mut index_bytes = [0u8; 32];
    index_bytes[30..].copy_from_slice(&index.to_be_bytes());
    PartyIndex(index_bytes)
}

/// Decodes party index `i: u16` from [`PartyIndex`]
pub fn party_index_to_u16(index: &PartyIndex) -> Option<round_based::PartyIndex> {
    if index.0[..30] != [0u8; 30] {
        return None;
    }
    let index = <[u8; 2]>::try_from(&index.0[30..]).expect("exactly two bytes are given");
    Some(u16::from_be_bytes(index))
}
