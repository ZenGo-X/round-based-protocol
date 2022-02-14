use round_based::{Delivery, Incoming, Mpc, MpcParty, Outgoing};

use ecdsa_mpc::protocol::{Address, InputMessage, OutputMessage, PartyIndex};
use ecdsa_mpc::state_machine::{self, State, Transition};

use futures::stream;
use futures::{SinkExt, StreamExt};
use thiserror::Error;

#[cfg(feature = "debugging")]
mod debugging;
#[cfg(feature = "debugging")]
pub use self::debugging::*;

pub async fn execute_ing_protocol<S, T, M>(
    party: M,
    party_index: u16,
    initial_state: S,
) -> Result<T::FinalState, Error<T::ErrorState, M::ReceiveError, M::SendError>>
where
    S: State<T>,
    T: StateMachineTraits,
    M: Mpc<ProtocolMessage = T::Msg>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (mut incomings, mut outgoings) = delivery.split();

    let mut state: Box<dyn State<T>> = Box::new(initial_state);

    loop {
        if let Some(msgs_to_send) = state.start() {
            outgoings
                .send_all(
                    &mut stream::iter(msgs_to_send)
                        .map(convert_output_message_to_outgoing)
                        .map(Ok),
                )
                .await
                .map_err(Error::SendMessage)?;
        }

        let mut received_msgs = vec![];
        while !state.is_input_complete(&received_msgs) {
            let incoming = incomings
                .next()
                .await
                .ok_or(Error::UnexpectedEof)?
                .map_err(Error::ReceiveNextMessage)?;
            let sender = incoming.sender;
            if sender == party_index {
                // Ignore own messages
                continue;
            }

            let msg = convert_incoming_to_input_message(incoming);
            if !state.is_message_expected(&msg, &received_msgs) {
                return Err(Error::ReceivedUnexpectedMessage {
                    sender: party_index_to_u16(msg.sender),
                });
            }
            received_msgs.push(msg);
        }

        match state.consume(received_msgs) {
            Transition::NewState(new_state) => {
                state = new_state;
                continue;
            }
            Transition::FinalState(Ok(output)) => return Ok(output),
            Transition::FinalState(Err(err)) => return Err(Error::ProtocolError(err)),
        }
    }
}

/// Converts ING's [`PartyIndex`] into `u16` index that can be used in round based
///
/// `index` is assumed to be output of [`party_index_from_u16`], otherwise returning value of this
/// function is not defined.
pub fn party_index_to_u16(index: PartyIndex) -> u16 {
    let index = <[u8; 2]>::try_from(&index.0[30..]).expect("exactly two bytes are given");
    u16::from_be_bytes(index)
}

/// Converts `u16` party index into ING's [`PartyIndex`]
///
/// Every `u16` index corresponds to a unique `PartyIndex`. Speaking mathematically,
/// `∀ i,j: i = j ⟷ party_index_from_u16(i) = party_index_from_u16(j)`
pub fn party_index_from_u16(index: u16) -> PartyIndex {
    let mut index_bytes = [0u8; 32];
    index_bytes[30..].copy_from_slice(&index.to_be_bytes());
    PartyIndex(index_bytes)
}

fn convert_output_message_to_outgoing<M>(msg: OutputMessage<M>) -> Outgoing<M> {
    let recipient = match msg.recipient {
        Address::Peer(index) => Some(party_index_to_u16(index)),
        Address::Broadcast => None,
    };

    Outgoing {
        recipient,
        msg: msg.body,
    }
}

fn convert_incoming_to_input_message<M>(incoming: Incoming<M>) -> InputMessage<M> {
    InputMessage {
        sender: party_index_from_u16(incoming.sender),
        body: incoming.msg,
    }
}

#[derive(Debug, Error)]
pub enum Error<PErr, IErr, OErr> {
    #[error("protocol terminated with error: {0:?}")]
    ProtocolError(PErr),
    #[error("receiving next message resulted into error")]
    ReceiveNextMessage(#[source] IErr),
    #[error("received unexpected message from party {sender}")]
    ReceivedUnexpectedMessage { sender: u16 },
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("cannot send a message")]
    SendMessage(#[source] OErr),
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
