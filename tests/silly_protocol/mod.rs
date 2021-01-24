use std::fmt;
use std::mem::replace;
use std::time::Duration;

use rand::{CryptoRng, RngCore};

use round_based::containers::{
    push::{Push, PushExt},
    *,
};
use round_based::{IsCritical, Msg, StateMachine};

mod rounds;
pub use rounds::{OutputRandomValue, ProceedError};
use rounds::{Round0, Round1, Round2};

pub struct MultiPartyGenRandom {
    round: R,
    msgs1: Option<Store<BroadcastMsgs<rounds::CommittedSeed>>>,
    msgs2: Option<Store<BroadcastMsgs<rounds::RevealedSeed>>>,
    msgs_queue: Vec<Msg<ProtocolMessage>>,

    party_i: u16,
    party_n: u16,
}

impl MultiPartyGenRandom {
    pub fn with_fixed_seed<Rnd: CryptoRng + RngCore>(
        party_i: u16,
        party_n: u16,
        seed: u32,
        rnd: &mut Rnd,
    ) -> Self {
        let mut blinding = [0u8; 32];
        rnd.fill_bytes(&mut blinding[..]);

        Self {
            party_i,
            party_n,
            round: R::Round0(Round0 {
                is_adversary: false,
                my_ind: party_i,
                my_seed: seed,
                blinding,
            }),
            msgs1: Some(Round1::expects_messages(party_i, party_n)),
            msgs2: Some(Round2::expects_messages(party_i, party_n)),
            msgs_queue: vec![],
        }
    }

    /// Adversary doesn't reveal its seed, so he's the only party who learn output.
    pub fn adversary_with_fixed_seed<Rnd: CryptoRng + RngCore>(
        party_i: u16,
        party_n: u16,
        seed: u32,
        rnd: &mut Rnd,
    ) -> Self {
        let mut blinding = [0u8; 32];
        rnd.fill_bytes(&mut blinding[..]);

        Self {
            party_i,
            party_n,
            round: R::Round0(Round0 {
                is_adversary: true,
                my_ind: party_i,
                my_seed: seed,
                blinding,
            }),
            msgs1: Some(Round1::expects_messages(party_i, party_n)),
            msgs2: Some(Round2::expects_messages(party_i, party_n)),
            msgs_queue: vec![],
        }
    }

    fn gmap_queue<'a, T, F>(&'a mut self, mut f: F) -> impl Push<Msg<T>> + 'a
    where
        F: FnMut(T) -> M + 'a,
    {
        (&mut self.msgs_queue).gmap(move |m: Msg<T>| m.map_body(|m| ProtocolMessage(f(m))))
    }

    fn proceed_round(&mut self, may_block: bool) -> Result<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: R;
        let try_again: bool = match replace(&mut self.round, R::Gone) {
            R::Round0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(self.gmap_queue(M::Round1))
                    .map(R::Round1)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round0(_) => {
                next_state = s;
                false
            }
            R::Round1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().expect("store gone before round complete");
                let msgs = store.finish().map_err(Error::HandleMsg)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round2))
                    .map(R::Round2)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round1(_) => {
                next_state = s;
                false
            }
            R::Round2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().expect("store gone before round complete");
                let msgs = store.finish().map_err(Error::HandleMsg)?;
                next_state = round
                    .proceed(msgs)
                    .map(R::Finished)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ R::Round2(_) => {
                next_state = s;
                false
            }
            s @ R::Finished(_) | s @ R::Gone => {
                next_state = s;
                false
            }
        };

        self.round = next_state;
        if try_again {
            self.proceed_round(may_block)
        } else {
            Ok(())
        }
    }
}

impl StateMachine for MultiPartyGenRandom {
    type MessageBody = ProtocolMessage;
    type Err = Error;
    type Output = OutputRandomValue;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<()> {
        let current_round = self.current_round();
        match msg.body {
            ProtocolMessage(M::Round1(m)) => {
                let store = self.msgs1.as_mut().ok_or(Error::OutOfOrderMsg {
                    current_round,
                    msg_round: 1,
                })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMsg)?;
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round2(m)) => {
                let store = self.msgs2.as_mut().ok_or(Error::OutOfOrderMsg {
                    current_round,
                    msg_round: 1,
                })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMsg)?;
                self.proceed_round(false)
            }
        }
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match self.round {
            R::Round0(_) => true,
            R::Round1(_) => !store1_wants_more,
            R::Round2(_) => !store2_wants_more,
            R::Finished(_) | R::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<()> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        if matches!(self.round, R::Round2(_)) {
            Some(Duration::from_secs(5))
        } else {
            None
        }
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        if !matches!(self.round, R::Round2(_)) {
            panic!("no timeout was set")
        }
        let (_, parties) = self
            .msgs2
            .as_ref()
            .expect("store is gone, but round is not over yet")
            .blame();
        Error::ProceedRound(ProceedError::PartiesDidntRevealItsSeed { party_ind: parties })
    }

    fn is_finished(&self) -> bool {
        matches!(self.round, R::Finished(_))
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output>> {
        match self.round {
            R::Finished(_) => (),
            R::Gone => return Some(Err(Error::DoublePickResult)),
            _ => return None,
        }

        match replace(&mut self.round, R::Gone) {
            R::Finished(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match self.round {
            R::Round0(_) => 0,
            R::Round1(_) => 1,
            R::Round2(_) => 2,
            R::Finished(_) | R::Gone => 3,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(2)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}

impl fmt::Debug for MultiPartyGenRandom {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let current_round = match &self.round {
            R::Round0(_) => "0",
            R::Round1(_) => "1",
            R::Round2(_) => "2",
            R::Finished(_) => "[Finished]",
            R::Gone => "[Gone]",
        };
        let msgs1 = match self.msgs1.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs2 = match self.msgs2.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        write!(
            f,
            "{{MPCRandom at round={} msgs1={} msgs2={} queue=[len={}]}}",
            current_round,
            msgs1,
            msgs2,
            self.msgs_queue.len()
        )
    }
}

// Rounds

pub enum R {
    Round0(Round0),
    Round1(Round1),
    Round2(Round2),
    Finished(OutputRandomValue),
    Gone,
}

// Messages

/// Protocol message
///
/// Hides message structure so it could be changed without breaking semver policy.
#[derive(Clone, Debug)]
pub struct ProtocolMessage(M);

#[derive(Clone, Debug)]
enum M {
    Round1(rounds::CommittedSeed),
    Round2(rounds::RevealedSeed),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Protocol error caught at proceeding round
    ProceedRound(ProceedError),
    /// Received message didn't pass pre-validation
    HandleMsg(StoreErr),
    /// Received message which we didn't expect to receive (e.g. message from previous round)
    OutOfOrderMsg { current_round: u16, msg_round: u16 },
    /// [SillyProtocol::pick_output] called twice
    DoublePickResult,
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        // Protocol is not resistant to occurring any of errors :(
        true
    }
}
