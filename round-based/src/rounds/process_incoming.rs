use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::{Fuse, FutureExt};
use futures::{ready, TryStream, TryStreamExt};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::delivery::Incoming;
use crate::rounds::{MessagesStore, ProtocolMessage, ReceiveError, RoundMessage, SupersedingStore};

pub struct ProtocolIncoming<M, E> {
    rounds: HashMap<u16, StoreInput<M, E>>,
}

impl<M, E> ProtocolIncoming<M, E>
where
    M: ProtocolMessage,
{
    pub fn new(rounds: HashMap<u16, StoreInput<M, E>>) -> Self {
        Self { rounds }
    }

    pub async fn start_processing<I>(mut self, mut incoming: I)
    where
        I: TryStream<Ok = Incoming<M>, Error = E> + Unpin,
    {
        loop {
            match incoming.try_next().await {
                Ok(Some(m)) => self.received_msg(m).await,
                Ok(None) => {
                    self.channel_closed().await;
                    return;
                }
                Err(e) => {
                    self.channel_broken(e).await;
                    return;
                }
            }
        }
    }

    async fn channel_broken(&mut self, error: E) {
        let mut error = Some(error);
        for (_, round) in &mut self.rounds {
            if round.flag.is_awaiting() {
                let _ = round.events.send(RoundEvent::Error(error.take())).await;
            } else {
                let _ = round.events.send(RoundEvent::Error(None)).await;
            }
        }
    }

    async fn channel_closed(&mut self) {
        for (_, round) in &mut self.rounds {
            let _ = round.events.send(RoundEvent::Eof).await;
        }
    }

    async fn received_msg(&mut self, msg: Incoming<M>) {
        let round = match self.rounds.get_mut(&msg.msg.variant_id()) {
            Some(r) => r,
            None => {
                // todo: log that round is not registered
                return;
            }
        };
        if let Err(_) = round.events.send(RoundEvent::Msg(msg)).await {
            // todo: log that round is dropped
        }
    }
}

pub struct RoundIncoming<P, S, E>
where
    P: ProtocolMessage + RoundMessage<S::Msg>,
    S: MessagesStore,
{
    store: S,
    events: mpsc::Receiver<RoundEvent<P, E>>,
    supersede: Fuse<oneshot::Receiver<oneshot::Sender<SupersedeResponse<P, S, E>>>>,
    force_finish: Arc<Notify>,
    output: oneshot::Sender<Result<S::Output, ReceiveError<S::Error, E>>>,
}

impl<P, S, E> RoundIncoming<P, S, E>
where
    P: ProtocolMessage + RoundMessage<S::Msg>,
    S: MessagesStore,
{
    pub fn with_store(
        store: S,
    ) -> (
        Self,
        StoreInput<P, E>,
        StoreOutput<S::Output, S::Error, E>,
        StoreSupersede<P, S, E>,
    ) {
        let (events_send, events_recv) = mpsc::channel(1);
        let (flag1, flag2) = AwaitingFlag::new();
        let (output_send, output_recv) = oneshot::channel();
        let (supersede_send, supersede_recv) = oneshot::channel();
        let force_finish = Arc::new(Notify::new());

        (
            Self {
                store,
                events: events_recv,
                supersede: supersede_recv.fuse(),
                force_finish: force_finish.clone(),
                output: output_send,
            },
            StoreInput {
                events: events_send,
                flag: flag1,
            },
            StoreOutput {
                output: output_recv,
                flag: Some(flag2),
                force_finish,
            },
            StoreSupersede {
                req: supersede_send,
            },
        )
    }

    pub async fn supersede<Q>(
        mut store: S,
        prior_round: StoreSupersede<P, Q, E>,
    ) -> Result<
        (Self, StoreSupersede<P, S, E>),
        SupersedeError<S, <S as SupersedingStore<Q>>::SupersedeError>,
    >
    where
        Q: MessagesStore<Msg = S::Msg, Error = S::Error, Output = S::Output>,
        S: SupersedingStore<Q>,
    {
        let (request, response) = oneshot::channel();
        if let Err(_) = prior_round.req.send(request) {
            // Task is gone. Probably it just finished.
            return Err(SupersedeError::PreviousStoreGone(store));
        }

        let state = match response.await {
            Ok(state) => state,
            Err(_) => {
                // Task is gone. Probably it just finished.
                return Err(SupersedeError::PreviousStoreGone(store));
            }
        };
        store
            .supersede(state.store)
            .map_err(SupersedeError::SupersedingFailed)?;

        let (supersede_send, supersede_recv) = oneshot::channel();
        Ok((
            Self {
                store,
                events: state.events,
                supersede: supersede_recv.fuse(),
                force_finish: state.force_finish,
                output: state.output,
            },
            StoreSupersede {
                req: supersede_send,
            },
        ))
    }

    pub async fn start_processing(mut self) {
        if self.is_finished() {
            self.finish();
            return;
        }
        loop {
            tokio::select! {
                biased;
                // We ignore supersede sender being dropped
                Ok(resp) = &mut self.supersede => {
                    self.supersede_requested(resp).await;
                    return
                }
                event = self.events.recv() => {
                    match event {
                        Some(RoundEvent::Msg(msg)) => {
                            self.received_msg(msg).await;
                            if self.is_finished() {
                                self.finish();
                                return
                            }
                        }
                        Some(RoundEvent::Eof) => {
                            self.channel_closed();
                            return
                        }
                        Some(RoundEvent::Error(error)) => {
                            self.channel_broken(error);
                            return
                        }
                        None => {
                            // todo: log that ProcessProtocolIncoming terminated
                            self.channel_closed();
                            return
                        }
                    }
                }
                // Notified is not completely cancellation safe - cancellation
                // makes us lose a place in the queue. It doesn't matter as there
                // are no other waiters
                () = self.force_finish.notified() => {
                    self.force_finish().await;
                    return
                }
            }
        }
    }

    async fn received_msg(&mut self, msg: Incoming<P>) {
        let round_msg = match msg.msg.into_round_message() {
            Some(msg) => msg,
            None => {
                //todo: log that we received message that is not addressed to us
                // it's a critical error, message is lost
                return;
            }
        };

        if let Err(_e) = self.store.add_message(Incoming {
            sender: msg.sender,
            msg: round_msg,
        }) {
            // todo: log the error
        }
    }

    fn is_finished(&self) -> bool {
        !self.store.wants_more()
    }

    fn finish(self) {
        let _ = match self.store.finish() {
            Ok(m) => self.output.send(Ok(m)),
            Err(store_error) => self.output.send(Err(
                ReceiveError::MessageStoreDidntOutputAfterReceivingEnoughMessages { store_error },
            )),
        };
    }

    fn channel_broken(self, error: Option<E>) {
        match self.store.finish() {
            Ok(out) => {
                let _ = self.output.send(Ok(out));
            }
            Err(store_error) => {
                let _ = self.output.send(Err(ReceiveError::IncomingChannelBroken {
                    receive_error: error,
                    store_error,
                }));
            }
        }
    }

    fn channel_closed(self) {
        match self.store.finish() {
            Ok(out) => {
                let _ = self.output.send(Ok(out));
            }
            Err(store_error) => {
                let _ = self
                    .output
                    .send(Err(ReceiveError::IncomingChannelClosed { store_error }));
            }
        }
    }

    async fn supersede_requested(self, response: oneshot::Sender<SupersedeResponse<P, S, E>>) {
        let _ = response.send(SupersedeResponse {
            store: self.store,
            events: self.events,
            force_finish: self.force_finish,
            output: self.output,
        });
    }

    async fn force_finish(self) {
        match self.store.finish() {
            Ok(out) => {
                let _ = self.output.send(Ok(out));
            }
            Err(store_error) => {
                let _ = self
                    .output
                    .send(Err(ReceiveError::NotEnoughMessages { store_error }));
            }
        }
    }
}

impl<P, S, E> fmt::Debug for RoundIncoming<P, S, E>
where
    P: ProtocolMessage + RoundMessage<S::Msg>,
    S: MessagesStore,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RoundIncoming {{ .. }}")
    }
}

impl<P, S, E> fmt::Debug for StoreSupersede<P, S, E>
where
    P: ProtocolMessage + RoundMessage<S::Msg>,
    S: MessagesStore,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RoundSupersede {{ .. }}")
    }
}

pub struct StoreInput<P, E> {
    events: mpsc::Sender<RoundEvent<P, E>>,
    flag: AwaitingFlag,
}

pub struct StoreOutput<O, SE, IE> {
    output: oneshot::Receiver<Result<O, ReceiveError<SE, IE>>>,
    flag: Option<AwaitingFlag>,
    force_finish: Arc<Notify>,
}

impl<O, SE, IE> StoreOutput<O, SE, IE> {
    pub fn force(&self) {
        self.force_finish.notify_one()
    }
}

impl<O, SE, IE> Future for StoreOutput<O, SE, IE> {
    type Output = Result<O, ReceiveError<SE, IE>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Some(flag) = self.flag.take() {
            flag.set(true)
        }
        match ready!(Pin::new(&mut self.output).poll(cx)) {
            Ok(out) => Poll::Ready(out),
            Err(_) => Poll::Ready(Err(ReceiveError::Gone)),
        }
    }
}

pub struct StoreSupersede<P, S, E>
where
    S: MessagesStore,
    P: ProtocolMessage + RoundMessage<S::Msg>,
{
    req: oneshot::Sender<oneshot::Sender<SupersedeResponse<P, S, E>>>,
}

struct SupersedeResponse<P, S, E>
where
    S: MessagesStore,
    P: ProtocolMessage + RoundMessage<S::Msg>,
{
    store: S,
    events: mpsc::Receiver<RoundEvent<P, E>>,
    force_finish: Arc<Notify>,
    output: oneshot::Sender<Result<S::Output, ReceiveError<S::Error, E>>>,
}

#[derive(Clone, Debug, PartialEq)]
enum RoundEvent<M, E> {
    Msg(Incoming<M>),
    Eof,
    Error(Option<E>),
}

struct AwaitingFlag {
    is_awaiting: Arc<AtomicBool>,
}

impl AwaitingFlag {
    pub fn new() -> (Self, Self) {
        let is_awaiting = Arc::new(AtomicBool::new(false));
        (
            Self {
                is_awaiting: is_awaiting.clone(),
            },
            Self { is_awaiting },
        )
    }

    pub fn is_awaiting(&self) -> bool {
        self.is_awaiting.load(Ordering::Relaxed)
    }

    pub fn set(&self, v: bool) {
        self.is_awaiting.store(v, Ordering::Relaxed)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SupersedeError<S, E> {
    PreviousStoreGone(S),
    SupersedingFailed(E),
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::iter::{self, FromIterator};

    use futures::StreamExt;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;

    use crate::delivery::Incoming;
    use crate::rounds::process_incoming::{
        AwaitingFlag, ProtocolIncoming, RoundEvent, RoundIncoming, StoreInput, SupersedeError,
    };
    use crate::rounds::{
        MessagesStore, ProtocolMessage, ReceiveError, RoundMessage, SupersedingStore,
    };

    #[derive(Debug, Clone, PartialEq)]
    enum TestMsg {
        R1(Round1Msg),
        R2(Round2Msg),
        R3(Round3Msg),
    }
    #[derive(Debug, Clone, PartialEq)]
    struct Round1Msg(u16);
    #[derive(Debug, Clone, PartialEq)]
    struct Round2Msg(u16);
    #[derive(Debug, Clone, PartialEq)]
    struct Round3Msg(u16);

    impl ProtocolMessage for TestMsg {
        fn variant_id(&self) -> u16 {
            match self {
                TestMsg::R1(_) => 0,
                TestMsg::R2(_) => 1,
                TestMsg::R3(_) => 2,
            }
        }
    }
    impl RoundMessage<Round1Msg> for TestMsg {
        const VARIANT_ID: u16 = 0;
        fn into_round_message(self) -> Option<Round1Msg> {
            match self {
                TestMsg::R1(msg) => Some(msg),
                _ => None,
            }
        }
        fn from_round_message(msg: Round1Msg) -> Self {
            Self::R1(msg)
        }
    }
    impl RoundMessage<Round2Msg> for TestMsg {
        const VARIANT_ID: u16 = 1;
        fn into_round_message(self) -> Option<Round2Msg> {
            match self {
                TestMsg::R2(msg) => Some(msg),
                _ => None,
            }
        }
        fn from_round_message(msg: Round2Msg) -> Self {
            Self::R2(msg)
        }
    }
    impl RoundMessage<Round3Msg> for TestMsg {
        const VARIANT_ID: u16 = 2;
        fn into_round_message(self) -> Option<Round3Msg> {
            match self {
                TestMsg::R3(msg) => Some(msg),
                _ => None,
            }
        }
        fn from_round_message(msg: Round3Msg) -> Self {
            Self::R3(msg)
        }
    }

    #[tokio::test]
    async fn protocol_incoming_redirects_messages_to_appropriate_rounds() {
        let (round1_send, round1_recv) = mpsc::channel(5);
        let (round2_send, round2_recv) = mpsc::channel(5);
        let (round3_send, round3_recv) = mpsc::channel(5);

        let (round1_flag1, _round1_flag2) = AwaitingFlag::new();
        let (round2_flag1, _round2_flag2) = AwaitingFlag::new();
        let (round3_flag1, _round3_flag2) = AwaitingFlag::new();

        let round1_input = StoreInput {
            events: round1_send,
            flag: round1_flag1,
        };
        let round2_input = StoreInput {
            events: round2_send,
            flag: round2_flag1,
        };
        let round3_input = StoreInput {
            events: round3_send,
            flag: round3_flag1,
        };

        let msg1 = Incoming {
            sender: 10,
            msg: TestMsg::R1(Round1Msg(1)),
        };
        let msg2 = Incoming {
            sender: 11,
            msg: TestMsg::R2(Round2Msg(2)),
        };
        let msg3 = Incoming {
            sender: 12,
            msg: TestMsg::R3(Round3Msg(3)),
        };
        let msg4 = Incoming {
            sender: 13,
            msg: TestMsg::R2(Round2Msg(4)),
        };
        let msg5 = Incoming {
            sender: 14,
            msg: TestMsg::R1(Round1Msg(5)),
        };
        let msgs = vec![
            Ok::<_, Infallible>(msg1.clone()),
            Ok(msg2.clone()),
            Ok(msg3.clone()),
            Ok(msg4.clone()),
            Ok(msg5.clone()),
        ];

        ProtocolIncoming::new(HashMap::from_iter([
            (0, round1_input),
            (1, round2_input),
            (2, round3_input),
        ]))
        .start_processing(futures::stream::iter(msgs))
        .await;

        let round1_received = ReceiverStream::new(round1_recv).collect::<Vec<_>>().await;
        let round2_received = ReceiverStream::new(round2_recv).collect::<Vec<_>>().await;
        let round3_received = ReceiverStream::new(round3_recv).collect::<Vec<_>>().await;

        let round1_expected = vec![
            RoundEvent::Msg(msg1),
            RoundEvent::Msg(msg5),
            RoundEvent::Eof,
        ];
        let round2_expected = vec![
            RoundEvent::Msg(msg2),
            RoundEvent::Msg(msg4),
            RoundEvent::Eof,
        ];
        let round3_expected = vec![RoundEvent::Msg(msg3), RoundEvent::Eof];

        assert_eq!(round1_received, round1_expected);
        assert_eq!(round2_received, round2_expected);
        assert_eq!(round3_received, round3_expected);
    }

    #[derive(Clone, Debug, PartialEq)]
    struct DummyError(&'static str);

    #[tokio::test]
    async fn process_incoming_redirects_error_to_first_round_that_raised_flag() {
        let (round1_send, round1_recv) = mpsc::channel(5);
        let (round2_send, round2_recv) = mpsc::channel(5);
        let (round3_send, round3_recv) = mpsc::channel(5);

        let (round1_flag1, _round1_flag2) = AwaitingFlag::new();
        let (round2_flag1, round2_flag2) = AwaitingFlag::new();
        let (round3_flag1, _round3_flag2) = AwaitingFlag::new();

        let round1_input = StoreInput {
            events: round1_send,
            flag: round1_flag1,
        };
        let round2_input = StoreInput {
            events: round2_send,
            flag: round2_flag1,
        };
        let round3_input = StoreInput {
            events: round3_send,
            flag: round3_flag1,
        };

        let msg1 = Incoming {
            sender: 10,
            msg: TestMsg::R1(Round1Msg(1)),
        };
        let msg2 = Incoming {
            sender: 11,
            msg: TestMsg::R2(Round2Msg(2)),
        };
        let msg3 = Incoming {
            sender: 12,
            msg: TestMsg::R3(Round3Msg(3)),
        };
        let msgs = vec![
            Ok(msg1.clone()),
            Ok(msg2.clone()),
            Ok(msg3.clone()),
            Err(DummyError("dummy error")),
        ];

        // Raise round2_flag2
        round2_flag2.set(true);

        ProtocolIncoming::new(HashMap::from_iter([
            (0, round1_input),
            (1, round2_input),
            (2, round3_input),
        ]))
        .start_processing(futures::stream::iter(msgs))
        .await;

        let round1_received = ReceiverStream::new(round1_recv).collect::<Vec<_>>().await;
        let round2_received = ReceiverStream::new(round2_recv).collect::<Vec<_>>().await;
        let round3_received = ReceiverStream::new(round3_recv).collect::<Vec<_>>().await;

        let round1_expected = vec![RoundEvent::Msg(msg1), RoundEvent::Error(None)];
        let round2_expected = vec![
            RoundEvent::Msg(msg2),
            RoundEvent::Error(Some(DummyError("dummy error"))),
        ];
        let round3_expected = vec![RoundEvent::Msg(msg3), RoundEvent::Error(None)];

        assert_eq!(round1_received, round1_expected);
        assert_eq!(round2_received, round2_expected);
        assert_eq!(round3_received, round3_expected);
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TestStore<M>(Vec<Option<M>>);
    #[derive(Clone, Debug, PartialEq)]
    enum TestStoreError<M> {
        PushMsg {
            msg: Incoming<M>,
            received_msgs: Vec<Option<M>>,
        },
        Finish {
            received_msgs: Vec<Option<M>>,
        },
    }

    impl<M> TestStore<M> {
        pub fn new(n: u16) -> Self {
            Self(iter::repeat_with(|| None).take(usize::from(n)).collect())
        }
    }

    impl<M: Clone> MessagesStore for TestStore<M> {
        type Msg = M;
        type Error = TestStoreError<M>;
        type Output = Vec<M>;

        fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
            match self.0.get_mut(usize::from(msg.sender)) {
                Some(vacant @ None) => {
                    *vacant = Some(msg.msg);
                    Ok(())
                }
                _ => Err(TestStoreError::PushMsg {
                    msg,
                    received_msgs: self.0.clone(),
                }),
            }
        }

        fn wants_more(&self) -> bool {
            self.0.iter().any(|entry| entry.is_none())
        }

        fn finish(self) -> Result<Self::Output, Self::Error> {
            if self.wants_more() {
                Err(TestStoreError::Finish {
                    received_msgs: self.0,
                })
            } else {
                Ok(self
                    .0
                    .into_iter()
                    .map(|entry| entry)
                    .collect::<Option<Vec<_>>>()
                    .unwrap())
            }
        }
    }

    #[tokio::test]
    async fn process_round_outputs_after_receiving_enough_messages() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, round_input, round_output, _round_supersede) =
            RoundIncoming::<TestMsg, _, _>::with_store(store);

        let processing = tokio::spawn(round.start_processing());

        let msg1 = Round2Msg(1);
        let msg2 = Round2Msg(2);
        let msg3 = Round2Msg(3);

        let mut events = vec![
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 0,
                msg: TestMsg::R2(msg1.clone()),
            }),
            RoundEvent::Msg(Incoming {
                sender: 1,
                msg: TestMsg::R2(msg2.clone()),
            }),
            RoundEvent::Msg(Incoming {
                sender: 2,
                msg: TestMsg::R2(msg3.clone()),
            }),
        ];
        // Order doesn't matter
        events.shuffle(&mut OsRng);

        for ev in events {
            round_input.events.send(ev).await.unwrap();
        }

        let result = round_output.await;
        let expected_result = vec![msg1, msg2, msg3];
        assert_eq!(result, Ok(expected_result));

        processing.await.expect("processing panicked");
    }

    #[tokio::test]
    async fn process_round_ignores_message_duplicates() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, round_input, round_output, _round_supersede) =
            RoundIncoming::<TestMsg, _, _>::with_store(store);

        let processing = tokio::spawn(round.start_processing());

        let msg1 = Round2Msg(1);
        let msg2 = Round2Msg(2);
        let msg2_2 = Round2Msg(123);
        let msg3 = Round2Msg(3);

        let events = vec![
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 0,
                msg: TestMsg::R2(msg1.clone()),
            }),
            RoundEvent::Msg(Incoming {
                sender: 1,
                msg: TestMsg::R2(msg2.clone()),
            }),
            RoundEvent::Msg(Incoming {
                sender: 1,
                msg: TestMsg::R2(msg2_2.clone()),
            }),
            RoundEvent::Msg(Incoming {
                sender: 2,
                msg: TestMsg::R2(msg3.clone()),
            }),
        ];

        for ev in events {
            round_input.events.send(ev).await.unwrap();
        }

        // todo: we should check that RoundIncoming has logged that we received duplicating message

        let result = round_output.await;
        let expected_result = vec![msg1, msg2, msg3];
        assert_eq!(result, Ok(expected_result));

        processing.await.expect("processing panicked");
    }

    #[tokio::test]
    async fn process_round_tries_to_take_result_from_store_if_got_error() {
        for err in [Some(DummyError("something happened")), None] {
            let store = TestStore::<Round2Msg>::new(3);

            let (round, round_input, round_output, _round_supersede) =
                RoundIncoming::<TestMsg, _, _>::with_store(store);

            let processing = tokio::spawn(round.start_processing());

            let msg1 = Round2Msg(1);

            let events = vec![
                RoundEvent::Msg(Incoming {
                    sender: 0,
                    msg: TestMsg::R2(msg1.clone()),
                }),
                RoundEvent::Error(err.clone()),
            ];

            for ev in events {
                round_input.events.send(ev).await.unwrap();
            }

            let result = round_output.await;
            let expected_result = ReceiveError::IncomingChannelBroken {
                store_error: TestStoreError::Finish {
                    received_msgs: vec![Some(msg1), None, None],
                },
                receive_error: err,
            };
            assert_eq!(result, Err(expected_result));

            processing.await.expect("processing panicked");
        }
    }

    #[tokio::test]
    async fn process_round_tries_to_take_result_from_store_if_channel_closed() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, round_input, round_output, _round_supersede) =
            RoundIncoming::<TestMsg, _, _>::with_store(store);

        let processing = tokio::spawn(round.start_processing());

        let msg1 = Round2Msg(1);

        let events = vec![
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 0,
                msg: TestMsg::R2(msg1.clone()),
            }),
            RoundEvent::Eof,
        ];

        for ev in events {
            round_input.events.send(ev).await.unwrap();
        }

        let result = round_output.await;
        let expected_result = ReceiveError::IncomingChannelClosed {
            store_error: TestStoreError::Finish {
                received_msgs: vec![Some(msg1), None, None],
            },
        };
        assert_eq!(result, Err(expected_result));

        processing.await.expect("processing panicked");
    }

    #[tokio::test]
    async fn process_round_tries_to_take_result_from_store_if_asked_to_force_finish() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, round_input, round_output, _round_supersede) =
            RoundIncoming::<TestMsg, _, _>::with_store(store);

        let processing = tokio::spawn(round.start_processing());

        let msg1 = Round2Msg(1);
        let msg2 = Round2Msg(2);

        let events = vec![
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 0,
                msg: TestMsg::R2(msg1.clone()),
            }),
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 1,
                msg: TestMsg::R2(msg2.clone()),
            }),
        ];

        for ev in events {
            round_input.events.send(ev).await.unwrap();
        }

        round_output.force();
        let result = round_output.await;
        let expected_result = ReceiveError::NotEnoughMessages {
            store_error: TestStoreError::Finish {
                received_msgs: vec![Some(msg1), Some(msg2), None],
            },
        };
        assert_eq!(result, Err(expected_result));

        processing.await.expect("processing panicked");
    }

    #[derive(Debug, Clone, PartialEq)]
    struct TestSupersedingStore<M> {
        required_at_least: u16,
        received: Vec<Option<M>>,
    }
    #[derive(Debug, Clone, PartialEq)]
    enum TestSupersedeError {
        MismatchedNumberOfParties { expected: usize, got: usize },
    }
    impl<M> TestSupersedingStore<M> {
        pub fn new(t: u16, n: u16) -> Self {
            Self {
                required_at_least: t,
                received: iter::repeat_with(|| None).take(usize::from(n)).collect(),
            }
        }
    }
    impl<M: Clone> MessagesStore for TestSupersedingStore<M> {
        type Msg = M;
        type Error = TestStoreError<M>;
        type Output = Vec<M>;

        fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
            match self.received.get_mut(usize::from(msg.sender)) {
                Some(vacant @ None) => {
                    *vacant = Some(msg.msg);
                    Ok(())
                }
                _ => Err(TestStoreError::PushMsg {
                    msg,
                    received_msgs: self.received.clone(),
                }),
            }
        }

        fn wants_more(&self) -> bool {
            self.received.iter().filter(|entry| entry.is_some()).count()
                < usize::from(self.required_at_least)
        }

        fn finish(self) -> Result<Self::Output, Self::Error> {
            if self.wants_more() {
                Err(TestStoreError::Finish {
                    received_msgs: self.received.clone(),
                })
            } else {
                Ok(self.received.into_iter().flatten().collect())
            }
        }
    }
    impl<M: Clone> SupersedingStore<TestStore<M>> for TestSupersedingStore<M> {
        type SupersedeError = TestSupersedeError;
        fn supersede(&mut self, prior_store: TestStore<M>) -> Result<(), Self::SupersedeError> {
            if self.received.len() != prior_store.0.len() {
                return Err(TestSupersedeError::MismatchedNumberOfParties {
                    expected: prior_store.0.len(),
                    got: self.received.len(),
                });
            }
            self.received = prior_store.0;
            Ok(())
        }
    }

    #[tokio::test]
    async fn superseding_store_finishes_immediately_if_enough_messages_already_collected() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, round_input, round_output, round_supersede) =
            RoundIncoming::<TestMsg, _, _>::with_store(store);

        let processing1 = tokio::spawn(round.start_processing());

        let msg1 = Round2Msg(1);
        let msg2 = Round2Msg(2);

        let events = vec![
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 0,
                msg: TestMsg::R2(msg1.clone()),
            }),
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 1,
                msg: TestMsg::R2(msg2.clone()),
            }),
        ];

        for ev in events {
            round_input.events.send(ev).await.unwrap();
        }

        // TODO: superseding must return error, e.g. if n1 != n2
        let store = TestSupersedingStore::new(2, 3);
        let (round, _round_supersede) = RoundIncoming::supersede(store, round_supersede)
            .await
            .unwrap();
        let proceeding2 = tokio::spawn(round.start_processing());

        processing1.await.expect("processing1 panicked");

        let result = round_output.await;
        let expected_result = vec![msg1, msg2];
        assert_eq!(result, Ok(expected_result));

        proceeding2.await.expect("processing2 panicked");
    }

    #[tokio::test]
    async fn superseding_store_finishes_once_it_received_enough_messages() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, round_input, round_output, round_supersede) =
            RoundIncoming::<TestMsg, _, _>::with_store(store);

        let processing1 = tokio::spawn(round.start_processing());

        let msg1 = Round2Msg(1);
        let msg2 = Round2Msg(2);

        round_input
            .events
            .send(RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 0,
                msg: TestMsg::R2(msg1.clone()),
            }))
            .await
            .unwrap();

        // TODO: superseding must return error, e.g. if n1 != n2
        let store = TestSupersedingStore::new(2, 3);
        let (round, _round_supersede) = RoundIncoming::supersede(store, round_supersede)
            .await
            .unwrap();
        let proceeding2 = tokio::spawn(round.start_processing());

        processing1.await.expect("processing1 panicked");

        round_input
            .events
            .send(RoundEvent::Msg(Incoming {
                sender: 2,
                msg: TestMsg::R2(msg2.clone()),
            }))
            .await
            .unwrap();

        let result = round_output.await;
        let expected_result = vec![msg1, msg2];
        assert_eq!(result, Ok(expected_result));

        proceeding2.await.expect("processing2 panicked");
    }

    #[tokio::test]
    async fn superseding_finished_store_is_error() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, round_input, round_output, round_supersede) =
            RoundIncoming::<TestMsg, _, _>::with_store(store);

        let processing = tokio::spawn(round.start_processing());

        let msg1 = Round2Msg(1);
        let msg2 = Round2Msg(2);
        let msg3 = Round2Msg(3);

        let events = vec![
            RoundEvent::<_, Infallible>::Msg(Incoming {
                sender: 0,
                msg: TestMsg::R2(msg1.clone()),
            }),
            RoundEvent::Msg(Incoming {
                sender: 1,
                msg: TestMsg::R2(msg2.clone()),
            }),
            RoundEvent::Msg(Incoming {
                sender: 2,
                msg: TestMsg::R2(msg3.clone()),
            }),
        ];

        for ev in events {
            round_input.events.send(ev).await.unwrap();
        }

        let result = round_output.await;
        let expected_result = vec![msg1, msg2, msg3];
        assert_eq!(result, Ok(expected_result));

        processing.await.expect("processing panicked");

        let store = TestSupersedingStore::new(2, 3);
        let result = RoundIncoming::supersede(store.clone(), round_supersede).await;
        assert_eq!(
            result.unwrap_err(),
            SupersedeError::PreviousStoreGone(store)
        );
    }

    #[tokio::test]
    async fn superseding_error_is_propagated() {
        let store = TestStore::<Round2Msg>::new(3);

        let (round, _round_input, _round_output, round_supersede) =
            RoundIncoming::<TestMsg, _, Infallible>::with_store(store);

        let _processing = tokio::spawn(round.start_processing());

        let store = TestSupersedingStore::new(2, 10);
        let result = RoundIncoming::supersede(store.clone(), round_supersede).await;
        assert_eq!(
            result.unwrap_err(),
            SupersedeError::SupersedingFailed(TestSupersedeError::MismatchedNumberOfParties {
                expected: 3,
                got: 10
            })
        );
    }
}
