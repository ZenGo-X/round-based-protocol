use std::convert::Infallible;

use phantom_type::PhantomType;

use crate::{Delivery, Incoming, Outgoing};

pub fn fake_delivery<M>() -> impl Delivery<M> {
    struct FakeDelivery<M>(PhantomType<M>);
    impl<M> Delivery<M> for FakeDelivery<M> {
        type Send = futures::sink::Drain<Outgoing<M>>;
        type Receive = futures::stream::Pending<Result<Incoming<M>, Infallible>>;

        type SendError = Infallible;
        type ReceiveError = Infallible;

        fn split(self) -> (Self::Receive, Self::Send) {
            (futures::stream::pending(), futures::sink::drain())
        }
    }
    FakeDelivery(PhantomType::new())
}
