use futures::SinkExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{digest::Output, Digest, Sha256};

use round_based::rounds::{CompleteRoundError, Error as StoreError, RoundInput, Rounds};
use round_based::{Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage};

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    CommitMsg(CommitMsg),
    DecommitMsg(DecommitMsg),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommitMsg {
    pub commitment: Output<Sha256>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecommitMsg {
    pub randomness: [u8; 32],
}

pub async fn protocol_of_random_generation<R, M>(
    party: M,
    i: u16,
    n: u16,
    mut rng: R,
) -> Result<[u8; 32], Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = Msg>,
    R: RngCore,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();

    // Define rounds
    let mut rounds = Rounds::<Msg>::builder();
    let round1 = rounds.add_round(RoundInput::<CommitMsg>::new(i, n));
    let round2 = rounds.add_round(RoundInput::<DecommitMsg>::new(i, n));
    let mut rounds = rounds.listen(incoming);

    // --- The Protocol ---

    // 1. Generate local randomness
    let mut local_randomness = [0u8; 32];
    rng.fill_bytes(&mut local_randomness);

    // 2. Commit local randomness (broadcast m=sha256(randomness))
    let commitment = Sha256::digest(&local_randomness);
    outgoing
        .send(Outgoing {
            recipient: None,
            msg: Msg::CommitMsg(CommitMsg { commitment }),
        })
        .await
        .map_err(Error::Round1Send)?;

    // 3. Receive committed randomness from other parties
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(Error::Round1Receive)?
        .into_vec_including_me(CommitMsg { commitment });

    // 4. Open local randomness
    outgoing
        .send(Outgoing {
            recipient: None,
            msg: Msg::DecommitMsg(DecommitMsg {
                randomness: local_randomness,
            }),
        })
        .await
        .map_err(Error::Round2Send)?;

    // 5. Receive opened local randomness from other parties, verify them, and output protocol randomness
    let randomness = rounds
        .complete(round2)
        .await
        .map_err(Error::Round2Receive)?
        .into_vec_including_me(DecommitMsg {
            randomness: local_randomness,
        });

    let mut guilty_parties = vec![];
    let mut output = [0u8; 32];
    for ((i, commit), decommit) in (0..).zip(commitments).zip(randomness) {
        let commitment_expected = Sha256::digest(&decommit.randomness);
        if commit.commitment != commitment_expected {
            guilty_parties.push(i);
            continue;
        }

        output
            .iter_mut()
            .zip(decommit.randomness)
            .for_each(|(x, r)| *x ^= r);
    }

    if !guilty_parties.is_empty() {
        Err(Error::PartiesOpenedRandomnessDoesntMatchCommitment { guilty_parties })
    } else {
        Ok(output)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error<RecvErr, SendErr> {
    #[error("send a message at round 1")]
    Round1Send(#[source] SendErr),
    #[error("receive messages at round 1")]
    Round1Receive(#[source] CompleteRoundError<StoreError, RecvErr>),
    #[error("send a message at round 2")]
    Round2Send(#[source] SendErr),
    #[error("receive messages at round 2")]
    Round2Receive(#[source] CompleteRoundError<StoreError, RecvErr>),

    #[error("malicious parties: {guilty_parties:?}")]
    PartiesOpenedRandomnessDoesntMatchCommitment { guilty_parties: Vec<u16> },
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use round_based::simulation::Simulation;

    use super::{protocol_of_random_generation, Msg};

    #[tokio::test]
    async fn main() {
        let n: u16 = 5;

        let mut simulation = Simulation::<Msg>::new();
        let mut party_output = vec![];

        for i in 0..n {
            let party = simulation.add_party();
            let rng = ChaCha20Rng::from_entropy();
            let output = protocol_of_random_generation(party, i, n, rng);
            party_output.push(output);
        }

        let output = futures::future::try_join_all(party_output).await.unwrap();

        // Assert that all parties outputed the same randomness
        for i in 1..n {
            assert_eq!(output[0], output[usize::from(i)]);
        }

        println!("Output randomness: {}", hex::encode(&output[0]));
    }
}
