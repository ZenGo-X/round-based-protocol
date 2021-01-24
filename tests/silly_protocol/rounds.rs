use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::Msg;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct Round0 {
    pub is_adversary: bool,
    pub my_ind: u16,
    pub my_seed: u32,
    pub blinding: [u8; 32],
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<CommittedSeed>>,
    {
        let mut committed_seed = [0u8; 32];
        let hash = Sha256::new()
            .chain(self.blinding)
            .chain(&self.my_seed.to_be_bytes()[..])
            .finalize();
        committed_seed.copy_from_slice(&hash);

        output.push(Msg {
            sender: self.my_ind,
            receiver: None,
            body: CommittedSeed(committed_seed),
        });

        Ok(Round1 {
            is_adversary: self.is_adversary,
            my_ind: self.my_ind,
            my_seed: self.my_seed,
            blinding: self.blinding,
        })
    }
    pub fn is_expensive(&self) -> bool {
        // We assume that computing hash is expensive operation (in real-world, it's not)
        true
    }
}

#[derive(Debug)]
pub struct Round1 {
    is_adversary: bool,
    my_ind: u16,
    my_seed: u32,
    blinding: [u8; 32],
}

impl Round1 {
    pub fn proceed<O>(self, input: BroadcastMsgs<CommittedSeed>, mut output: O) -> Result<Round2>
    where
        O: Push<Msg<RevealedSeed>>,
    {
        if !self.is_adversary {
            output.push(Msg {
                sender: self.my_ind,
                receiver: None,
                body: RevealedSeed {
                    seed: self.my_seed,
                    blinding: self.blinding,
                },
            });
        }
        Ok(Round2 {
            my_seed: self.my_seed,
            committed_seeds: input,
        })
    }
    pub fn expects_messages(party_i: u16, party_n: u16) -> Store<BroadcastMsgs<CommittedSeed>> {
        containers::BroadcastMsgsStore::new(party_i, party_n)
    }
    pub fn is_expensive(&self) -> bool {
        // Sending cached message is the cheapest operation
        false
    }
}

#[derive(Debug)]
pub struct Round2 {
    my_seed: u32,
    committed_seeds: BroadcastMsgs<CommittedSeed>,
}

impl Round2 {
    pub fn proceed(self, input: BroadcastMsgs<RevealedSeed>) -> Result<OutputRandomValue> {
        let mut result = self.my_seed;
        let msgs = self
            .committed_seeds
            .into_iter_indexed()
            .zip(input.into_iter());

        let mut non_cooperative_parties: Vec<u16> = vec![];
        for ((i, commit), decommit) in msgs {
            let hash = Sha256::new()
                .chain(decommit.blinding)
                .chain(&decommit.seed.to_be_bytes()[..])
                .finalize();
            if commit.0 != hash.as_ref() {
                non_cooperative_parties.push(i)
            } else {
                result ^= decommit.seed;
            }
        }

        if !non_cooperative_parties.is_empty() {
            Err(ProceedError::PartiesDidntRevealItsSeed {
                party_ind: non_cooperative_parties,
            })
        } else {
            Ok(result)
        }
    }
    pub fn expects_messages(party_i: u16, party_n: u16) -> Store<BroadcastMsgs<RevealedSeed>> {
        containers::BroadcastMsgsStore::new(party_i, party_n)
    }
    pub fn is_expensive(&self) -> bool {
        // Round involves computing a hash, we assume it's expensive (again, in real-world it's not)
        true
    }
}

pub type OutputRandomValue = u32;

// Messages

#[derive(Clone, Debug)]
pub struct CommittedSeed([u8; 32]);

#[derive(Clone, Debug)]
pub struct RevealedSeed {
    seed: u32,
    blinding: [u8; 32],
}

// Errors

type Result<T> = std::result::Result<T, ProceedError>;

#[derive(Debug, PartialEq)]
pub enum ProceedError {
    PartiesDidntRevealItsSeed { party_ind: Vec<u16> },
}
