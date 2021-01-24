use std::fmt::Debug;

use crate::sm::*;

mod benchmark;
use benchmark::Benchmark;
pub use benchmark::{BenchmarkResults, Measurements};

/// Emulates running protocol between local parties
///
/// Takes parties (every party is instance of [StateMachine](crate::sm::StateMachine)) and
/// executes protocol between them. It logs whole process (changing state of party, receiving
/// messages, etc.) in stdout.
///
/// Compared to [AsyncSimulation](super::AsyncSimulation), it's lightweight (doesn't require
/// async runtime), and, more importantly, executes everything in straight order (sequently, without
/// any parallelism). It makes this sumaltion more useful for writing benchmarks that detect
/// performance regression.
///
/// ## Limitations
/// * Currently, it's a bit silly and doesn't support specific [StateMachine](crate::sm::StateMachine)
///   implementations (e.g. it'll panic if SM wants to [proceed](crate::sm::StateMachine::wants_to_proceed),
///   but there are some messages sent by other parties which should be handled)
/// * No proper error handling. It should attach a context to returning error (like current round,
///   what we was doing when error occurred, etc.). The only way to determine error context is to
///   look at stdout and find out what happened from logs.
/// * Logging to stdout. No option here.
///
/// ## Example
/// ```no_run
/// # use round_based::StateMachine;
/// # use round_based::dev::Simulation;
/// # trait Builder { fn new(party_i: u16, party_n: u16) -> Self; }
/// # fn is_valid<T>(_: &T) -> bool { true }
/// # fn _test<Party: StateMachine + Builder>() -> Result<(), Party::Err>
/// # where Party: std::fmt::Debug,
/// #       Party::Err: std::fmt::Debug,
/// #       Party::MessageBody: std::fmt::Debug + Clone,
/// # {
/// let results = Simulation::new()
///     .add_party(Party::new(1, 3))    
///     .add_party(Party::new(2, 3))    
///     .add_party(Party::new(3, 3))
///     .run()?;   
/// assert!(results.into_iter().all(|r| is_valid(&r)));
/// # Ok(())
/// # }
/// ```
pub struct Simulation<P> {
    /// Parties who run a protocol
    ///
    /// Field is exposed mainly to allow examining parties state after simulation is completed.
    pub parties: Vec<P>,
    benchmark: Option<Benchmark>,
}

impl<P> Simulation<P> {
    /// Creates new simulation
    pub fn new() -> Self {
        Self {
            parties: vec![],
            benchmark: None,
        }
    }

    /// Adds protocol participant
    pub fn add_party(&mut self, party: P) -> &mut Self {
        self.parties.push(party);
        self
    }

    /// Enables benchmarks so they can be [retrieved](Simulation::benchmark_results) after simulation
    /// is completed
    pub fn enable_benchmarks(&mut self, enable: bool) -> &mut Self {
        if enable {
            self.benchmark = Some(Benchmark::new())
        } else {
            self.benchmark = None
        }
        self
    }

    /// Returns benchmark results if they were [enabled](Simulation::enable_benchmarks)
    ///
    /// Benchmarks show how much time (in average) [proceed](StateMachine::proceed) method takes for
    /// proceeding particular rounds. Benchmarks might help to find out which rounds are cheap to
    /// proceed, and which of them are expensive to compute.
    pub fn benchmark_results(&self) -> Option<&BenchmarkResults> {
        self.benchmark.as_ref().map(|b| b.results())
    }
}

impl<P> Simulation<P>
where
    P: StateMachine,
    // Needed for logging:
    P: Debug,
    P::Err: Debug,
    P::MessageBody: Debug,
    // Needed to transmit a single broadcast message to every party:
    P::MessageBody: Clone,
{
    /// Runs a simulation
    ///
    /// ## Returns
    /// Returns either Vec of protocol outputs (one output for each one party) or first
    /// occurred critical error.
    ///
    /// ## Panics
    /// * Number of parties is less than 2
    /// * Party behaves unexpectedly (see [limitations](Simulation#limitations))
    pub fn run(&mut self) -> Result<Vec<P::Output>, P::Err> {
        assert!(self.parties.len() >= 2, "at least two parties required");

        println!("Simulation starts");
        loop {
            let mut msgs: Vec<Msg<P::MessageBody>> = vec![];
            for party in &mut self.parties {
                if party.wants_to_proceed() {
                    println!("Party {} wants to proceed", party.party_ind());
                    println!("  - before: {:?}", party);

                    let round_old = party.current_round();
                    let stopwatch = self.benchmark.as_mut().map(|b| b.start());
                    match party.proceed() {
                        Ok(()) => (),
                        Err(err) if err.is_critical() => return Err(err),
                        Err(err) => {
                            println!("Non-critical error encountered: {:?}", err);
                        }
                    }
                    let round_new = party.current_round();
                    let duration = stopwatch
                        .filter(|_| round_old + 1 == round_new)
                        .map(|s| s.stop_and_save(round_old));

                    println!("  - after : {:?}", party);
                    println!("  - time  : {:?}", duration);
                }

                println!(
                    "Party {} sends {} message(s)",
                    party.party_ind(),
                    party.message_queue().len()
                );
                msgs.append(party.message_queue())
            }

            for party in &mut self.parties {
                let party_i = party.party_ind();
                let msgs = msgs.iter().filter(|m| {
                    m.sender != party_i && (m.receiver.is_none() || m.receiver == Some(party_i))
                });

                for msg in msgs {
                    assert!(
                        !party.wants_to_proceed(),
                        "simulation is silly and doesn't expect party \
                         to wanna proceed at the middle of message handling"
                    );
                    println!(
                        "Party {} got message from={}, broadcast={}: {:?}",
                        party.party_ind(),
                        msg.sender,
                        msg.receiver.is_none(),
                        msg,
                    );
                    println!("  - before: {:?}", party);
                    match party.handle_incoming(msg.clone()) {
                        Ok(()) => (),
                        Err(err) if err.is_critical() => return Err(err),
                        Err(err) => {
                            println!("Non-critical error encountered: {:?}", err);
                        }
                    }
                    println!("  - after : {:?}", party);
                }
            }

            let is_finished = self.parties[0].is_finished();
            let same_answer_for_all_parties =
                self.parties.iter().all(|p| p.is_finished() == is_finished);
            assert!(same_answer_for_all_parties);

            if is_finished {
                let mut results = vec![];
                for party in &mut self.parties {
                    results.push(
                        party
                            .pick_output()
                            .expect("is_finished == true, but pick_output == None")?,
                    )
                }

                break Ok(results);
            }
        }
    }
}
