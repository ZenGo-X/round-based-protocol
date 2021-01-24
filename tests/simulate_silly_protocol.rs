use round_based::async_runtime;
use round_based::dev::{AsyncSimulation, AsyncSimulationError, Simulation};

use crate::silly_protocol::{Error, MultiPartyGenRandom, ProceedError};

mod silly_protocol;

#[test]
fn simulate_silly_protocol() {
    let mut rnd = rand::thread_rng();
    let mut simulation = Simulation::new();
    simulation
        .enable_benchmarks(true)
        .add_party(MultiPartyGenRandom::with_fixed_seed(1, 3, 10, &mut rnd))
        .add_party(MultiPartyGenRandom::with_fixed_seed(2, 3, 20, &mut rnd))
        .add_party(MultiPartyGenRandom::with_fixed_seed(3, 3, 30, &mut rnd));
    let result = simulation.run().expect("simulation failed");
    assert_eq!(result, vec![10 ^ 20 ^ 30; 3]);
    println!("Benchmarks:");
    println!("{:#?}", simulation.benchmark_results().unwrap());
}

#[tokio::test]
async fn async_simulation_of_silly_protocol() {
    let mut rnd = rand::thread_rng();
    let results = AsyncSimulation::new()
        .add_party(MultiPartyGenRandom::with_fixed_seed(1, 3, 22, &mut rnd))
        .add_party(MultiPartyGenRandom::with_fixed_seed(2, 3, 33, &mut rnd))
        .add_party(MultiPartyGenRandom::with_fixed_seed(3, 3, 44, &mut rnd))
        .run()
        .await;
    println!("Simulation results: {:?}", results);
    let predicate = |x| match x {
        &Ok(x) => x == 22 ^ 33 ^ 44,
        &Err(_) => false,
    };
    assert!(results.iter().all(predicate))
}

#[tokio::test]
async fn async_simulation_of_silly_protocol_with_adversary() {
    let mut rnd = rand::thread_rng();
    let results = AsyncSimulation::new()
        .add_party(MultiPartyGenRandom::with_fixed_seed(1, 3, 43, &mut rnd))
        .add_party(MultiPartyGenRandom::with_fixed_seed(2, 3, 44, &mut rnd))
        .add_party(MultiPartyGenRandom::adversary_with_fixed_seed(
            3, 3, 45, &mut rnd,
        ))
        .run()
        .await;
    println!("Simulation results: {:?}", results);
    let blamed = |x| match x {
        &Err(AsyncSimulationError::ProtocolExecution(
            async_runtime::Error::HandleIncomingTimeout(Error::ProceedRound(
                ProceedError::PartiesDidntRevealItsSeed { ref party_ind },
            )),
        )) => Some(party_ind.clone()),
        _ => None,
    };
    let predicate = |(i, x)| match i {
        0..=1 => blamed(x) == Some(vec![3]),
        2 => x.is_ok() && *x.as_ref().unwrap() == 43 ^ 44 ^ 45,
        _ => unreachable!(),
    };
    assert!(results.iter().enumerate().all(predicate))
}
