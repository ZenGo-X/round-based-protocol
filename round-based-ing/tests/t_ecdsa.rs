use anyhow::Context;
use futures::future;
use sha2::{Digest, Sha256};
use test_case::test_case;

use sorted_vec::SortedVec;

use round_based::simulation::Simulation;
use round_based_ing::{KeyShare, Keygen, KeygenSetup, Message, Signing, SigningMsg};

lazy_static::lazy_static! {
    static ref ZKP_SETUPS: Vec<KeygenSetup> = serde_json::from_str(include_str!("../data/dev_zkp_setup.json")).unwrap();
    static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::gen_new();
}

#[test_case(2, 3 ; "2 out of 3")]
#[test_case(3, 3 ; "3 out of 3")]
#[test_case(3, 4 ; "3 out of 4")]
#[test_case(7, 10; "7 out of 10")]
#[tokio::test]
async fn keygens(min_signers: u16, n: u16) {
    init_logging();

    let _ = simulate_keygen(min_signers, n).await.unwrap();
}

#[test_case(2, 3, &[0, 1] ; "2 out of 3 signers 0 1")]
#[test_case(2, 3, &[0, 1, 2] ; "2 out of 3 signers 0 1 2")]
#[test_case(2, 3, &[0, 2] ; "2 out of 3 signers 0 2")]
#[test_case(3, 3, &[0, 1, 2] ; "3 out of 3 signers 0 1 2")]
#[test_case(3, 4, &[0, 1, 3] ; "3 out of 4 signers 0 1 3")]
#[test_case(7, 10, &[0, 1, 2, 3, 4, 5, 6] ; "7 out of 10")]
#[tokio::test]
async fn signs(min_signers: u16, n: u16, signers: &[u16]) {
    init_logging();

    const DATA: &[u8] = b"Hello, thresholdies";

    let shares = simulate_keygen(min_signers, n)
        .await
        .expect("keygen failed");
    let signers = signers
        .iter()
        .map(|signer_ind| shares[usize::from(*signer_ind)].clone())
        .collect::<Vec<_>>();
    let message = Sha256::new().chain(DATA);
    let message = Message::from_hash(message);
    let signature = simulate_signing(message, &signers)
        .await
        .expect("signing failed");

    // Verify signature
    let msg = Sha256::digest(DATA);
    let msg = secp256k1::Message::from_slice(msg.as_slice()).expect("construct hashed message");
    SECP256K1
        .verify(&msg, &signature, &signers[0].public_key())
        .expect("signature is not valid");
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .pretty()
        .with_ansi(false)
        .with_test_writer()
        .with_env_filter("debug,round_based_ing=trace,t_ecdsa=trace")
        .try_init();
}

async fn simulate_keygen(min_signers: u16, n: u16) -> anyhow::Result<Vec<KeyShare>> {
    let mut simulation = Simulation::with_capacity(usize::from(n * n));
    let mut running = vec![];

    for i in 0..n {
        let party = simulation.add_party();
        running.push(async move {
            let span = tracing::span!(tracing::Level::TRACE, "keygen", party_index = i);
            Keygen::new(i, min_signers, n)?
                .set_pregenerated_setup(ZKP_SETUPS[usize::from(i)].clone())
                .enable_logs(span)
                .run(party)
                .await
                .with_context(|| format!("party {i} failed to complete keygen"))
        });
    }

    future::try_join_all(running).await.context("keygen failed")
}

async fn simulate_signing(
    msg: Message,
    signers: &[KeyShare],
) -> anyhow::Result<secp256k1::Signature> {
    // Deduce list of signers indexes
    let signers_indexes: SortedVec<u16> = signers
        .iter()
        .map(|signer| signer.local_party_index())
        .collect::<Vec<_>>()
        .into();

    // Run signing
    let mut simulation = Simulation::<SigningMsg>::with_capacity(signers.len() * signers.len());
    let mut running = vec![];

    for (i, signer) in (0..).zip(signers) {
        let party = simulation.add_party();
        let signers_indexes = signers_indexes.clone();
        running.push(async move {
            let span = tracing::span!(tracing::Level::TRACE, "signing", party_index = i);
            Signing::new(signer.clone(), &signers_indexes, msg)?
                .enable_logs(span)
                .run(party)
                .await
                .with_context(|| format!("party {i} failed to complete signing"))
        })
    }

    // Wait until it's done
    let signatures = future::try_join_all(running).await.context("sign failed")?;
    // Verify that all signatures are equal
    for signature in &signatures {
        assert_eq!(*signature, signatures[0]);
    }
    Ok(signatures[0])
}
