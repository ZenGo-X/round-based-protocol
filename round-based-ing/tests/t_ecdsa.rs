use std::fmt;
use std::sync::Arc;

use anyhow::Context;
use futures::future;
use test_case::test_case;

use curv_kzen::elliptic::curves::secp256_k1::FE as InitialSecret;
use ecdsa_mpc::algorithms::zkp::ZkpSetup;
use ecdsa_mpc::ecdsa::keygen::{
    DecryptionKey, Message as KeygenMsg, MultiPartyInfo, Phase1, SecretKeyLoader,
    SecretKeyLoaderError,
};
use ecdsa_mpc::ecdsa::{InitialKeys, InitialPublicKeys};
use ecdsa_mpc::Parameters;

use round_based::simulation::Simulation;
use round_based_ing::{execute_ing_protocol, party_index_from_u16, Debugging};

lazy_static::lazy_static! {
    static ref ZKP_SETUPS: Vec<ZkpSetup> = serde_json::from_str(include_str!("../data/dev_zkp_setup.json")).unwrap();
}

#[test_case(2, 3 ; "2 out of 3")]
#[test_case(3, 3 ; "3 out of 3")]
#[test_case(3, 4 ; "3 out of 4")]
#[test_case(7, 10; "7 out of 10")]
#[tokio::test]
async fn keygens(min_signers: u16, n: u16) {
    let _ = tracing_subscriber::fmt()
        .pretty()
        .with_env_filter("debug,round_based_ing=trace,t_ecdsa=trace")
        .try_init();

    let _ = keygen(min_signers, n).await.unwrap();
}

async fn keygen(min_signers: u16, n: u16) -> anyhow::Result<Vec<MultiPartyInfo>> {
    let mut simulation = Simulation::<KeygenMsg>::with_capacity(usize::from(n * n));
    let parameters =
        Parameters::new(usize::from(min_signers), usize::from(n)).context("invalid parameters")?;

    let parties = (0..n).map(|i| party_index_from_u16(i)).collect::<Vec<_>>();

    let mut running = vec![];
    for i in 0..n {
        let init_keys = InitialKeys::random();
        let init_public_keys = InitialPublicKeys::from(&init_keys);
        let zkp_setup = ZKP_SETUPS[usize::from(i)].clone();

        let initial_state = Phase1::new(
            &parameters,
            init_public_keys,
            Some(zkp_setup),
            &parties,
            party_index_from_u16(i),
            Arc::new(Box::new(InMemorySecretStorage(init_keys))),
            None,
        )
        .context("construct initial keygen state")?;

        let party = simulation.add_party();
        running.push(async move {
            let span = tracing::span!(tracing::Level::TRACE, "keygen", party_index = i);
            execute_ing_protocol(party, i, Debugging::new(initial_state).set_span(span))
                .await
                .map(|state| state.multiparty_shared_info)
                .context(format!("party {i} failed to complete keygen"))
        });
    }

    future::try_join_all(running).await.context("keygen failed")
}

struct InMemorySecretStorage(InitialKeys);

impl SecretKeyLoader for InMemorySecretStorage {
    fn get_initial_secret(&self) -> Result<Box<InitialSecret>, SecretKeyLoaderError> {
        Ok(Box::new(self.0.u_i))
    }

    fn get_paillier_secret(&self) -> Result<Box<DecryptionKey>, SecretKeyLoaderError> {
        Ok(Box::new(self.0.paillier_keys.dk.clone()))
    }
}

impl fmt::Debug for InMemorySecretStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InMemorySecretStorage")
    }
}
