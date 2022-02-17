use std::fmt;
use std::sync::Arc;

use anyhow::Context;
use futures::future;
use sha2::{Digest, Sha256};
use test_case::test_case;

use curv_kzen::elliptic::curves::secp256_k1::FE as InitialSecret;
use curv_kzen::elliptic::curves::traits::{ECPoint, ECScalar};
use ecdsa_mpc::algorithms::zkp::ZkpSetup;
use ecdsa_mpc::ecdsa::keygen::{
    self, DecryptionKey, Message as KeygenMsg, MultiPartyInfo, SecretKeyLoader,
    SecretKeyLoaderError,
};
use ecdsa_mpc::ecdsa::signature::{self, Message as SignMsg};
use ecdsa_mpc::ecdsa::{InitialKeys, InitialPublicKeys};
use ecdsa_mpc::Parameters;

use round_based::simulation::Simulation;
use round_based_ing::generic::{execute_ing_protocol, party_index_from_u16, Parties};
use round_based_ing::Debugging;

lazy_static::lazy_static! {
    static ref ZKP_SETUPS: Vec<ZkpSetup> = serde_json::from_str(include_str!("../data/dev_zkp_setup.json")).unwrap();
    static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::gen_new();
}

#[test_case(2, 3 ; "2 out of 3")]
#[test_case(3, 3 ; "3 out of 3")]
#[test_case(3, 4 ; "3 out of 4")]
#[test_case(7, 10; "7 out of 10")]
#[tokio::test]
async fn keygens(min_signers: u16, n: u16) {
    init_logging();
    let _ = keygen(min_signers, n).await.unwrap();
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

    let shares = keygen(min_signers, n).await.expect("keygen failed");
    let signers = signers
        .iter()
        .map(|signer_ind| shares[usize::from(*signer_ind)].clone())
        .collect::<Vec<_>>();
    let message = b"Hello, thresholdies";
    let signature = sign(message, &signers).await.expect("signing failed");

    // Verify signature
    let msg = Sha256::digest(message);
    let msg = secp256k1::Message::from_slice(msg.as_slice()).expect("construct hashed message");
    SECP256K1
        .verify(&msg, &signature, &signers[0].public_key.get_element())
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

async fn keygen(min_signers: u16, n: u16) -> anyhow::Result<Vec<MultiPartyInfo>> {
    let mut simulation = Simulation::<KeygenMsg>::with_capacity(usize::from(n * n));
    let parameters =
        Parameters::new(usize::from(min_signers), usize::from(n)).context("invalid parameters")?;

    let parties = (0..n).map(|i| party_index_from_u16(i)).collect::<Vec<_>>();
    let parties = Parties::try_from(parties)?;

    let mut running = vec![];
    for i in 0..n {
        let init_keys = InitialKeys::random();
        let init_public_keys = InitialPublicKeys::from(&init_keys);
        let zkp_setup = ZKP_SETUPS[usize::from(i)].clone();
        let parties = parties.clone();

        let initial_state = keygen::Phase1::new(
            &parameters,
            init_public_keys,
            Some(zkp_setup),
            parties.as_slice(),
            party_index_from_u16(i),
            Arc::new(Box::new(InMemorySecretStorage(init_keys))),
            None,
        )
        .context("construct initial keygen state")?;

        let party = simulation.add_party();
        running.push(async move {
            let span = tracing::span!(tracing::Level::TRACE, "keygen", party_index = i);
            execute_ing_protocol(
                party,
                Debugging::new(initial_state).set_span(span),
                i,
                parties,
            )
            .await
            .map(|state| state.multiparty_shared_info)
            .context(format!("party {i} failed to complete keygen"))
        });
    }

    future::try_join_all(running).await.context("keygen failed")
}

async fn sign(msg: &[u8], signers: &[MultiPartyInfo]) -> anyhow::Result<secp256k1::Signature> {
    // Convert message to elliptic scalar
    let msg = Sha256::digest(msg);
    let msg = curv_kzen::BigInt::from(msg.as_slice());
    let msg = <curv_kzen::FE as ECScalar<_>>::from(&msg);

    // Deduce list of signers
    let signers_indexes = signers
        .iter()
        .map(|signer| signer.own_party_index)
        .collect::<Vec<_>>();
    let signers_indexes = Parties::try_from(signers_indexes)?;
    tracing::info!(list = ?signers_indexes, "Signers list");

    // Run signing
    let mut simulation = Simulation::<SignMsg>::with_capacity(signers.len() * signers.len());
    let mut running = vec![];

    for (i, signer) in (0..).zip(signers) {
        let signers_indexes = signers_indexes.clone();
        let initial_state =
            signature::Phase1::new(msg, signer.clone(), signers_indexes.as_slice(), None)
                .context("construct initial state")?;

        let party = simulation.add_party();
        running.push(async move {
            let span = tracing::span!(tracing::Level::TRACE, "signing", party_index = i);
            execute_ing_protocol(
                party,
                Debugging::new(initial_state).set_span(span),
                i,
                signers_indexes,
            )
            .await
            .with_context(|| format!("party {i} failed to complete signing"))
        })
    }

    // Wait until it's done
    let signatures = future::try_join_all(running).await.context("sign failed")?;

    // Verify that signature is valid
    let is_valid = ecdsa_mpc::ecdsa::Signature {
        r: signatures[0].r,
        s: signatures[0].s,
    }
    .verify(&signers[0].public_key, &msg);
    if !is_valid {
        anyhow::bail!("signature is not valid")
    }

    // Convert signature to secp256k1::Signature
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&signatures[0].r.get_element()[..]);
    signature[32..].copy_from_slice(&signatures[0].s.get_element()[..]);

    let mut signature =
        secp256k1::Signature::from_compact(&signature).context("signature not valid")?;
    signature.normalize_s();
    Ok(signature)
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
