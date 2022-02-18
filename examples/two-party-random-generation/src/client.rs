use anyhow::Context;
use structopt::StructOpt;

use random_generation_protocol::{protocol_of_random_generation, Msg};
use round_based::delivery::two_party::TcpClientBuilder;
use round_based::MpcParty;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long, default_value = "127.0.0.1:8555")]
    address: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Cli = StructOpt::from_args();

    let delivery = TcpClientBuilder::<Msg>::new()
        .set_message_size_limit(50)
        .connect(args.address)
        .await
        .context("connect to the server")?;
    let party = MpcParty::connected(delivery);

    eprintln!("Connection established, carrying out the protocol");
    eprintln!();

    let randomness = protocol_of_random_generation(party, 1, 2, rand::rngs::OsRng)
        .await
        .context("protocol didn't complete")?;

    eprintln!("Protocol is completed, resulting randomness:");
    println!("{}", hex::encode(randomness));
    eprintln!();

    Ok(())
}
