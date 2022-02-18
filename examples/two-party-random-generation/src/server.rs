use anyhow::Context;
use structopt::StructOpt;

use random_generation_protocol::{protocol_of_random_generation, Msg};
use round_based::delivery::two_party::TcpServer;
use round_based::MpcParty;

#[derive(Debug, StructOpt)]
pub struct Cli {
    #[structopt(long, default_value = "127.0.0.1:8555")]
    address: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Cli = StructOpt::from_args();

    let mut server = TcpServer::<Msg>::bind(args.address)
        .await
        .context("bind a server")?
        .set_message_size_limit(50);

    eprintln!("Server is started, waiting for clients");
    eprintln!();
    loop {
        let (delivery, client_addr) = server.accept().await.context("accept a client")?;
        eprintln!("Client connected: {:?}", client_addr);
        eprintln!();

        let party = MpcParty::connected(delivery);
        let randomness = protocol_of_random_generation(party, 0, 2, rand::rngs::OsRng)
            .await
            .context("protocol didn't complete")?;
        eprintln!("Protocol is completed, resulting randomness:");
        println!("{}", hex::encode(randomness));
        eprintln!();
    }
}
