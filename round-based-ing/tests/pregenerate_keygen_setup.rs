use std::fs::OpenOptions;

use round_based_ing::KeygenSetup;

#[test]
fn pregenerate_keygen_setup() {
    let output = match OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(true)
        .open("./data/dev_zkp_setup.json")
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            println!("File already exists, skipping generation");
            return;
        }
        Err(err) => panic!("Couldn't create a file: {}", err),
    };

    let mut counter = 0;
    let setups = std::iter::repeat_with(KeygenSetup::generate)
        .inspect(|_| {
            counter += 1;
            println!("Generated setups: {counter}")
        })
        .take(10)
        .collect::<Vec<_>>();
    serde_json::to_writer_pretty(output, &setups).expect("serialize and save");
}
