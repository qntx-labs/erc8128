#![allow(clippy::print_stdout)]
//! Send an ERC-8128 signed HTTP request with reqwest.
//!
//! ```sh
//! cargo run --example reqwest_client --features k256,reqwest
//! ```

use erc8128::{Replay, SignOptions, client::signed_fetch, eoa::EoaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = EoaSigner::from_slice(&[0xAB; 32], 1)?;
    let client = reqwest::Client::new();

    // Use Replayable mode for this demo (no server-side nonce store).
    let opts = SignOptions {
        replay: Replay::Replayable,
        ..SignOptions::default()
    };

    let response = signed_fetch(
        &client,
        reqwest::Method::GET,
        "https://httpbin.org/get",
        &[],
        None,
        &signer,
        &opts,
    )
    .await?;

    println!("Status: {}", response.status());
    println!("Body:\n{}", response.text().await?);
    Ok(())
}
