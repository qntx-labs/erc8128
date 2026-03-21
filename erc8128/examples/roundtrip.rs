#![allow(clippy::print_stdout)]
//! Pure in-memory sign → verify roundtrip.
//!
//! ```sh
//! cargo run --example roundtrip --features k256
//! ```

use erc8128::{
    MemoryNonceStore, Request, SignOptions, VerifyPolicy,
    eoa::{EoaSigner, EoaVerifier},
    sign_request, verify_request,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = EoaSigner::from_slice(&[0xAB; 32], 1)?;

    let request = Request {
        method: "POST",
        url: "https://api.example.com/orders",
        headers: &[("content-type", "application/json")],
        body: Some(b"{\"item\":\"widget\"}"),
    };

    let signed = sign_request(&request, &signer, &SignOptions::default()).await?;

    println!("Signature-Input: {}", signed.signature_input);
    println!("Signature:       {}", signed.signature);
    if let Some(ref d) = signed.content_digest {
        println!("Content-Digest:  {d}");
    }

    let mut headers: Vec<(&str, &str)> = request.headers.to_vec();
    headers.push(("signature-input", &signed.signature_input));
    headers.push(("signature", &signed.signature));
    if let Some(ref d) = signed.content_digest {
        headers.push(("content-digest", d));
    }

    let verify_req = Request {
        headers: &headers,
        ..request
    };
    let nonces = MemoryNonceStore::default();
    let result =
        verify_request(&verify_req, &EoaVerifier, &nonces, &VerifyPolicy::default()).await?;

    println!(
        "\n✓ Verified: address={} chain_id={}",
        result.address, result.chain_id
    );
    Ok(())
}
