#![allow(clippy::print_stdout)]
//! End-to-end: axum server + reqwest client in one process.
//!
//! Demonstrates `NonReplayable` replay protection with `MemoryNonceStore`.
//!
//! ```sh
//! cargo run --example e2e --features k256,axum,reqwest
//! ```

use axum::{Extension, Router, routing::post};
use erc8128::{
    MemoryNonceStore, RejectReplayable, Request, SignOptions, VerifyPolicy, VerifySuccess,
    client::{RequestBuilderExt, signed_fetch},
    eoa::{EoaSigner, EoaVerifier},
    middleware::Erc8128Layer,
    sign_request,
};

async fn handler(Extension(auth): Extension<VerifySuccess>) -> String {
    format!("✓ {} (chain {})", auth.address, auth.chain_id)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Server
    let app = Router::new()
        .route("/api", post(handler))
        .layer(Erc8128Layer::new(
            EoaVerifier,
            MemoryNonceStore::default(),
            RejectReplayable,
            VerifyPolicy::default(),
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(axum::serve(listener, app).into_future());

    // Client
    let signer = EoaSigner::from_slice(&[0xAB; 32], 1)?;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api");
    let headers: &[(&str, &str)] = &[("content-type", "application/json")];
    let body = b"{\"action\":\"test\"}";

    // 1. Fresh signature → 200
    let r = signed_fetch(
        &client,
        reqwest::Method::POST,
        &url,
        headers,
        Some(body),
        &signer,
        &SignOptions::default(),
    )
    .await?;
    println!("[1] Fresh:  {} - {}", r.status(), r.text().await?);

    // 2. Replay attack: sign once, send twice — second is rejected
    let req = Request {
        method: "POST",
        url: &url,
        headers,
        body: Some(body),
    };
    let signed = sign_request(&req, &signer, &SignOptions::default()).await?;

    let r = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .signed_headers(&signed)
        .send()
        .await?;
    println!("[2] First:  {} - {}", r.status(), r.text().await?);

    let r = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .signed_headers(&signed)
        .send()
        .await?;
    println!("[3] Replay: {} (nonce rejected)", r.status());

    // 3. New signature → 200
    let r = signed_fetch(
        &client,
        reqwest::Method::POST,
        &url,
        headers,
        Some(body),
        &signer,
        &SignOptions::default(),
    )
    .await?;
    println!("[4] Fresh:  {} - {}", r.status(), r.text().await?);

    Ok(())
}
