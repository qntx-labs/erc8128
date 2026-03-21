#![allow(clippy::print_stdout)]
//! Axum server with ERC-8128 signature verification middleware.
//!
//! ```sh
//! cargo run --example axum_server --features k256,axum
//! ```

use axum::{Extension, Router, routing::post};
use erc8128::{
    NoNonceStore, VerifyPolicy, VerifySuccess, eoa::EoaVerifier, middleware::Erc8128Layer,
};

async fn handler(Extension(auth): Extension<VerifySuccess>) -> String {
    format!(
        "Authenticated: address={} chain_id={}",
        auth.address, auth.chain_id
    )
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api", post(handler))
        .layer(Erc8128Layer::new(
            EoaVerifier,
            NoNonceStore,
            VerifyPolicy::default(),
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("bind");
    println!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.expect("serve");
}
