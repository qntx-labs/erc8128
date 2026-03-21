//! # erc8128 — Signed HTTP Requests with Ethereum
//!
//! Rust implementation of [ERC-8128]: authenticate HTTP requests using
//! HTTP Message Signatures ([RFC 9421]) with Ethereum accounts.
//!
//! Two core operations:
//! - [`sign_request`] — sign an outgoing HTTP request
//! - [`verify_request`] — verify an incoming signed HTTP request
//!
//! Chain-specific signature verification (EOA / ERC-1271) is pluggable
//! via the [`Verifier`] trait.
//!
//! # Examples
//!
//! ```no_run
//! use erc8128::{Request, SignOptions, sign_request};
//!
//! # async fn example(signer: impl erc8128::Signer) -> Result<(), erc8128::Erc8128Error> {
//! let request = Request {
//!     method: "GET",
//!     url: "https://api.example.com/resource",
//!     headers: &[],
//!     body: None,
//! };
//! let signed = sign_request(&request, &signer, &SignOptions::default()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! [ERC-8128]: https://erc8128.org
//! [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421

mod error;
/// `KeyID` formatting and parsing (`erc8128:<chainId>:<address>`).
pub mod keyid;
/// Cryptographically secure nonce generation.
pub mod nonce;
pub(crate) mod sf;
pub(crate) mod sign;
pub(crate) mod traits;
pub(crate) mod types;
pub(crate) mod verify;

/// EOA signer and verifier using pure `k256` ECDSA.
#[cfg(feature = "k256")]
pub mod eoa;

/// Adapter for [`alloy_signer::Signer`] implementations.
#[cfg(feature = "alloy")]
pub mod alloy;

/// Axum middleware for ERC-8128 signature verification.
#[cfg(feature = "axum")]
pub mod middleware;

/// Reqwest client helpers for ERC-8128 signed requests.
#[cfg(feature = "reqwest")]
pub mod client;

pub use error::Erc8128Error;
pub use sign::sign_request;
pub use traits::{MemoryNonceStore, NoNonceStore, NonceStore, Signer, Verifier};
pub use types::{
    Address, Binding, ContentDigest, Replay, Request, SignOptions, SignatureParams, SignedHeaders,
    VerifyPolicy, VerifySuccess,
};
pub use verify::verify_request;
