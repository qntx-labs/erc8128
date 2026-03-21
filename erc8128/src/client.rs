//! Reqwest client helpers for ERC-8128 signed requests.
//!
//! Enabled by the `reqwest` feature. Provides [`signed_fetch`] for
//! sending authenticated HTTP requests in one call.
//!
//! # Examples
//!
//! ```ignore
//! use erc8128::client::signed_fetch;
//! use erc8128::eoa::EoaSigner;
//! use erc8128::SignOptions;
//!
//! let client = reqwest::Client::new();
//! let signer = EoaSigner::from_slice(&key_bytes, 1)?;
//!
//! let response = signed_fetch(
//!     &client,
//!     reqwest::Method::POST,
//!     "https://api.example.com/orders",
//!     &[("content-type", "application/json")],
//!     Some(b"{\"amount\":100}"),
//!     &signer,
//!     &SignOptions::default(),
//! ).await?;
//! ```

use crate::error::Erc8128Error;
use crate::traits::Signer;
use crate::types::{Request, SignOptions};

/// Error type for [`signed_fetch`].
#[derive(Debug, thiserror::Error)]
pub enum SignedFetchError {
    /// ERC-8128 signing failed.
    #[error(transparent)]
    Sign(#[from] Erc8128Error),
    /// HTTP request failed.
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

/// Send an ERC-8128 signed HTTP request.
///
/// Constructs the request, signs it, attaches `Signature-Input`,
/// `Signature`, and (optionally) `Content-Digest` headers, then sends.
///
/// # Errors
///
/// Returns [`SignedFetchError`] on signing or transport failure.
pub async fn signed_fetch(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    signer: &impl Signer,
    opts: &SignOptions,
) -> Result<reqwest::Response, SignedFetchError> {
    let req = Request {
        method: method.as_str(),
        url,
        headers,
        body,
    };

    let signed = crate::sign::sign_request(&req, signer, opts).await?;

    let mut builder = client.request(method, url);
    for &(name, value) in headers {
        builder = builder.header(name, value);
    }
    builder = builder.header("signature-input", &signed.signature_input);
    builder = builder.header("signature", &signed.signature);
    if let Some(digest) = &signed.content_digest {
        builder = builder.header("content-digest", digest);
    }
    if let Some(body) = body {
        builder = builder.body(body.to_vec());
    }

    Ok(builder.send().await?)
}
