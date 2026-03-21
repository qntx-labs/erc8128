//! Reqwest client helpers for ERC-8128 signed requests.
//!
//! Enabled by the `reqwest` feature.
//!
//! - [`signed_fetch`] — sign and send in one call
//! - [`RequestBuilderExt`] — apply pre-computed [`SignedHeaders`] to a builder

use crate::error::Erc8128Error;
use crate::traits::Signer;
use crate::types::{Request, SignOptions, SignedHeaders};

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

/// Extension trait for applying [`SignedHeaders`] to a [`reqwest::RequestBuilder`].
pub trait RequestBuilderExt {
    /// Attach `Signature-Input`, `Signature`, and `Content-Digest` headers.
    #[must_use]
    fn signed_headers(self, signed: &SignedHeaders) -> Self;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn signed_headers(self, signed: &SignedHeaders) -> Self {
        let b = self
            .header("signature-input", &signed.signature_input)
            .header("signature", &signed.signature);
        match &signed.content_digest {
            Some(d) => b.header("content-digest", d),
            None => b,
        }
    }
}

/// Sign and send an HTTP request in one call.
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
    builder = builder.signed_headers(&signed);
    if let Some(body) = body {
        builder = builder.body(body.to_vec());
    }

    Ok(builder.send().await?)
}
