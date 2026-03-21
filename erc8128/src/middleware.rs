//! Axum middleware for ERC-8128 signature verification.
//!
//! Enabled by the `axum` feature. Provides a Tower [`Layer`] that
//! verifies incoming requests and injects [`VerifySuccess`] into
//! request extensions.
//!
//! # Examples
//!
//! ```ignore
//! use erc8128::middleware::Erc8128Layer;
//! use erc8128::eoa::EoaVerifier;
//! use erc8128::{MemoryNonceStore, RejectReplayable, VerifyPolicy};
//! use axum::{Router, routing::post, Extension};
//!
//! let app = Router::new()
//!     .route("/api", post(handler))
//!     .layer(Erc8128Layer::new(
//!         EoaVerifier,
//!         MemoryNonceStore::default(),
//!         RejectReplayable,
//!         VerifyPolicy::default(),
//!     ));
//!
//! async fn handler(Extension(auth): Extension<erc8128::VerifySuccess>) -> &'static str {
//!     "authenticated"
//! }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::traits::{NonceStore, ReplayablePolicy, Verifier};
use crate::types::VerifyPolicy;

/// Tower [`Layer`] that verifies ERC-8128 signatures on incoming requests.
///
/// On success, [`VerifySuccess`](crate::VerifySuccess) is inserted into
/// request extensions. On failure, responds with `401 Unauthorized`.
#[derive(Clone)]
pub struct Erc8128Layer<V, N, R> {
    verifier: Arc<V>,
    nonce_store: Arc<N>,
    replayable: Arc<R>,
    policy: VerifyPolicy,
    max_body_size: usize,
}

impl<V, N, R> Erc8128Layer<V, N, R> {
    /// Create a new verification layer.
    pub fn new(verifier: V, nonce_store: N, replayable: R, policy: VerifyPolicy) -> Self {
        Self {
            verifier: Arc::new(verifier),
            nonce_store: Arc::new(nonce_store),
            replayable: Arc::new(replayable),
            policy,
            max_body_size: 2 * 1024 * 1024,
        }
    }

    /// Set the maximum request body size for buffering (default: 2 `MiB`).
    #[must_use]
    pub const fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }
}

impl<V: std::fmt::Debug, N: std::fmt::Debug, R: std::fmt::Debug> std::fmt::Debug
    for Erc8128Layer<V, N, R>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Erc8128Layer")
            .field("max_body_size", &self.max_body_size)
            .finish_non_exhaustive()
    }
}

impl<S, V, N, R> tower::Layer<S> for Erc8128Layer<V, N, R>
where
    V: Clone,
    N: Clone,
    R: Clone,
{
    type Service = Erc8128Service<S, V, N, R>;

    fn layer(&self, inner: S) -> Self::Service {
        Erc8128Service {
            inner,
            verifier: Arc::clone(&self.verifier),
            nonce_store: Arc::clone(&self.nonce_store),
            replayable: Arc::clone(&self.replayable),
            policy: self.policy.clone(),
            max_body_size: self.max_body_size,
        }
    }
}

/// Tower [`Service`] that verifies ERC-8128 signatures.
///
/// Created by [`Erc8128Layer`]. Not typically used directly.
#[derive(Debug, Clone)]
pub struct Erc8128Service<S, V, N, R> {
    inner: S,
    verifier: Arc<V>,
    nonce_store: Arc<N>,
    replayable: Arc<R>,
    policy: VerifyPolicy,
    max_body_size: usize,
}

impl<S, V, N, R> tower::Service<Request<Body>> for Erc8128Service<S, V, N, R>
where
    S: tower::Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    V: Verifier + 'static,
    N: NonceStore + 'static,
    R: ReplayablePolicy + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let verifier = Arc::clone(&self.verifier);
        let nonce_store = Arc::clone(&self.nonce_store);
        let replayable = Arc::clone(&self.replayable);
        let policy = self.policy.clone();
        let max_body_size = self.max_body_size;

        Box::pin(async move {
            let (parts, body) = request.into_parts();

            let Ok(bytes) = axum::body::to_bytes(body, max_body_size).await else {
                return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
            };

            let scheme = parts
                .headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("https");
            let host = parts
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            let url = format!("{scheme}://{host}{}", parts.uri);

            let header_pairs: Vec<(String, String)> = parts
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect();
            let header_refs: Vec<(&str, &str)> = header_pairs
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();

            let body_ref = if bytes.is_empty() {
                None
            } else {
                Some(bytes.as_ref())
            };

            let req = crate::types::Request {
                method: parts.method.as_str(),
                url: &url,
                headers: &header_refs,
                body: body_ref,
            };

            match crate::verify::verify_request(
                &req,
                verifier.as_ref(),
                nonce_store.as_ref(),
                replayable.as_ref(),
                &policy,
            )
            .await
            {
                Ok(success) => {
                    let mut request = Request::from_parts(parts, Body::from(bytes));
                    request.extensions_mut().insert(success);
                    inner.call(request).await
                }
                Err(_) => Ok(StatusCode::UNAUTHORIZED.into_response()),
            }
        })
    }
}
