//! # erc8128 — Signed HTTP Requests with Ethereum
//!
//! Rust implementation of [ERC-8128]: authenticate HTTP requests using
//! HTTP Message Signatures ([RFC 9421]) with Ethereum accounts.
//!
//! The crate provides two core operations:
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
//! // Attach signed.signature_input and signed.signature to your HTTP request.
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
mod sign;
mod verifier;
mod verify;

use std::future::Future;

pub use alloy_primitives::Address;
pub use error::Erc8128Error;
pub use sign::sign_request;
pub use verifier::Verifier;
pub use verify::verify_request;

/// No-op nonce store for replayable-only policies.
///
/// Always returns `false` (rejects nonce consumption). Use this when
/// your verification policy only allows replayable signatures.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoNonceStore;

/// An HTTP request to be signed or verified.
///
/// This is a simple, framework-agnostic representation. Callers construct it
/// from whatever HTTP library they use (reqwest, hyper, axum, etc.).
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub method: &'a str,
    /// Absolute URL (e.g. `"https://api.example.com/path?q=1"`).
    pub url: &'a str,
    /// Request headers as `(name, value)` pairs.
    pub headers: &'a [(&'a str, &'a str)],
    /// Request body bytes (if any).
    pub body: Option<&'a [u8]>,
}

/// How tightly a signature is bound to a specific request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Binding {
    /// Authorizes exactly one concrete HTTP request.
    #[default]
    RequestBound,
    /// Authorizes a class of requests defined by the covered components.
    ClassBound,
}

/// Whether a signature can be validly reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Replay {
    /// Includes a nonce; verifiers enforce uniqueness.
    #[default]
    NonReplayable,
    /// May be reused within the validity window.
    Replayable,
}

/// How to handle the `Content-Digest` header during signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentDigest {
    /// Use existing header if present, otherwise compute from body.
    #[default]
    Auto,
    /// Always recompute and overwrite.
    Recompute,
    /// Require header to exist; do not compute.
    Require,
    /// Disabled — error if content-digest is needed.
    Off,
}

/// RFC 9421 signature parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParams {
    /// Unix timestamp when the signature was created.
    pub created: u64,
    /// Unix timestamp when the signature expires.
    pub expires: u64,
    /// Identity binding: `erc8128:<chainId>:<address>`.
    pub keyid: String,
    /// Replay-prevention nonce (present for non-replayable signatures).
    pub nonce: Option<String>,
    /// Optional discriminator tag.
    pub tag: Option<String>,
}

/// Options for [`sign_request`].
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Signature label (default: `"eth"`).
    pub label: Option<String>,
    /// Binding mode (default: [`Binding::RequestBound`]).
    pub binding: Option<Binding>,
    /// Replay mode (default: [`Replay::NonReplayable`]).
    pub replay: Option<Replay>,
    /// Unix timestamp for `created` (default: now).
    pub created: Option<u64>,
    /// Unix timestamp for `expires` (default: `created + ttl_seconds`).
    pub expires: Option<u64>,
    /// Signature validity in seconds (default: 60).
    pub ttl_seconds: Option<u64>,
    /// Explicit nonce value (default: auto-generated).
    pub nonce: Option<String>,
    /// Content-Digest handling mode.
    pub content_digest: Option<ContentDigest>,
    /// Override or extend the signed components.
    pub components: Option<Vec<String>>,
}

/// Headers produced by [`sign_request`] to attach to the outgoing request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Value for the `Signature-Input` header.
    pub signature_input: String,
    /// Value for the `Signature` header.
    pub signature: String,
    /// Value for the `Content-Digest` header (if computed).
    pub content_digest: Option<String>,
}

/// Ethereum message signer.
///
/// Implement this trait to provide signing capability. The simplest case
/// wraps a local private key; more advanced implementations can use
/// hardware wallets or KMS.
///
/// `sign_message` receives the RFC 9421 signature base bytes. The
/// implementation MUST apply EIP-191 `personal_sign` wrapping
/// (`"\x19Ethereum Signed Message:\n" + len + message`) before signing.
pub trait Signer: Send + Sync {
    /// The Ethereum address of this signer.
    fn address(&self) -> Address;

    /// The chain id this signer is associated with.
    fn chain_id(&self) -> u64;

    /// Sign the RFC 9421 signature base as an EIP-191 personal message.
    ///
    /// Returns the raw signature bytes (65 bytes for EOA, variable for SCA).
    fn sign_message(
        &self,
        message: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Erc8128Error>> + Send;
}

/// Nonce store for replay protection.
///
/// Verifiers use this to ensure each nonce is consumed exactly once.
/// Implementations should use atomic operations in concurrent environments.
pub trait NonceStore: Send + Sync {
    /// Atomically consume a nonce. Returns `true` if newly consumed,
    /// `false` if already seen (replay).
    fn consume(&self, key: &str, ttl_seconds: u64) -> impl Future<Output = bool> + Send;
}

impl NonceStore for NoNonceStore {
    async fn consume(&self, _key: &str, _ttl_seconds: u64) -> bool {
        false
    }
}

/// Successful verification result.
#[derive(Debug, Clone)]
pub struct VerifySuccess {
    /// Authenticated Ethereum address.
    pub address: Address,
    /// Chain id from the keyid.
    pub chain_id: u64,
    /// Signature label (e.g. `"eth"`).
    pub label: String,
    /// Signed components.
    pub components: Vec<String>,
    /// Signature parameters.
    pub params: SignatureParams,
    /// Whether the signature is replayable (no nonce).
    pub replayable: bool,
    /// Binding mode.
    pub binding: Binding,
}

/// Policy for [`verify_request`].
#[derive(Debug, Clone)]
pub struct VerifyPolicy {
    /// Preferred signature label (default: `"eth"`).
    pub label: Option<String>,
    /// Require exact label match (default: `false`).
    pub strict_label: bool,
    /// Allow replayable (nonce-less) signatures (default: `false`).
    pub allow_replayable: bool,
    /// Maximum allowed validity window in seconds (default: 300).
    pub max_validity_sec: u64,
    /// Allowed clock drift in seconds (default: 0).
    pub clock_skew_sec: u64,
    /// Extra components required for request-bound signatures beyond the
    /// default set (`@authority`, `@method`, `@path`, `@query`, `content-digest`).
    pub additional_request_bound_components: Option<Vec<String>>,
    /// Class-bound component policies. `None` disables class-bound.
    pub class_bound_policies: Option<Vec<Vec<String>>>,
    /// Override "now" for testing (unix seconds).
    pub now: Option<u64>,
    /// Maximum number of candidate signatures to try (default: 3).
    pub max_signature_verifications: Option<usize>,
}

impl Default for VerifyPolicy {
    fn default() -> Self {
        Self {
            label: None,
            strict_label: false,
            allow_replayable: false,
            max_validity_sec: 300,
            clock_skew_sec: 0,
            additional_request_bound_components: None,
            class_bound_policies: None,
            now: None,
            max_signature_verifications: None,
        }
    }
}
