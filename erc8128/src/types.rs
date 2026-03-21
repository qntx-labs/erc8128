//! Public data types for ERC-8128 signing and verification.

pub use alloy_primitives::Address;

/// An HTTP request to be signed or verified.
///
/// Framework-agnostic, zero-copy representation. Construct from whatever
/// HTTP library you use (reqwest, hyper, axum, etc.).
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

/// Options for [`sign_request`](crate::sign_request).
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Signature label (default: `"eth"`).
    pub label: Option<String>,
    /// Binding mode.
    pub binding: Binding,
    /// Replay mode.
    pub replay: Replay,
    /// Unix timestamp for `created` (default: now).
    pub created: Option<u64>,
    /// Unix timestamp for `expires` (default: `created + ttl_seconds`).
    pub expires: Option<u64>,
    /// Signature validity in seconds (default: 60).
    pub ttl_seconds: Option<u64>,
    /// Explicit nonce value (default: auto-generated).
    pub nonce: Option<String>,
    /// Content-Digest handling mode.
    pub content_digest: ContentDigest,
    /// Override or extend the signed components.
    pub components: Option<Vec<String>>,
    /// Application-specific tag (e.g. `"erc8128-login"`).
    pub tag: Option<String>,
}

/// Headers produced by [`sign_request`](crate::sign_request).
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Value for the `Signature-Input` header.
    pub signature_input: String,
    /// Value for the `Signature` header.
    pub signature: String,
    /// Value for the `Content-Digest` header (if computed).
    pub content_digest: Option<String>,
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

/// Information about a replayable signature, passed to
/// [`ReplayablePolicy::invalidated`](crate::ReplayablePolicy::invalidated).
#[derive(Debug, Clone)]
pub struct ReplayableInfo<'a> {
    /// Identity: `erc8128:<chainId>:<address>`.
    pub keyid: &'a str,
    /// Unix timestamp when the signature was created.
    pub created: u64,
    /// Unix timestamp when the signature expires.
    pub expires: u64,
    /// Signature label (e.g. `"eth"`).
    pub label: &'a str,
    /// Raw decoded signature bytes.
    pub signature: &'a [u8],
    /// Reconstructed RFC 9421 signature base.
    pub signature_base: &'a [u8],
    /// Raw `Signature-Input` member value.
    pub params_value: &'a str,
}

/// Policy for [`verify_request`](crate::verify_request).
#[derive(Debug, Clone)]
pub struct VerifyPolicy {
    /// Preferred signature label (default: `"eth"`).
    pub label: Option<String>,
    /// Require exact label match (default: `false`).
    pub strict_label: bool,
    /// Maximum allowed validity window in seconds (default: 300).
    pub max_validity_sec: u64,
    /// Allowed clock drift in seconds (default: 0).
    pub clock_skew_sec: u64,
    /// Maximum nonce retention window in seconds. Non-replayable signatures
    /// with `expires - created` exceeding this are rejected. `None` disables.
    pub max_nonce_window_sec: Option<u64>,
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
            max_validity_sec: 300,
            clock_skew_sec: 0,
            max_nonce_window_sec: None,
            additional_request_bound_components: None,
            class_bound_policies: None,
            now: None,
            max_signature_verifications: None,
        }
    }
}
