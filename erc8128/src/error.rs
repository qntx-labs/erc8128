/// Errors produced by ERC-8128 signing and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Erc8128Error {
    // -- Signing errors --
    /// The request URL is not absolute or cannot be parsed.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// Sign/verify options are invalid (e.g. `expires <= created`).
    #[error("invalid options: {0}")]
    InvalidOptions(String),

    /// A Structured Fields value contains forbidden characters.
    #[error("invalid header value: {0}")]
    InvalidHeaderValue(String),

    /// A derived component (`@method`, `@authority`, …) produced non-visible-ASCII.
    #[error("invalid derived value: {0}")]
    InvalidDerivedValue(String),

    /// A required field is empty or the overall format is wrong.
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// `content-digest` handling failed during signing.
    #[error("digest error: {0}")]
    DigestError(String),

    /// The signer returned an empty or malformed signature.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    // -- Verification errors --
    /// `Signature-Input` / `Signature` headers are missing.
    #[error("missing signature headers")]
    MissingHeaders,

    /// The requested signature label was not found.
    #[error("label not found")]
    LabelNotFound,

    /// `Signature-Input` / `Signature` could not be parsed.
    #[error("bad signature input: {0}")]
    BadSignatureInput(String),

    /// The `keyid` does not match `erc8128:<chainId>:<address>`.
    #[error("bad keyid")]
    BadKeyId,

    /// `created` / `expires` are missing, non-integer, or `expires <= created`.
    #[error("bad time")]
    BadTime,

    /// Signature is not yet valid (`now + skew < created`).
    #[error("not yet valid")]
    NotYetValid,

    /// Signature has expired (`now - skew > expires`).
    #[error("expired")]
    Expired,

    /// `expires - created` exceeds the policy maximum.
    #[error("validity too long")]
    ValidityTooLong,

    /// Non-replayable signature requires a nonce but none was provided.
    #[error("nonce required")]
    NonceRequired,

    /// Replayable (nonce-less) signature rejected by policy.
    #[error("replayable not allowed")]
    ReplayableNotAllowed,

    /// Replayable signature accepted but no invalidation mechanism is provided.
    /// Required by ERC-8128 Section 3.2.2 + 5.2.
    #[error("replayable invalidation required")]
    ReplayableInvalidationRequired,

    /// Replayable signature rejected: `created` before the per-key `not_before` cutoff.
    #[error("replayable not before")]
    ReplayableNotBefore,

    /// Replayable signature explicitly invalidated by policy hook.
    #[error("replayable invalidated")]
    ReplayableInvalidated,

    /// Signed components do not satisfy request-bound requirements.
    #[error("not request bound")]
    NotRequestBound,

    /// Signed components do not match any class-bound policy.
    #[error("class bound not allowed")]
    ClassBoundNotAllowed,

    /// `expires - created` exceeds the nonce retention window.
    #[error("nonce window too long")]
    NonceWindowTooLong,

    /// `content-digest` header required by components but missing.
    #[error("digest required")]
    DigestRequired,

    /// `content-digest` value does not match the body.
    #[error("digest mismatch")]
    DigestMismatch,

    /// Signature bytes could not be decoded (bad base64 or empty).
    #[error("bad signature bytes")]
    BadSignatureBytes,

    /// The signature is cryptographically invalid.
    #[error("bad signature")]
    BadSignature,

    /// The nonce has already been consumed (replay detected).
    #[error("replay detected")]
    Replay,

    /// Algorithm is not allowed by policy.
    #[error("algorithm not allowed")]
    AlgNotAllowed,

    /// The cryptographic verification call itself failed (e.g. RPC error).
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}
