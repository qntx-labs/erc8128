/// Errors produced by ERC-8128 operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Erc8128Error {
    /// A required field is empty or the overall format is wrong.
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// The `keyid` does not match `erc8128:<chainId>:<address>`.
    #[error("invalid keyid: {0}")]
    InvalidKeyId(String),

    /// A Structured Fields value contains forbidden characters.
    #[error("invalid header value: {0}")]
    InvalidHeaderValue(String),

    /// A derived component (`@method`, `@authority`, …) produced invalid output.
    #[error("invalid derived value: {0}")]
    InvalidDerivedValue(String),

    /// The request URL is not absolute or cannot be parsed.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// Sign/verify options are invalid (e.g. `expires <= created`).
    #[error("invalid options: {0}")]
    InvalidOptions(String),

    /// `content-digest` is required but missing, or the digest does not match.
    #[error("digest error: {0}")]
    DigestError(String),

    /// The request body could not be read.
    #[error("body read failed: {0}")]
    BodyReadFailed(String),

    /// The signer returned an empty or malformed signature.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// `Signature-Input` / `Signature` headers are missing.
    #[error("missing signature headers")]
    MissingHeaders,

    /// The signature label was not found in the headers.
    #[error("label not found")]
    LabelNotFound,

    /// `Signature-Input` / `Signature` headers could not be parsed.
    #[error("bad signature input: {0}")]
    BadSignatureInput(String),

    /// The signature is cryptographically invalid.
    #[error("bad signature")]
    BadSignature,

    /// The `keyid` in the signature does not parse as a valid ERC-8128 keyid.
    #[error("bad keyid")]
    BadKeyId,

    /// `created` / `expires` are missing or non-integer.
    #[error("bad time")]
    BadTime,

    /// The request is not yet valid (`now < created`).
    #[error("not yet valid")]
    NotYetValid,

    /// The request has expired (`now > expires`).
    #[error("expired")]
    Expired,

    /// `expires - created` exceeds the allowed maximum.
    #[error("validity too long")]
    ValidityTooLong,

    /// A nonce is required but missing (non-replayable policy).
    #[error("nonce required")]
    NonceRequired,

    /// Replayable signatures are not allowed by policy.
    #[error("replayable not allowed")]
    ReplayableNotAllowed,

    /// The signed components do not satisfy request-bound requirements.
    #[error("not request bound")]
    NotRequestBound,

    /// The signed components do not match any class-bound policy.
    #[error("class bound not allowed")]
    ClassBoundNotAllowed,

    /// The nonce has already been consumed (replay detected).
    #[error("replay detected")]
    Replay,

    /// `content-digest` header is required by components but missing.
    #[error("digest required")]
    DigestRequired,

    /// `content-digest` value does not match the body.
    #[error("digest mismatch")]
    DigestMismatch,

    /// The cryptographic verification check itself failed (e.g. RPC error).
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}
