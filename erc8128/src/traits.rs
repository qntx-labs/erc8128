//! Core traits for ERC-8128 signing and verification.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::error::Erc8128Error;
use crate::types::{Address, ReplayableInfo};

/// Ethereum message signer.
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

/// Signature verifier for Ethereum accounts.
///
/// Implementors provide chain-specific verification logic:
/// - **EOA** — recover the signer via EIP-191 `personal_sign` and compare
/// - **SCA** — call `isValidSignature` (ERC-1271) on-chain
///
/// # Contract
///
/// * Return `Ok(())` when the signature is **valid** for the given message.
/// * Return `Err(Erc8128Error::VerificationFailed(..))` on cryptographic failure.
/// * Return other `Err` variants for malformed inputs.
pub trait Verifier: Send + Sync {
    /// Verify that `signature` is a valid Ethereum signature over `message`
    /// by `address`.
    fn verify(
        &self,
        address: Address,
        message: &[u8],
        signature: &[u8],
    ) -> impl Future<Output = Result<(), Erc8128Error>> + Send;
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

/// In-memory nonce store for development and testing.
///
/// Thread-safe via `Arc<Mutex<_>>`. Nonces are never evicted.
/// Use a TTL-aware store (Redis, `DashMap`, etc.) in production.
#[derive(Debug, Clone, Default)]
pub struct MemoryNonceStore {
    seen: Arc<Mutex<HashSet<String>>>,
}

impl NonceStore for MemoryNonceStore {
    async fn consume(&self, key: &str, _ttl_seconds: u64) -> bool {
        self.seen
            .lock()
            .expect("lock poisoned")
            .insert(key.to_owned())
    }
}

/// No-op nonce store that rejects all nonces.
///
/// Always returns `false` (= replay). Use only with replayable-only
/// policies where nonce consumption never occurs.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoNonceStore;

impl NonceStore for NoNonceStore {
    async fn consume(&self, _key: &str, _ttl_seconds: u64) -> bool {
        false
    }
}

/// Policy for replayable (nonce-less) signature acceptance and invalidation.
///
/// Required by ERC-8128 Section 3.2.2 + 5.2: verifiers that accept
/// replayable signatures **MUST** implement early invalidation mechanisms.
///
/// Use [`RejectReplayable`] (default) to reject all replayable signatures.
pub trait ReplayablePolicy: Send + Sync {
    /// Whether to accept replayable (nonce-less) signatures.
    fn allow(&self) -> bool;

    /// Return a `not_before` timestamp for the given `keyid`.
    /// Signatures with `created < not_before` are rejected.
    /// Return `None` to skip this check.
    fn not_before(&self, keyid: &str) -> impl Future<Output = Option<u64>> + Send;

    /// Check if a specific replayable signature has been invalidated.
    /// Return `true` to reject the signature.
    fn invalidated(&self, info: &ReplayableInfo<'_>) -> impl Future<Output = bool> + Send;
}

/// Reject all replayable signatures (default secure behavior).
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectReplayable;

impl ReplayablePolicy for RejectReplayable {
    fn allow(&self) -> bool {
        false
    }

    async fn not_before(&self, _keyid: &str) -> Option<u64> {
        None
    }

    async fn invalidated(&self, _info: &ReplayableInfo<'_>) -> bool {
        false
    }
}
