//! Adapter for [`alloy_signer::Signer`] implementations.
//!
//! Enabled by the `alloy` feature. Wraps any alloy signer (e.g.
//! `PrivateKeySigner`, hardware wallets, KMS) into our [`Signer`] trait.
//!
//! # Examples
//!
//! ```ignore
//! use alloy_signer_local::PrivateKeySigner;
//! use erc8128::alloy::AlloySigner;
//!
//! let wallet = PrivateKeySigner::random();
//! let signer = AlloySigner::new(wallet, 1);
//! ```

use alloy_primitives::Address;

use crate::error::Erc8128Error;

/// Adapter wrapping any [`alloy_signer::Signer`] into our [`Signer`](crate::Signer) trait.
///
/// The inner signer's `sign_message` already applies EIP-191 wrapping.
#[derive(Debug, Clone)]
pub struct AlloySigner<S> {
    inner: S,
    chain_id: u64,
}

impl<S> AlloySigner<S> {
    /// Wrap an alloy signer with the given chain id.
    #[must_use]
    pub const fn new(inner: S, chain_id: u64) -> Self {
        Self { inner, chain_id }
    }

    /// Returns a reference to the inner signer.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S> crate::traits::Signer for AlloySigner<S>
where
    S: alloy_signer::Signer + Send + Sync,
{
    fn address(&self) -> Address {
        alloy_signer::Signer::address(&self.inner)
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Erc8128Error> {
        let sig = alloy_signer::Signer::sign_message(&self.inner, message)
            .await
            .map_err(|e| Erc8128Error::SigningFailed(e.to_string()))?;
        Ok(sig.as_bytes().to_vec())
    }
}
