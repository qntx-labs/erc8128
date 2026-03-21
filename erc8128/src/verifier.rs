use std::future::Future;

use alloy_primitives::Address;

use crate::Erc8128Error;

/// Signature verifier for Ethereum accounts.
///
/// Implementors provide chain-specific verification logic:
/// - **EOA** — recover the signer via EIP-191 `personal_sign` and compare
/// - **SCA** — call `isValidSignature` (ERC-1271) on-chain
///
/// Verification is async to accommodate on-chain RPC calls; purely
/// computational verifiers simply wrap their synchronous logic in `async {}`.
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
