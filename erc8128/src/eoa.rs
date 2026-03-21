//! EOA signer and verifier using pure `k256` ECDSA.
//!
//! Enabled by the `k256` feature. Provides lightweight, zero-dependency
//! (beyond `k256` + `alloy-primitives`) implementations of [`Signer`] and
//! [`Verifier`] for Externally Owned Accounts.
//!
//! # Examples
//!
//! ```no_run
//! use erc8128::eoa::{EoaSigner, EoaVerifier};
//!
//! # fn example() -> Result<(), erc8128::Erc8128Error> {
//! let signer = EoaSigner::from_slice(&[0u8; 32], 1)?;
//! let verifier = EoaVerifier;
//! # Ok(())
//! # }
//! ```

use alloy_primitives::{Address, keccak256};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

use crate::error::Erc8128Error;

/// EOA signer backed by a `k256` private key.
///
/// Applies EIP-191 `personal_sign` wrapping internally.
#[derive(Clone)]
pub struct EoaSigner {
    key: SigningKey,
    address: Address,
    chain_id: u64,
}

impl std::fmt::Debug for EoaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EoaSigner")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl EoaSigner {
    /// Create from a [`SigningKey`].
    #[must_use]
    pub fn new(key: SigningKey, chain_id: u64) -> Self {
        let address = pubkey_to_address(key.verifying_key());
        Self {
            key,
            address,
            chain_id,
        }
    }

    /// Create from a raw private key byte slice (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not a valid secp256k1 private key.
    pub fn from_slice(private_key: &[u8], chain_id: u64) -> Result<Self, Erc8128Error> {
        let key = SigningKey::from_slice(private_key)
            .map_err(|e| Erc8128Error::SigningFailed(e.to_string()))?;
        Ok(Self::new(key, chain_id))
    }
}

impl crate::traits::Signer for EoaSigner {
    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Erc8128Error> {
        let hash = eip191_hash(message);
        let (sig, recid): (Signature, RecoveryId) = self
            .key
            .sign_prehash(&hash)
            .map_err(|e| Erc8128Error::SigningFailed(e.to_string()))?;

        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.to_bytes());
        out.push(recid.to_byte() + 27);
        Ok(out)
    }
}

/// EOA signature verifier using `k256` ecrecover.
///
/// Recovers the signer address from the ECDSA signature and compares
/// it against the expected address. Pure computation, no RPC needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct EoaVerifier;

impl crate::traits::Verifier for EoaVerifier {
    async fn verify(
        &self,
        address: Address,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Erc8128Error> {
        if signature.len() != 65 {
            return Err(Erc8128Error::BadSignature);
        }

        let hash = eip191_hash(message);

        let v = signature[64];
        let recid = RecoveryId::from_byte(v.wrapping_sub(27)).ok_or(Erc8128Error::BadSignature)?;
        let sig =
            Signature::from_slice(&signature[..64]).map_err(|_| Erc8128Error::BadSignature)?;

        let recovered = VerifyingKey::recover_from_prehash(&hash, &sig, recid)
            .map_err(|_| Erc8128Error::BadSignature)?;

        let recovered_addr = pubkey_to_address(&recovered);
        if recovered_addr != address {
            return Err(Erc8128Error::BadSignature);
        }

        Ok(())
    }
}

fn eip191_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = Vec::with_capacity(prefix.len() + message.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(message);
    keccak256(&data).into()
}

fn pubkey_to_address(key: &VerifyingKey) -> Address {
    let uncompressed = key.to_encoded_point(false);
    let hash = keccak256(&uncompressed.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Signer, Verifier};

    #[tokio::test]
    async fn sign_and_verify_roundtrip() {
        let key_bytes = keccak256(b"test-private-key");
        let signer = EoaSigner::from_slice(key_bytes.as_slice(), 1).expect("valid key");
        let verifier = EoaVerifier;

        let message = b"hello world";
        let signature = signer.sign_message(message).await.expect("sign ok");

        assert_eq!(signature.len(), 65);

        verifier
            .verify(signer.address(), message, &signature)
            .await
            .expect("verify ok");
    }

    #[tokio::test]
    async fn verify_wrong_address_fails() {
        let key_bytes = keccak256(b"test-private-key");
        let signer = EoaSigner::from_slice(key_bytes.as_slice(), 1).expect("valid key");
        let verifier = EoaVerifier;

        let message = b"hello world";
        let signature = signer.sign_message(message).await.expect("sign ok");

        let wrong_address = Address::ZERO;
        let result = verifier.verify(wrong_address, message, &signature).await;
        assert!(result.is_err());
    }
}
