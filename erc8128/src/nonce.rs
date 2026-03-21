//! Cryptographically secure nonce generation for replay-attack prevention.

use rand::RngExt as _;

/// Default nonce length in characters.
const DEFAULT_LEN: usize = 22;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Generates a random base64url-safe nonce of `len` characters.
///
/// # Panics
///
/// Panics if `len == 0`.
///
/// # Examples
///
/// ```
/// let nonce = erc8128::nonce::generate(22);
/// assert_eq!(nonce.len(), 22);
/// ```
#[must_use]
pub fn generate(len: usize) -> String {
    assert!(len > 0, "nonce length must be > 0");
    let mut rng = rand::rng();
    (0..len)
        .map(|_| ALPHABET[rng.random_range(..ALPHABET.len())] as char)
        .collect()
}

/// Generates a random nonce with the default length (22 characters).
///
/// # Examples
///
/// ```
/// let nonce = erc8128::nonce::generate_default();
/// assert_eq!(nonce.len(), 22);
/// ```
#[must_use]
pub fn generate_default() -> String {
    generate(DEFAULT_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_has_correct_length() {
        assert_eq!(generate(8).len(), 8);
        assert_eq!(generate(32).len(), 32);
    }

    #[test]
    fn nonce_is_url_safe() {
        let n = generate(100);
        assert!(
            n.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn default_nonce_length() {
        assert_eq!(generate_default().len(), 22);
    }

    #[test]
    #[should_panic(expected = "nonce length must be > 0")]
    fn zero_length_panics() {
        let _ = generate(0);
    }
}
