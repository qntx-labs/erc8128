use alloy_primitives::Address;

/// Format a `keyid` from chain id and address.
///
/// Produces `erc8128:<chainId>:<lowercased-address>`.
#[must_use]
pub fn format_keyid(chain_id: u64, address: Address) -> String {
    // ERC-8128 requires lowercased address in keyid.
    // Address::to_string() produces EIP-55 checksum; lowercase it.
    format!("erc8128:{chain_id}:{}", address.to_string().to_lowercase())
}

/// Parse a `keyid` string into `(chain_id, address)`.
///
/// Returns `None` if the format does not match `erc8128:<digits>:<0x hex40>`.
#[must_use]
pub fn parse_keyid(keyid: &str) -> Option<(u64, Address)> {
    let rest = keyid.strip_prefix("erc8128:")?;
    let (chain_str, addr_str) = rest.split_once(':')?;
    let chain_id = chain_str.parse::<u64>().ok()?;
    let address = addr_str.parse::<Address>().ok()?;
    Some((chain_id, address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let addr: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let kid = format_keyid(1, addr);
        assert!(kid.starts_with("erc8128:1:0x"));
        let (chain_id, parsed_addr) = parse_keyid(&kid).unwrap();
        assert_eq!(chain_id, 1);
        assert_eq!(parsed_addr, addr);
    }

    #[test]
    fn parse_invalid() {
        assert!(parse_keyid("not-erc8128:1:0x0000000000000000000000000000000000000000").is_none());
        assert!(parse_keyid("erc8128:abc:0x0000000000000000000000000000000000000000").is_none());
        assert!(parse_keyid("erc8128:1:notanaddress").is_none());
        assert!(parse_keyid("").is_none());
    }
}
