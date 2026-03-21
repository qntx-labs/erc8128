//! Minimal RFC 9421 Structured Fields serialization and parsing.
//!
//! Only the subset required by ERC-8128 is implemented: sf-string, sf-binary,
//! sf-integer, inner-list with parameters, and dictionary members.

use std::fmt::Write;

use crate::{Erc8128Error, SignatureParams, sign::validate_label};

/// Quote a value as an sf-string: `"value"` with `\` and `"` escaped.
///
/// # Errors
///
/// Returns an error if the value contains control characters.
pub fn quote_sf_string(value: &str) -> Result<String, Erc8128Error> {
    for b in value.bytes() {
        if b <= 0x1F || b == 0x7F {
            return Err(Erc8128Error::InvalidHeaderValue(
                "sf-string cannot contain control characters".into(),
            ));
        }
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

/// Serialize the `Signature-Input` member value (inner-list + params).
///
/// Produces: `("@authority" "@method" ...);created=N;expires=N;nonce="...";keyid="..."`
///
/// # Errors
///
/// Returns an error if `expires <= created` or `keyid` is empty.
pub fn serialize_signature_params(
    components: &[String],
    params: &SignatureParams,
) -> Result<String, Erc8128Error> {
    if params.expires <= params.created {
        return Err(Erc8128Error::InvalidOptions(
            "expires must be > created".into(),
        ));
    }
    if params.keyid.is_empty() {
        return Err(Erc8128Error::InvalidOptions("keyid is required".into()));
    }

    let items: Vec<String> = components
        .iter()
        .map(|c| quote_sf_string(c))
        .collect::<Result<_, _>>()?;

    let mut out = format!("({})", items.join(" "));
    let _ = write!(out, ";created={}", params.created);
    let _ = write!(out, ";expires={}", params.expires);
    if let Some(ref nonce) = params.nonce {
        let _ = write!(out, ";nonce={}", quote_sf_string(nonce)?);
    }
    if let Some(ref tag) = params.tag {
        let _ = write!(out, ";tag={}", quote_sf_string(tag)?);
    }
    let _ = write!(out, ";keyid={}", quote_sf_string(&params.keyid)?);
    Ok(out)
}

/// A parsed `Signature-Input` dictionary member.
#[derive(Debug)]
pub struct ParsedSignatureInput {
    pub label: String,
    pub components: Vec<String>,
    pub params: SignatureParams,
    /// Raw member value after `label=` (for signature base reconstruction).
    pub params_value: String,
}

/// Parse the `Signature-Input` header into a list of members.
///
/// # Errors
///
/// Returns an error on malformed input.
pub fn parse_signature_input_dictionary(
    header: &str,
) -> Result<Vec<ParsedSignatureInput>, Erc8128Error> {
    let mut result = Vec::new();
    for raw in split_top_level_commas(header) {
        let m = raw.trim();
        if m.is_empty() {
            continue;
        }
        let eq = m
            .find('=')
            .filter(|&i| i > 0)
            .ok_or_else(|| Erc8128Error::BadSignatureInput("missing '='".into()))?;
        let label = m[..eq].trim();
        validate_label(label)?;
        let value = m[eq + 1..].trim().to_owned();
        let parsed = parse_inner_list_with_params(&value)?;
        result.push(ParsedSignatureInput {
            label: label.to_owned(),
            components: parsed.items,
            params: parsed.params,
            params_value: value,
        });
    }
    Ok(result)
}

/// Parse the `Signature` header into a map of `label -> base64`.
///
/// # Errors
///
/// Returns an error on malformed input.
pub fn parse_signature_dictionary(
    header: &str,
) -> Result<std::collections::HashMap<String, String>, Erc8128Error> {
    let mut map = std::collections::HashMap::new();
    for raw in split_top_level_commas(header) {
        let m = raw.trim();
        if m.is_empty() {
            continue;
        }
        let eq = m
            .find('=')
            .filter(|&i| i > 0)
            .ok_or_else(|| Erc8128Error::BadSignatureInput("missing '='".into()))?;
        let label = m[..eq].trim();
        validate_label(label)?;
        let value = m[eq + 1..].trim();
        let b64 = parse_sf_binary(value)?;
        map.insert(label.to_owned(), b64);
    }
    Ok(map)
}

fn parse_sf_binary(v: &str) -> Result<String, Erc8128Error> {
    let s = v.trim();
    if !s.starts_with(':') || !s.ends_with(':') || s.len() < 3 {
        return Err(Erc8128Error::BadSignatureInput("invalid sf-binary".into()));
    }
    let inner = &s[1..s.len() - 1];
    if !inner
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(Erc8128Error::BadSignatureInput(
            "invalid base64 in sf-binary".into(),
        ));
    }
    Ok(inner.to_owned())
}

struct ParsedInnerList {
    items: Vec<String>,
    params: SignatureParams,
}

fn parse_inner_list_with_params(value: &str) -> Result<ParsedInnerList, Erc8128Error> {
    let s = value.trim();
    let bytes = s.as_bytes();
    let mut i = 0;

    if bytes.get(i).copied() != Some(b'(') {
        return Err(Erc8128Error::BadSignatureInput(
            "inner list must start with '('".into(),
        ));
    }
    i += 1;

    let mut items = Vec::new();
    loop {
        skip_ws(bytes, &mut i);
        if bytes.get(i).copied() == Some(b')') {
            i += 1;
            break;
        }
        if i >= bytes.len() {
            return Err(Erc8128Error::BadSignatureInput(
                "unterminated inner list".into(),
            ));
        }
        items.push(parse_sf_string_at(s, bytes, &mut i)?);
        skip_ws(bytes, &mut i);
    }

    if items.is_empty() {
        return Err(Erc8128Error::BadSignatureInput(
            "inner list has no items".into(),
        ));
    }

    // Parse parameters
    let mut params_map = std::collections::HashMap::<String, ParamValue>::new();
    while i < bytes.len() {
        skip_ws(bytes, &mut i);
        if bytes.get(i).copied() != Some(b';') {
            break;
        }
        i += 1;
        skip_ws(bytes, &mut i);
        let key = parse_token(s, bytes, &mut i)?;
        skip_ws(bytes, &mut i);
        if bytes.get(i).copied() != Some(b'=') {
            return Err(Erc8128Error::BadSignatureInput(format!(
                "param {key} missing '='"
            )));
        }
        i += 1;
        skip_ws(bytes, &mut i);
        let val = parse_param_value(s, bytes, &mut i)?;
        params_map.insert(key, val);
    }

    let created = match params_map.get("created") {
        Some(ParamValue::Integer(n)) => *n,
        _ => {
            return Err(Erc8128Error::BadSignatureInput(
                "missing or invalid created".into(),
            ));
        }
    };
    let expires = match params_map.get("expires") {
        Some(ParamValue::Integer(n)) => *n,
        _ => {
            return Err(Erc8128Error::BadSignatureInput(
                "missing or invalid expires".into(),
            ));
        }
    };
    let keyid = match params_map.get("keyid") {
        Some(ParamValue::Str(s)) => s.clone(),
        _ => {
            return Err(Erc8128Error::BadSignatureInput(
                "missing or invalid keyid".into(),
            ));
        }
    };
    let nonce = params_map.get("nonce").and_then(|v| match v {
        ParamValue::Str(s) => Some(s.clone()),
        ParamValue::Integer(_) => None,
    });
    let tag = params_map.get("tag").and_then(|v| match v {
        ParamValue::Str(s) => Some(s.clone()),
        ParamValue::Integer(_) => None,
    });

    Ok(ParsedInnerList {
        items,
        params: SignatureParams {
            created: u64::try_from(created)
                .map_err(|_| Erc8128Error::BadSignatureInput("created out of range".into()))?,
            expires: u64::try_from(expires)
                .map_err(|_| Erc8128Error::BadSignatureInput("expires out of range".into()))?,
            keyid,
            nonce,
            tag,
        },
    })
}

#[derive(Debug)]
enum ParamValue {
    Str(String),
    Integer(i64),
}

fn skip_ws(bytes: &[u8], i: &mut usize) {
    while *i < bytes.len() && (bytes[*i] == b' ' || bytes[*i] == b'\t') {
        *i += 1;
    }
}

fn parse_sf_string_at(_s: &str, bytes: &[u8], i: &mut usize) -> Result<String, Erc8128Error> {
    if bytes.get(*i).copied() != Some(b'"') {
        return Err(Erc8128Error::BadSignatureInput("expected sf-string".into()));
    }
    *i += 1;
    let mut out = String::new();
    while *i < bytes.len() {
        let ch = bytes[*i];
        if ch == b'"' {
            *i += 1;
            return Ok(out);
        }
        if ch == b'\\' {
            *i += 1;
            if *i >= bytes.len() {
                return Err(Erc8128Error::BadSignatureInput(
                    "bad escape in sf-string".into(),
                ));
            }
            out.push(bytes[*i] as char);
            *i += 1;
            continue;
        }
        if ch < 0x20 || ch == 0x7F {
            return Err(Erc8128Error::BadSignatureInput(
                "control char in sf-string".into(),
            ));
        }
        out.push(ch as char);
        *i += 1;
    }
    Err(Erc8128Error::BadSignatureInput(
        "unterminated sf-string".into(),
    ))
}

fn parse_token(s: &str, bytes: &[u8], i: &mut usize) -> Result<String, Erc8128Error> {
    let start = *i;
    while *i < bytes.len()
        && (bytes[*i].is_ascii_alphanumeric()
            || bytes[*i] == b'_'
            || bytes[*i] == b'-'
            || bytes[*i] == b'*'
            || bytes[*i] == b'.')
    {
        *i += 1;
    }
    if *i == start {
        return Err(Erc8128Error::BadSignatureInput("expected token".into()));
    }
    Ok(s[start..*i].to_owned())
}

fn parse_param_value(s: &str, bytes: &[u8], i: &mut usize) -> Result<ParamValue, Erc8128Error> {
    if bytes.get(*i).copied() == Some(b'"') {
        return Ok(ParamValue::Str(parse_sf_string_at(s, bytes, i)?));
    }
    // Integer
    let start = *i;
    if bytes.get(*i).copied() == Some(b'-') {
        *i += 1;
    }
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        *i += 1;
    }
    if *i == start {
        return Err(Erc8128Error::BadSignatureInput(
            "expected param value".into(),
        ));
    }
    let num: i64 = s[start..*i]
        .parse()
        .map_err(|_| Erc8128Error::BadSignatureInput("bad integer param".into()))?;
    Ok(ParamValue::Integer(num))
}

fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    let bytes = s.as_bytes();

    for (idx, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if b == b'\\' && in_quotes {
            escaped = true;
            continue;
        }
        if b == b'"' {
            in_quotes = !in_quotes;
            continue;
        }
        if b == b',' && !in_quotes {
            result.push(&s[start..idx]);
            start = idx + 1;
        }
    }
    if start <= s.len() {
        result.push(&s[start..]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_sf_string_basic() {
        assert_eq!(quote_sf_string("@method").unwrap(), "\"@method\"");
        assert_eq!(quote_sf_string("has\"quote").unwrap(), "\"has\\\"quote\"");
    }

    #[test]
    fn roundtrip_signature_params() {
        let components = vec!["@authority".to_owned(), "@method".to_owned()];
        let params = SignatureParams {
            created: 1_700_000_000,
            expires: 1_700_000_060,
            keyid: "erc8128:1:0x0000000000000000000000000000000000000000".to_owned(),
            nonce: Some("abc123".to_owned()),
            tag: None,
        };
        let serialized = serialize_signature_params(&components, &params).unwrap();
        assert!(serialized.starts_with("(\"@authority\" \"@method\")"));
        assert!(serialized.contains(";created=1700000000"));
        assert!(serialized.contains(";nonce=\"abc123\""));

        let parsed = parse_inner_list_with_params(&serialized).unwrap();
        assert_eq!(parsed.items, components);
        assert_eq!(parsed.params.created, params.created);
        assert_eq!(parsed.params.nonce, params.nonce);
    }

    #[test]
    fn parse_signature_dict() {
        let header = "eth=:AQID:, other=:BAUG:";
        let map = parse_signature_dictionary(header).unwrap();
        assert_eq!(map.get("eth").unwrap(), "AQID");
        assert_eq!(map.get("other").unwrap(), "BAUG");
    }

    #[test]
    fn split_commas_respects_quotes() {
        let input = r#"a="x,y", b=:z:"#;
        let parts = split_top_level_commas(input);
        assert_eq!(parts.len(), 2);
    }
}
