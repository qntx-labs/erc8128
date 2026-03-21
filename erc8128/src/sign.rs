use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest, Sha256};

use crate::{
    error::Erc8128Error,
    keyid::format_keyid,
    sf::{quote_sf_string, serialize_signature_params},
    types::{Binding, ContentDigest, Replay, Request, SignOptions, SignedHeaders},
};

/// Sign an HTTP request according to ERC-8128.
///
/// Returns the headers (`Signature-Input`, `Signature`, and optionally
/// `Content-Digest`) that the caller must attach to the outgoing request.
///
/// # Errors
///
/// Returns [`Erc8128Error`] if the request URL is invalid, options are
/// inconsistent, or the signer produces an empty signature.
pub async fn sign_request(
    request: &Request<'_>,
    signer: &impl crate::traits::Signer,
    opts: &SignOptions,
) -> Result<SignedHeaders, Erc8128Error> {
    let url = parse_url(request.url)?;
    let label = opts.label.as_deref().unwrap_or("eth");
    validate_label(label)?;

    let now = now_unix();
    let created = opts.created.unwrap_or(now);
    let ttl = opts.ttl_seconds.unwrap_or(60);
    let expires = opts.expires.unwrap_or(created + ttl);

    if expires <= created {
        return Err(Erc8128Error::InvalidOptions(
            "expires must be > created".into(),
        ));
    }

    let nonce = match opts.replay {
        Replay::NonReplayable => Some(
            opts.nonce
                .clone()
                .unwrap_or_else(crate::nonce::generate_default),
        ),
        Replay::Replayable => None,
    };

    let keyid = format_keyid(signer.chain_id(), signer.address());
    let has_query = !url.query.is_empty();
    let has_body = request.body.is_some();

    let mut components = resolve_components(
        opts.binding,
        has_query,
        has_body,
        opts.components.as_deref(),
    )?;

    let content_digest_value = resolve_content_digest(
        request,
        opts.binding,
        has_body,
        opts.content_digest,
        &mut components,
    )?;

    let params = crate::types::SignatureParams {
        created,
        expires,
        keyid,
        nonce,
        tag: None,
    };

    let params_value = serialize_signature_params(&components, &params)?;

    let signature_base = build_signature_base(
        request,
        &url,
        &components,
        &params_value,
        content_digest_value.as_deref(),
    )?;

    let sig_bytes = signer.sign_message(&signature_base).await?;
    if sig_bytes.is_empty() {
        return Err(Erc8128Error::SigningFailed(
            "signer returned empty signature".into(),
        ));
    }

    let sig_b64 = BASE64.encode(&sig_bytes);

    Ok(SignedHeaders {
        signature_input: format!("{label}={params_value}"),
        signature: format!("{label}=:{sig_b64}:"),
        content_digest: content_digest_value.map(|v| format!("sha-256=:{v}:")),
    })
}

fn resolve_content_digest(
    request: &Request<'_>,
    binding: Binding,
    has_body: bool,
    digest_mode: ContentDigest,
    components: &mut Vec<String>,
) -> Result<Option<String>, Erc8128Error> {
    let needs_digest =
        has_str(components, "content-digest") || (binding == Binding::RequestBound && has_body);

    if !needs_digest {
        return Ok(None);
    }
    if !has_str(components, "content-digest") {
        components.push("content-digest".into());
    }
    compute_content_digest(request, digest_mode).map(Some)
}

pub struct ParsedUrl {
    pub authority: String,
    pub path: String,
    pub query: String,
}

pub fn parse_url(url: &str) -> Result<ParsedUrl, Erc8128Error> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(Erc8128Error::InvalidUrl(
            "must be absolute http(s) URL".into(),
        ));
    };

    let (authority_and_path, query) = rest
        .find('?')
        .map_or((rest, ""), |i| (&rest[..i], &rest[i..]));

    let (authority_raw, path) = authority_and_path
        .find('/')
        .map_or((authority_and_path, "/"), |i| {
            (&authority_and_path[..i], &authority_and_path[i..])
        });

    Ok(ParsedUrl {
        authority: normalize_authority(scheme, authority_raw),
        path: path.to_owned(),
        query: query.to_owned(),
    })
}

fn normalize_authority(scheme: &str, raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    match lower.rsplit_once(':') {
        Some((host, port_str)) => {
            if let Ok(port) = port_str.parse::<u16>() {
                let is_default =
                    (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
                if is_default {
                    return host.to_owned();
                }
            }
            lower
        }
        None => lower,
    }
}

fn resolve_components(
    binding: Binding,
    has_query: bool,
    has_body: bool,
    provided: Option<&[String]>,
) -> Result<Vec<String>, Erc8128Error> {
    match binding {
        Binding::RequestBound => {
            let mut out: Vec<String> = ["@authority", "@method", "@path"]
                .iter()
                .map(|&s| s.into())
                .collect();
            if has_query {
                out.push("@query".into());
            }
            if has_body {
                out.push("content-digest".into());
            }
            if let Some(extra) = provided {
                for c in extra {
                    let c = c.trim();
                    if !c.is_empty() && !has_str(&out, c) {
                        out.push(c.to_owned());
                    }
                }
            }
            Ok(out)
        }
        Binding::ClassBound => {
            let Some(provided) = provided else {
                return Err(Erc8128Error::InvalidOptions(
                    "components are required for class-bound signatures".into(),
                ));
            };
            let mut out: Vec<String> = provided
                .iter()
                .map(|c| c.trim().to_owned())
                .filter(|c| !c.is_empty())
                .collect();
            if !has_str(&out, "@authority") {
                out.insert(0, "@authority".into());
            }
            Ok(out)
        }
    }
}

fn has_str(haystack: &[String], needle: &str) -> bool {
    haystack.iter().any(|s| s == needle)
}

fn compute_content_digest(
    request: &Request<'_>,
    mode: ContentDigest,
) -> Result<String, Erc8128Error> {
    match mode {
        ContentDigest::Off => Err(Erc8128Error::DigestError(
            "content-digest required but mode is Off".into(),
        )),
        ContentDigest::Require => find_header_digest(request).ok_or_else(|| {
            Erc8128Error::DigestError("content-digest required but missing from headers".into())
        }),
        ContentDigest::Auto => Ok(find_header_digest(request)
            .unwrap_or_else(|| compute_sha256(request.body.unwrap_or_default()))),
        ContentDigest::Recompute => Ok(compute_sha256(request.body.unwrap_or_default())),
    }
}

fn find_header_digest(request: &Request<'_>) -> Option<String> {
    for &(name, value) in request.headers {
        if name.eq_ignore_ascii_case("content-digest") {
            return parse_digest_b64(value).ok();
        }
    }
    None
}

fn compute_sha256(body: &[u8]) -> String {
    BASE64.encode(Sha256::digest(body))
}

fn parse_digest_b64(header_value: &str) -> Result<String, Erc8128Error> {
    let s = header_value.trim();
    let rest = s
        .strip_prefix("sha-256=:")
        .ok_or_else(|| Erc8128Error::DigestError("unsupported digest algorithm".into()))?;
    let b64 = rest
        .strip_suffix(':')
        .ok_or_else(|| Erc8128Error::DigestError("malformed content-digest".into()))?;
    Ok(b64.to_owned())
}

pub fn build_signature_base(
    request: &Request<'_>,
    url: &ParsedUrl,
    components: &[String],
    signature_params_value: &str,
    content_digest_b64: Option<&str>,
) -> Result<Vec<u8>, Erc8128Error> {
    let mut lines = Vec::with_capacity(components.len() + 1);

    for comp in components {
        let value = component_value(request, url, comp, content_digest_b64)?;
        ensure_visible_ascii(&value, comp)?;
        lines.push(format!("{}: {value}", quote_sf_string(comp)?));
    }

    lines.push(format!(
        "{}: {signature_params_value}",
        quote_sf_string("@signature-params")?
    ));

    Ok(lines.join("\n").into_bytes())
}

pub fn component_value(
    request: &Request<'_>,
    url: &ParsedUrl,
    component: &str,
    content_digest_b64: Option<&str>,
) -> Result<String, Erc8128Error> {
    match component {
        "@method" => Ok(request.method.to_ascii_uppercase()),
        "@authority" => Ok(url.authority.clone()),
        "@path" => Ok(if url.path.is_empty() {
            "/".to_owned()
        } else {
            url.path.clone()
        }),
        "@query" => Ok(url.query.clone()),
        "content-digest" => {
            if let Some(b64) = content_digest_b64 {
                return Ok(format!("sha-256=:{b64}:"));
            }
            find_header_value(request, "content-digest")
        }
        _ => find_header_value(request, component),
    }
}

fn find_header_value(request: &Request<'_>, name: &str) -> Result<String, Erc8128Error> {
    for &(n, v) in request.headers {
        if n.eq_ignore_ascii_case(name) {
            return Ok(canonicalize_field_value(v));
        }
    }
    Err(Erc8128Error::InvalidHeaderValue(format!(
        "required header \"{name}\" is missing"
    )))
}

fn canonicalize_field_value(v: &str) -> String {
    v.trim()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn ensure_visible_ascii(value: &str, name: &str) -> Result<(), Erc8128Error> {
    if value.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        Ok(())
    } else {
        Err(Erc8128Error::InvalidDerivedValue(format!(
            "{name} produced non-visible-ASCII character"
        )))
    }
}

pub fn validate_label(label: &str) -> Result<(), Erc8128Error> {
    let bytes = label.as_bytes();
    let valid = !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|&b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        });
    if valid {
        Ok(())
    } else {
        Err(Erc8128Error::InvalidFormat(format!(
            "invalid label: {label}"
        )))
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
