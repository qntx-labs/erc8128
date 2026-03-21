use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest, Sha256};

use crate::{
    Binding, ContentDigest, Erc8128Error, Replay, Request, SignOptions, SignedHeaders,
    keyid::format_keyid,
    sf::{quote_sf_string, serialize_signature_params},
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
///
/// # Examples
///
/// ```
/// use erc8128::{Request, SignOptions, sign_request};
///
/// # async fn example(signer: impl erc8128::Signer) -> Result<(), erc8128::Erc8128Error> {
/// let request = Request {
///     method: "POST",
///     url: "https://api.example.com/orders",
///     headers: &[("content-type", "application/json")],
///     body: Some(b"{\"amount\":\"100\"}"),
/// };
/// let headers = sign_request(&request, &signer, &SignOptions::default()).await?;
/// // Attach headers.signature_input, headers.signature, headers.content_digest
/// // to your HTTP request.
/// # Ok(())
/// # }
/// ```
pub async fn sign_request(
    request: &Request<'_>,
    signer: &impl crate::Signer,
    opts: &SignOptions,
) -> Result<SignedHeaders, Erc8128Error> {
    let url = parse_url(request.url)?;
    let label = opts.label.as_deref().unwrap_or("eth");
    validate_label(label)?;

    let binding = opts.binding.unwrap_or(Binding::RequestBound);
    let replay = opts.replay.unwrap_or(Replay::NonReplayable);
    let digest_mode = opts.content_digest.unwrap_or_default();

    let now = now_unix();
    let created = opts.created.unwrap_or(now);
    let ttl = opts.ttl_seconds.unwrap_or(60);
    let expires = opts.expires.unwrap_or(created + ttl);

    if expires <= created {
        return Err(Erc8128Error::InvalidOptions(
            "expires must be > created".into(),
        ));
    }

    let nonce = match replay {
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

    let mut components =
        resolve_components(binding, has_query, has_body, opts.components.as_deref())?;

    // Content-Digest handling
    let content_digest_value = if components.contains(&"content-digest".to_owned())
        || (binding == Binding::RequestBound && has_body)
    {
        if !components.contains(&"content-digest".to_owned()) {
            components.push("content-digest".to_owned());
        }
        Some(compute_content_digest(request, digest_mode)?)
    } else {
        None
    };

    let params = crate::SignatureParams {
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
    let signature_input = format!("{label}={params_value}");
    let signature = format!("{label}=:{sig_b64}:");

    Ok(SignedHeaders {
        signature_input,
        signature,
        content_digest: content_digest_value.map(|v| format!("sha-256=:{v}:")),
    })
}

// ── Internal helpers ────────────────────────────────────────────────

pub struct ParsedUrl {
    pub authority: String,
    pub path: String,
    pub query: String,
}

pub fn parse_url(url: &str) -> Result<ParsedUrl, Erc8128Error> {
    // Minimal URL parser: extract scheme, authority, path, query.
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| Erc8128Error::InvalidUrl("must be absolute http(s) URL".into()))?;

    let scheme = if url.starts_with("https://") {
        "https"
    } else {
        "http"
    };

    let (authority_and_path, query) = rest
        .find('?')
        .map_or((rest, ""), |i| (&rest[..i], &rest[i..]));

    let (authority_raw, path) = authority_and_path
        .find('/')
        .map_or((authority_and_path, "/"), |i| {
            (&authority_and_path[..i], &authority_and_path[i..])
        });

    // Normalize authority: lowercase hostname, strip default port
    let authority = normalize_authority(scheme, authority_raw);

    Ok(ParsedUrl {
        authority,
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
            let mut base = vec![
                "@authority".to_owned(),
                "@method".to_owned(),
                "@path".to_owned(),
            ];
            if has_query {
                base.push("@query".to_owned());
            }
            if has_body {
                base.push("content-digest".to_owned());
            }
            if let Some(extra) = provided {
                for c in extra {
                    let c = c.trim().to_owned();
                    if !c.is_empty() && !base.contains(&c) {
                        base.push(c);
                    }
                }
            }
            Ok(base)
        }
        Binding::ClassBound => {
            let Some(provided) = provided else {
                return Err(Erc8128Error::InvalidOptions(
                    "components are required for class-bound signatures".into(),
                ));
            };
            let mut components: Vec<String> = provided
                .iter()
                .map(|c| c.trim().to_owned())
                .filter(|c| !c.is_empty())
                .collect();
            if !components.contains(&"@authority".to_owned()) {
                components.insert(0, "@authority".to_owned());
            }
            Ok(components)
        }
    }
}

fn compute_content_digest(
    request: &Request<'_>,
    mode: ContentDigest,
) -> Result<String, Erc8128Error> {
    match mode {
        ContentDigest::Off => Err(Erc8128Error::DigestError(
            "content-digest required by components, but mode is Off".into(),
        )),
        ContentDigest::Require => {
            // Check if caller already provided it in headers
            for &(name, value) in request.headers {
                if name.eq_ignore_ascii_case("content-digest") {
                    return parse_digest_b64(value);
                }
            }
            Err(Erc8128Error::DigestError(
                "content-digest required but missing from request headers".into(),
            ))
        }
        ContentDigest::Auto => {
            // Use existing header if present, otherwise compute
            for &(name, value) in request.headers {
                if name.eq_ignore_ascii_case("content-digest") {
                    return parse_digest_b64(value);
                }
            }
            Ok(compute_sha256(request.body.unwrap_or_default()))
        }
        ContentDigest::Recompute => Ok(compute_sha256(request.body.unwrap_or_default())),
    }
}

fn compute_sha256(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    BASE64.encode(hash)
}

fn parse_digest_b64(header_value: &str) -> Result<String, Erc8128Error> {
    // Parse `sha-256=:<base64>:` format
    let s = header_value.trim();
    let rest = s
        .strip_prefix("sha-256=:")
        .ok_or_else(|| Erc8128Error::DigestError("unsupported digest algorithm".into()))?;
    let b64 = rest
        .strip_suffix(':')
        .ok_or_else(|| Erc8128Error::DigestError("malformed content-digest".into()))?;
    Ok(b64.to_owned())
}

fn build_signature_base(
    request: &Request<'_>,
    url: &ParsedUrl,
    components: &[String],
    signature_params_value: &str,
    content_digest_b64: Option<&str>,
) -> Result<Vec<u8>, Erc8128Error> {
    let mut lines = Vec::new();

    for comp in components {
        let value = component_value(request, url, comp, content_digest_b64)?;
        ensure_visible_ascii(&value, comp)?;
        lines.push(format!("{}: {value}", quote_sf_string(comp)?));
    }

    let sig_params_line = format!(
        "{}: {signature_params_value}",
        quote_sf_string("@signature-params")?
    );

    let base = if lines.is_empty() {
        sig_params_line
    } else {
        format!("{}\n{sig_params_line}", lines.join("\n"))
    };

    Ok(base.into_bytes())
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
        "@path" => {
            let p = if url.path.is_empty() { "/" } else { &url.path };
            Ok(p.to_owned())
        }
        "@query" => Ok(url.query.clone()),
        "content-digest" => {
            if let Some(b64) = content_digest_b64 {
                return Ok(format!("sha-256=:{b64}:"));
            }
            // Try from request headers
            for &(name, value) in request.headers {
                if name.eq_ignore_ascii_case("content-digest") {
                    return Ok(canonicalize_field_value(value));
                }
            }
            Err(Erc8128Error::InvalidHeaderValue(
                "required header \"content-digest\" is missing".into(),
            ))
        }
        _ => {
            // Regular header field
            for &(name, value) in request.headers {
                if name.eq_ignore_ascii_case(component) {
                    return Ok(canonicalize_field_value(value));
                }
            }
            Err(Erc8128Error::InvalidHeaderValue(format!(
                "required header \"{component}\" is missing"
            )))
        }
    }
}

fn canonicalize_field_value(v: &str) -> String {
    v.trim()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn ensure_visible_ascii(value: &str, name: &str) -> Result<(), Erc8128Error> {
    for b in value.bytes() {
        if !(0x20..=0x7E).contains(&b) {
            return Err(Erc8128Error::InvalidDerivedValue(format!(
                "{name} produced non-visible-ASCII character"
            )));
        }
    }
    Ok(())
}

pub fn validate_label(label: &str) -> Result<(), Erc8128Error> {
    if label.is_empty() {
        return Err(Erc8128Error::InvalidFormat("empty label".into()));
    }
    let bytes = label.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return Err(Erc8128Error::InvalidFormat(format!(
            "invalid label: {label}"
        )));
    }
    if !bytes.iter().all(|&b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
    }) {
        return Err(Erc8128Error::InvalidFormat(format!(
            "invalid label: {label}"
        )));
    }
    Ok(())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
