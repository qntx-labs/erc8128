use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    Binding, Erc8128Error, NonceStore, Request, SignatureParams, Verifier, VerifyPolicy,
    VerifySuccess,
    keyid::parse_keyid,
    sf::{parse_signature_dictionary, parse_signature_input_dictionary, quote_sf_string},
    sign,
};

/// Verify a signed HTTP request according to ERC-8128.
///
/// Use [`NoNonceStore`](crate::NoNonceStore) if your policy only allows
/// replayable signatures and you don't need nonce tracking.
///
/// # Errors
///
/// Returns [`Erc8128Error`] describing why verification failed.
pub async fn verify_request(
    request: &Request<'_>,
    verifier: &impl Verifier,
    nonce_store: &impl NonceStore,
    policy: &VerifyPolicy,
) -> Result<VerifySuccess, Erc8128Error> {
    let sig_input_raw =
        find_header(request, "signature-input").ok_or(Erc8128Error::MissingHeaders)?;
    let sig_raw = find_header(request, "signature").ok_or(Erc8128Error::MissingHeaders)?;

    let parsed_inputs = parse_signature_input_dictionary(sig_input_raw)?;
    let parsed_sigs = parse_signature_dictionary(sig_raw)?;

    let strict_label = policy.strict_label;
    let mut candidates: Vec<Candidate> = Vec::new();

    for input in &parsed_inputs {
        if let Some(sig_b64) = parsed_sigs.get(&input.label) {
            candidates.push(Candidate {
                label: input.label.clone(),
                components: input.components.clone(),
                params: input.params.clone(),
                params_value: input.params_value.clone(),
                sig_b64: sig_b64.clone(),
            });
        }
    }

    if candidates.is_empty() {
        return Err(Erc8128Error::LabelNotFound);
    }

    if let Some(pref) = policy.label.as_deref()
        && strict_label
    {
        candidates.retain(|c| c.label == pref);
        if candidates.is_empty() {
            return Err(Erc8128Error::LabelNotFound);
        }
    }

    let url = sign::parse_url(request.url)?;
    let has_query = !url.query.is_empty();
    let has_body = request.body.is_some();
    let now = policy.now.unwrap_or_else(sign::now_unix);
    let max_verifications = policy.max_signature_verifications.unwrap_or(3);
    let extra_components = policy
        .additional_request_bound_components
        .as_deref()
        .unwrap_or_default();
    let request_bound_required =
        required_request_bound_components(has_query, has_body, extra_components);

    let mut last_err = Erc8128Error::BadSignature;

    for (tried, candidate) in candidates.iter().enumerate() {
        if tried >= max_verifications {
            break;
        }

        let Some((chain_id, address)) = parse_keyid(&candidate.params.keyid) else {
            last_err = Erc8128Error::BadKeyId;
            continue;
        };

        let replayable = candidate.params.nonce.is_none();

        let binding = classify_binding(
            &candidate.components,
            &request_bound_required,
            policy.class_bound_policies.as_ref(),
        );

        let Some(binding) = binding else {
            last_err = if policy.class_bound_policies.is_some() {
                Erc8128Error::ClassBoundNotAllowed
            } else {
                Erc8128Error::NotRequestBound
            };
            continue;
        };

        if let Err(e) = check_time(
            now,
            policy.clock_skew_sec,
            policy.max_validity_sec,
            candidate.params.created,
            candidate.params.expires,
        ) {
            last_err = e;
            continue;
        }

        if replayable && !policy.allow_replayable {
            last_err = Erc8128Error::ReplayableNotAllowed;
            continue;
        }

        if candidate.components.iter().any(|c| c == "content-digest")
            && let Err(e) = verify_content_digest(request)
        {
            last_err = e;
            continue;
        }

        let signature_base = build_verify_signature_base(
            request,
            &url,
            &candidate.components,
            &candidate.params_value,
        )?;

        let sig_bytes = BASE64
            .decode(&candidate.sig_b64)
            .map_err(|_| Erc8128Error::BadSignature)?;

        if sig_bytes.is_empty() {
            last_err = Erc8128Error::BadSignature;
            continue;
        }

        match verifier.verify(address, &signature_base, &sig_bytes).await {
            Ok(()) => {
                if let Some(nonce) = candidate.params.nonce.as_deref() {
                    let key = format!("{}:{nonce}", candidate.params.keyid);
                    let ttl = candidate.params.expires.saturating_sub(now);
                    if !nonce_store.consume(&key, ttl).await {
                        return Err(Erc8128Error::Replay);
                    }
                }

                return Ok(VerifySuccess {
                    address,
                    chain_id,
                    label: candidate.label.clone(),
                    components: candidate.components.clone(),
                    params: candidate.params.clone(),
                    replayable,
                    binding,
                });
            }
            Err(e) => {
                last_err = e;
            }
        }
    }

    Err(last_err)
}

struct Candidate {
    label: String,
    components: Vec<String>,
    params: SignatureParams,
    params_value: String,
    sig_b64: String,
}

fn find_header<'a>(request: &'a Request<'_>, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
}

fn required_request_bound_components(
    has_query: bool,
    has_body: bool,
    extras: &[String],
) -> Vec<String> {
    let mut c = vec![
        "@authority".to_owned(),
        "@method".to_owned(),
        "@path".to_owned(),
    ];
    if has_query {
        c.push("@query".to_owned());
    }
    if has_body {
        c.push("content-digest".to_owned());
    }
    for extra in extras {
        let e = extra.trim().to_owned();
        if !e.is_empty() && !c.iter().any(|x| x == &e) {
            c.push(e);
        }
    }
    c
}

fn classify_binding(
    signed: &[String],
    request_bound_required: &[String],
    class_bound_policies: Option<&Vec<Vec<String>>>,
) -> Option<Binding> {
    if includes_all(request_bound_required, signed) {
        return Some(Binding::RequestBound);
    }

    if let Some(policies) = class_bound_policies {
        for policy in policies {
            let mut required = policy.clone();
            if !required.contains(&"@authority".to_owned()) {
                required.insert(0, "@authority".to_owned());
            }
            if includes_all(&required, signed) {
                return Some(Binding::ClassBound);
            }
        }
    }

    None
}

fn includes_all(required: &[String], have: &[String]) -> bool {
    required.iter().all(|r| have.contains(r))
}

const fn check_time(
    now: u64,
    skew: u64,
    max_validity: u64,
    created: u64,
    expires: u64,
) -> Result<(), Erc8128Error> {
    if expires <= created {
        return Err(Erc8128Error::BadTime);
    }
    if now + skew < created {
        return Err(Erc8128Error::NotYetValid);
    }
    if now.saturating_sub(skew) > expires {
        return Err(Erc8128Error::Expired);
    }
    if expires - created > max_validity {
        return Err(Erc8128Error::ValidityTooLong);
    }
    Ok(())
}

fn verify_content_digest(request: &Request<'_>) -> Result<(), Erc8128Error> {
    let header_val = find_header(request, "content-digest").ok_or(Erc8128Error::DigestRequired)?;

    let s = header_val.trim();
    let rest = s
        .strip_prefix("sha-256=:")
        .ok_or(Erc8128Error::DigestMismatch)?;
    let claimed_b64 = rest.strip_suffix(':').ok_or(Erc8128Error::DigestMismatch)?;

    let body = request.body.unwrap_or_default();
    let actual_hash = Sha256::digest(body);
    let actual_b64 = BASE64.encode(actual_hash);

    let eq = claimed_b64.as_bytes().ct_eq(actual_b64.as_bytes());
    if bool::from(eq) {
        Ok(())
    } else {
        Err(Erc8128Error::DigestMismatch)
    }
}

fn build_verify_signature_base(
    request: &Request<'_>,
    url: &sign::ParsedUrl,
    components: &[String],
    signature_params_value: &str,
) -> Result<Vec<u8>, Erc8128Error> {
    let mut lines = Vec::new();

    for comp in components {
        let value = sign::component_value(request, url, comp, None)?;
        sign::ensure_visible_ascii(&value, comp)?;
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
