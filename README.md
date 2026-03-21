<!-- markdownlint-disable MD033 MD041 MD036 -->

<div align="center">

# ERC-8128

**Signed HTTP Requests with Ethereum**

[![CI][ci-badge]][ci-url]
[![crates.io][crate-badge]][crate-url]
[![docs.rs][doc-badge]][doc-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[ci-badge]: https://github.com/qntx/erc8128/actions/workflows/rust.yml/badge.svg
[ci-url]: https://github.com/qntx/erc8128/actions/workflows/rust.yml
[crate-badge]: https://img.shields.io/crates/v/erc8128.svg
[crate-url]: https://crates.io/crates/erc8128
[doc-badge]: https://img.shields.io/docsrs/erc8128.svg
[doc-url]: https://docs.rs/erc8128
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

Type-safe Rust SDK for [ERC-8128][spec]: HTTP request authentication via
[RFC 9421][rfc9421] message signatures with Ethereum accounts (EOA & ERC-1271).

[Quick Start](#quick-start) | [Protocol](#erc-8128-protocol) | [API Reference][doc-url]

</div>

## Overview

[ERC-8128][spec] binds [RFC 9421 HTTP Message Signatures][rfc9421] to Ethereum's signing ecosystem. A client signs each outgoing HTTP request with its Ethereum key; the server reconstructs the signature base and verifies it — either by `ecrecover` (EOA / [EIP-191][eip191]) or on-chain validation ([ERC-1271][erc1271]).

This crate is **framework-agnostic** (zero HTTP framework dependencies) and exposes two entry points:

- **[`sign_request`][doc-url]** — produce `Signature-Input`, `Signature`, and `Content-Digest` headers.
- **[`verify_request`][doc-url]** — parse, verify, and authenticate an incoming signed request.

Chain-specific verification logic is pluggable via the [`Verifier`][doc-url] trait.

> [!NOTE]
> Reference implementation: **[erc8128/erc8128-ts](https://github.com/erc8128/erc8128)** (TypeScript).
> See [SECURITY.md](SECURITY.md) before production use.

## Quick Start

### Sign (Client)

```rust
use erc8128::{Request, SignOptions, sign_request};

let request = Request {
    method: "POST",
    url: "https://api.example.com/orders",
    headers: &[("content-type", "application/json")],
    body: Some(b"{\"item\":\"widget\",\"qty\":1}"),
};

let signed = sign_request(&request, &signer, &SignOptions::default()).await?;

// Attach to your HTTP client:
//   Signature-Input: signed.signature_input
//   Signature:       signed.signature
//   Content-Digest:  signed.content_digest  (Some when body is present)
```

### Verify (Server)

```rust
use erc8128::{Request, VerifyPolicy, NoNonceStore, verify_request};

let result = verify_request(&request, &verifier, &nonce_store, &VerifyPolicy::default()).await?;

assert_eq!(result.address, expected_address);
println!("chain={} binding={:?} replayable={}", result.chain_id, result.binding, result.replayable);
```

## ERC-8128 Protocol

### Signature Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    C->>C: Construct RFC 9421 signature base
    C->>C: EIP-191 personal_sign(signature_base)
    C->>S: HTTP Request + Signature-Input + Signature + Content-Digest

    S->>S: Parse Signature-Input
    S->>S: Reconstruct signature base from request
    S->>S: Verify Content-Digest (SHA-256)
    S->>S: ecrecover / ERC-1271 verify
    S->>S: Nonce & expiry checks

    S-->>C: Authenticated response
```

### Binding Modes

| Mode | Covered Components | Semantics |
| --- | --- | --- |
| **Request-Bound** | `@method` `@authority` `@path` `@query` `content-digest` | Authorizes **exactly one** concrete HTTP request. |
| **Class-Bound** | Caller-defined set (must include `@authority`) | Authorizes **a class** of requests matching the covered components. |

### Replay Protection

| Mode | Nonce | Semantics |
| --- | --- | --- |
| **Non-Replayable** | Present | Each signature consumed **exactly once** via `NonceStore`. |
| **Replayable** | Absent | Valid for any number of uses within the `[created, expires]` window. |

### Signature Parameters (RFC 9421)

| Parameter | Required | Description |
| --- | --- | --- |
| `created` | Yes | Unix timestamp of signature creation. |
| `expires` | Yes | Unix timestamp of signature expiration. |
| `keyid` | Yes | Signer identity: `erc8128:<chainId>:<address>`. |
| `nonce` | Non-Replayable | Cryptographically random replay-prevention token. |
| `tag` | No | Application-level discriminator for routing. |

### Content-Digest

Body integrity is protected by a `Content-Digest: sha-256=:<base64>:` header. Four modes control its behavior:

| Mode | Behavior |
| --- | --- |
| **`Auto`** | Use an existing header, or compute one from the body. *(default)* |
| **`Recompute`** | Always recompute, overwriting any existing header. |
| **`Require`** | Fail if the header is absent — never compute. |
| **`Off`** | Disable entirely — fail if body-bound components are present. |

## Extensibility

The SDK delegates all environment-specific logic to three traits:

| Trait | Responsibility | Implementations |
| --- | --- | --- |
| [`Signer`][doc-url] | Produce EIP-191 `personal_sign` signatures. | Private key, HSM, KMS, MPC |
| [`Verifier`][doc-url] | Verify signatures given `(address, message, signature)`. | `ecrecover`, ERC-1271, [ERC-6492][erc6492] |
| [`NonceStore`][doc-url] | Atomically consume nonces for replay protection. | Redis, DashMap, RDBMS — or [`NoNonceStore`][doc-url] for replayable-only policies |

## Related Standards

| Standard | Relationship |
| --- | --- |
| [RFC 9421][rfc9421] | HTTP Message Signatures — the wire format ERC-8128 builds on |
| [EIP-191][eip191] | Signed Data Standard — `personal_sign` message prefix |
| [ERC-1271][erc1271] | Standard Signature Validation for smart contract accounts |
| [ERC-6492][erc6492] | Signature Validation for pre-deployed (counterfactual) contracts |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QNTX](https://qntx.fun)** open-source project.

<a href="https://qntx.fun"><img alt="QNTX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx-banner.svg" /></a>

<!--prettier-ignore-->
Code is law. We write both.

</div>

[spec]: https://erc8128.org
[rfc9421]: https://www.rfc-editor.org/rfc/rfc9421
[eip191]: https://eips.ethereum.org/EIPS/eip-191
[erc1271]: https://eips.ethereum.org/EIPS/eip-1271
[erc6492]: https://eips.ethereum.org/EIPS/eip-6492
