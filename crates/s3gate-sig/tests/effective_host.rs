// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The effective-host case suite (`c-sig-0206` .. `c-sig-0208`, `c-sig-0247` .. `c-sig-0252`).
//!
//! Responsible for: the eight request shapes a hyper 1.11.0 server was measured to forward
//! untouched, and the one property that makes the whole module worth having — that four spellings
//! of one host are four hosts as far as the signature is concerned.
//! NOT responsible for: the canonical request itself (`tests/canonical_request.rs`), or virtual
//! host bucket extraction, which is the router's and does not exist yet.
//! Upstream: the `s3gate-sig` public API and `http`. Downstream: none (test target).
//!
//! Every request below is built through `http::Request`, which is the same type hyper hands a
//! service — so "hyper answers 200" and "this crate refuses" are statements about the same value.
//! HTTP/2 is modelled the way hyper presents it: `:authority` becomes the URI authority, and a
//! bare-frame request that carried only `host` arrives with no authority at all.

use http::header::HOST;
use http::{Request, Uri};
use s3gate_sig::{HostError, HostSource, RawHost, effective_host};

fn request(uri: &str, hosts: &[&str]) -> Request<()> {
    let mut builder = Request::builder().method("GET").uri(uri.parse::<Uri>().expect("test uri"));
    for host in hosts {
        builder = builder.header(HOST, *host);
    }
    builder.body(()).expect("test request")
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// Positive — c-sig-0206: an HTTP/2 request with no `host` header takes its host from
/// `:authority`, which hyper surfaces as the URI authority (s3s#540, s3s#283).
#[test]
fn c_sig_0206_http2_takes_its_host_from_the_authority() {
    let host = effective_host(&request("https://127.0.0.1:38080/foo", &[])).expect("resolved");
    assert_eq!(host.as_str(), "127.0.0.1:38080");
    assert_eq!(host.source(), HostSource::Authority);
}

/// Positive — c-sig-0207: an h2 bare frame carrying `host` and no `:authority` is legal under
/// RFC 9113 §8.3.1, and resolves from the header.
#[test]
fn c_sig_0207_an_h2_request_with_only_a_host_header_resolves_from_it() {
    let host = effective_host(&request("/foo", &["only.example.com"])).expect("resolved");
    assert_eq!(host.as_str(), "only.example.com");
    assert_eq!(host.source(), HostSource::HostHeader);
}

/// Positive — c-sig-0208: a non-default port is part of the host and survives verbatim, so a
/// presigned URL minted against `:9000` still verifies (s3s#438).
#[test]
fn c_sig_0208_a_non_default_port_is_part_of_the_signed_host() {
    let host = effective_host(&request("/foo", &["minio.example.com:9000"])).expect("resolved");
    assert_eq!(host.as_str(), "minio.example.com:9000");
    let default_port = RawHost::from_host_header(b"minio.example.com").expect("valid");
    assert_ne!(host.as_bytes(), default_port.as_bytes(), "the port is not stripped");
}

/// Positive — an HTTP/1.1 origin-form request resolves from its single `Host` header, and an
/// absolute-form request whose authority agrees with its `Host` resolves to the same value.
#[test]
fn c_sig_0206b_the_two_agreeing_shapes_resolve_identically() {
    let origin_form = effective_host(&request("/foo", &["a.example.com"])).expect("resolved");
    let absolute_form = effective_host(&request("http://a.example.com/foo", &["a.example.com"])).expect("resolved");
    assert_eq!(origin_form.as_bytes(), absolute_form.as_bytes());
    assert_eq!(origin_form.source(), HostSource::HostHeader);
    assert_eq!(absolute_form.source(), HostSource::Authority);
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

/// Negative — c-sig-0247: an HTTP/1.1 origin-form request with no `Host` at all. hyper answers 200.
#[test]
fn c_sig_0247_a_request_with_no_host_is_refused() {
    assert_eq!(effective_host(&request("/foo", &[])), Err(HostError::Missing));
}

/// Negative — c-sig-0248: an empty `Host:`. hyper answers 200.
#[test]
fn c_sig_0248_an_empty_host_is_refused() {
    assert_eq!(effective_host(&request("/foo", &[""])), Err(HostError::Invalid));
}

/// Negative — c-sig-0249: two `Host` headers. hyper answers 200. Refused whether or not they agree:
/// which one is "the" host is the question that must not have an answer here.
#[test]
fn c_sig_0249_duplicate_host_headers_are_refused() {
    assert_eq!(effective_host(&request("/foo", &["a", "b"])), Err(HostError::Duplicate));
    assert_eq!(effective_host(&request("/foo", &["a", "a"])), Err(HostError::Duplicate));
}

/// Negative — c-sig-0250: an h2 request whose `:authority` and `host` disagree. hyper answers 200,
/// and this is the shape where the signature covers `good` while the router reads `evil`.
#[test]
fn c_sig_0250_an_authority_conflicting_with_the_host_header_is_refused() {
    assert_eq!(
        effective_host(&request("https://good.example.com/foo", &["evil.example.com"])),
        Err(HostError::Conflict)
    );
}

/// Negative — c-sig-0251: HTTP/1.1 absolute-form whose target authority contradicts `Host`.
/// RFC 9112 §5.5 permits ignoring `Host`; this crate refuses instead, because "silently pick one"
/// is how the signer and the router come to pick differently.
#[test]
fn c_sig_0251_absolute_form_conflicting_with_the_host_header_is_refused() {
    assert_eq!(
        effective_host(&request("http://bucket.example.com/foo", &["other.example.com"])),
        Err(HostError::Conflict)
    );
}

/// Negative — c-sig-0252: four spellings of one host stay four distinct byte strings, so one
/// signature can never be valid for all of them. This is the many-to-one regression: a resolver
/// that lowercases, strips `:443` and drops the trailing dot would map all four onto one value.
#[test]
fn c_sig_0252_host_spellings_are_never_folded_together() {
    let spellings = ["example.com", "EXAMPLE.COM", "example.com.", "example.com:443"];
    let resolved: Vec<RawHost> = spellings
        .iter()
        .map(|spelling| effective_host(&request("/foo", &[spelling])).expect("resolved"))
        .collect();
    for (index, host) in resolved.iter().enumerate() {
        assert_eq!(host.as_str(), spellings[index], "nothing may be normalised");
        for (other_index, other) in resolved.iter().enumerate() {
            if index != other_index {
                assert_ne!(
                    host.as_bytes(),
                    other.as_bytes(),
                    "{} and {} must stay distinct",
                    spellings[index],
                    spellings[other_index]
                );
            }
        }
    }
    // And the conflict rule follows the same byte-exact comparison.
    assert_eq!(
        effective_host(&request("http://example.com/foo", &["example.com:443"])),
        Err(HostError::Conflict)
    );
}

/// Negative — a host carrying whitespace, a control character, non-ASCII, or more bytes than a DNS
/// name can hold is refused. A `\r\n` inside a host would be header injection in the canonical
/// request and log injection in the audit record.
#[test]
fn c_sig_0248b_hosts_with_forbidden_bytes_are_refused() {
    for bad in ["exa mple.com", "example.com\tx", "exämple.com"] {
        assert_eq!(RawHost::from_host_header(bad.as_bytes()), Err(HostError::Invalid), "must reject {bad:?}");
    }
    assert_eq!(RawHost::from_host_header(b"a\r\nX-Injected: 1"), Err(HostError::Invalid));
    assert_eq!(RawHost::from_host_header(&[b'a'; RawHost::MAX_LEN + 1]), Err(HostError::Invalid));
    assert!(RawHost::from_host_header(&[b'a'; RawHost::MAX_LEN]).is_ok());
}

/// Negative — every host rejection is a 400, never a 403. Collapsing the two would bury host
/// smuggling in the noise of ordinary credential failures.
#[test]
fn c_sig_0247b_every_host_rejection_is_a_bad_request() {
    assert_eq!(HostError::HTTP_STATUS, 400);
    for error in [
        HostError::Missing,
        HostError::Duplicate,
        HostError::Conflict,
        HostError::Invalid,
    ] {
        assert!(!error.reason().is_empty());
        assert_eq!(format!("{error}"), error.reason());
    }
}
