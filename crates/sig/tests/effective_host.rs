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
//! Responsible for: the request shapes a hyper 1.11.0 server was measured to forward untouched,
//! and the one property that makes the whole module worth having — that four spellings of one host
//! are four hosts as far as the signature is concerned.
//! NOT responsible for: the canonical request itself (`tests/canonical_request.rs`), or virtual
//! host bucket extraction, which is the router's and does not exist yet.
//! Upstream: the `rustfs-gateway-sig` public API, `rustfs-gateway-http` and `http`. Downstream: none
//! (test target).
//!
//! The implementation these cases run against lives in `rustfs-gateway-http`: there is one
//! `effective_host`, the wire layer owns it, and this crate consumes it. The suite stays here
//! anyway, and deliberately — these are the *signature layer's* requirements on that function, and
//! a wire-layer refactor that quietly relaxed one of them would break this file rather than only
//! its own. `crates/http/tests/host_ambiguity.rs` covers the same function from the routing side.
//!
//! Every request below is built through `http::Request`, which is the same type hyper hands a
//! service — so "hyper answers 200" and "this crate refuses" are statements about the same value.
//! HTTP/2 is modelled the way hyper presents it: `:authority` becomes the URI authority, and a
//! bare-frame request that carried only `host` arrives with no authority at all.

use http::header::HOST;
use http::{Request, Uri};
use rustfs_gateway_sig::{HostError, HostSource, MAX_HOST_BYTES, RawHost, effective_host};

fn request(uri: &str, hosts: &[&str]) -> Request<()> {
    let mut builder = Request::builder().method("GET").uri(uri.parse::<Uri>().expect("test uri"));
    for host in hosts {
        builder = builder.header(HOST, *host);
    }
    builder.body(()).expect("test request")
}

/// The host as the signer will see it: raw bytes, plus where they came from.
///
/// Every case below asserts against this rather than against the normalised value, because the
/// normalised value is the router's and folding the two together in a test is the same mistake the
/// module exists to prevent.
fn resolve(uri: &str, hosts: &[&str]) -> Result<RawHost, HostError> {
    effective_host(&request(uri, hosts)).map(|host| host.raw_for_signing().clone())
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// Positive — c-sig-0206: an HTTP/2 request with no `host` header takes its host from
/// `:authority`, which hyper surfaces as the URI authority (s3s#540, s3s#283).
#[test]
fn c_sig_0206_http2_takes_its_host_from_the_authority() {
    let host = resolve("https://127.0.0.1:38080/foo", &[]).expect("resolved");
    assert_eq!(host.as_str(), "127.0.0.1:38080");
    assert_eq!(host.source(), HostSource::Authority);
}

/// Positive — c-sig-0207: an h2 bare frame carrying `host` and no `:authority` is legal under
/// RFC 9113 §8.3.1, and resolves from the header.
#[test]
fn c_sig_0207_an_h2_request_with_only_a_host_header_resolves_from_it() {
    let host = resolve("/foo", &["only.example.com"]).expect("resolved");
    assert_eq!(host.as_str(), "only.example.com");
    assert_eq!(host.source(), HostSource::HostHeader);
}

/// Positive — c-sig-0208: a non-default port is part of the host and survives verbatim, so a
/// presigned URL minted against `:9000` still verifies (s3s#438).
#[test]
fn c_sig_0208_a_non_default_port_is_part_of_the_signed_host() {
    let host = resolve("/foo", &["minio.example.com:9000"]).expect("resolved");
    assert_eq!(host.as_str(), "minio.example.com:9000");
    let default_port = RawHost::from_host_header(b"minio.example.com").expect("valid");
    assert_ne!(host.as_bytes(), default_port.as_bytes(), "the port is not stripped");
}

/// Positive — an HTTP/1.1 origin-form request resolves from its single `Host` header, and an
/// absolute-form request whose authority agrees with its `Host` resolves to the same value.
#[test]
fn c_sig_0206b_the_two_agreeing_shapes_resolve_identically() {
    let origin_form = resolve("/foo", &["a.example.com"]).expect("resolved");
    let absolute_form = resolve("http://a.example.com/foo", &["a.example.com"]).expect("resolved");
    assert_eq!(origin_form.as_bytes(), absolute_form.as_bytes());
    assert_eq!(origin_form.source(), HostSource::HostHeader);
    // Both sources are present in the absolute-form request, so the `Host` header's bytes are
    // the ones kept — the signature was computed over that header, and recording the authority
    // instead would name bytes nobody signed.
    assert_eq!(absolute_form.source(), HostSource::HostHeader);
}

/// Positive — the merged determination hands the signer raw bytes and the router a normalised
/// value, from one resolution of one request. Losing either half would undo half the merge: a
/// signer reading the normalised form makes one signature valid for four spellings, and a router
/// reading the raw form gives one bucket four routing keys.
#[test]
fn c_sig_0252b_one_resolution_yields_both_the_raw_and_the_normalised_reading() {
    let host = effective_host(&request("/foo", &["B.Example.COM.:9000"])).expect("resolved");
    assert_eq!(host.as_str(), "b.example.com:9000", "the router reads the normalised value");
    assert_eq!(host.host_without_port(), "b.example.com");
    assert_eq!(host.port(), Some(9000));
    assert_eq!(
        host.raw_for_signing().as_str(),
        "B.Example.COM.:9000",
        "the signer reads the bytes as sent"
    );
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

/// Negative — c-sig-0247: an HTTP/1.1 origin-form request with no `Host` at all. hyper answers 200.
#[test]
fn c_sig_0247_a_request_with_no_host_is_refused() {
    assert_eq!(resolve("/foo", &[]), Err(HostError::Missing));
}

/// Negative — c-sig-0248: an empty `Host:`. hyper answers 200.
#[test]
fn c_sig_0248_an_empty_host_is_refused() {
    assert_eq!(resolve("/foo", &[""]), Err(HostError::Invalid));
}

/// Negative — c-sig-0249: two `Host` headers. hyper answers 200. Refused whether or not they agree:
/// which one is "the" host is the question that must not have an answer here.
#[test]
fn c_sig_0249_duplicate_host_headers_are_refused() {
    assert_eq!(resolve("/foo", &["a", "b"]), Err(HostError::Duplicate));
    assert_eq!(resolve("/foo", &["a", "a"]), Err(HostError::Duplicate));
}

/// Negative — c-sig-0250: an h2 request whose `:authority` and `host` disagree. hyper answers 200,
/// and this is the shape where the signature covers `good` while the router reads `evil`.
#[test]
fn c_sig_0250_an_authority_conflicting_with_the_host_header_is_refused() {
    assert_eq!(resolve("https://good.example.com/foo", &["evil.example.com"]), Err(HostError::Conflict));
}

/// Negative — c-sig-0250b: the comparison is byte-exact, so a case difference between the
/// authority and the `Host` header is a conflict too.
///
/// Positive — the two sources may differ in case, because host names do.
///
/// The merge of the P3-01 wire draft and the P2-03 signature draft first took the stricter,
/// byte-exact reading here, and that was reverted: `B.Example.COM` and `b.example.com` are one
/// host under DNS rules, so the difference cannot point at another bucket or another origin, and
/// non-ASCII is refused before the comparison, so no IDN folding hides behind the case fold. All
/// the strictness bought was a 400 for anyone behind a case-normalising proxy.
///
/// The property byte-exactness protected — which spelling reaches the canonical request — is
/// held directly instead: with both sources present, the `Host` header's bytes are kept.
#[test]
fn c_sig_0250b_an_authority_differing_from_the_host_header_only_in_case_agrees() {
    let from_upper_authority = resolve("http://B.Example.COM/foo", &["b.example.com"]).expect("one host");
    assert_eq!(from_upper_authority.as_bytes(), b"b.example.com");

    let from_upper_header = resolve("http://b.example.com/foo", &["B.Example.COM"]).expect("one host");
    assert_eq!(from_upper_header.as_bytes(), b"B.Example.COM");
}

/// Negative — c-sig-0251: HTTP/1.1 absolute-form whose target authority contradicts `Host`.
/// RFC 9112 §5.5 permits ignoring `Host`; this crate refuses instead, because "silently pick one"
/// is how the signer and the router come to pick differently.
#[test]
fn c_sig_0251_absolute_form_conflicting_with_the_host_header_is_refused() {
    assert_eq!(resolve("http://bucket.example.com/foo", &["other.example.com"]), Err(HostError::Conflict));
}

/// Negative — c-sig-0251b: a malformed `Host` beside a well-formed authority is `Invalid`, not
/// `Conflict`. Both are a 400, so nothing is admitted either way; the ordering is the P2-03 draft's
/// and is kept because it names the actual fault, and because no value reaches the comparison
/// without having been validated first.
#[test]
fn c_sig_0251b_a_malformed_host_beside_a_valid_authority_is_invalid() {
    assert_eq!(resolve("http://a.example.com/foo", &["user@a.example.com"]), Err(HostError::Invalid));
    assert_eq!(resolve("http://a.example.com/foo", &[""]), Err(HostError::Invalid));
}

/// Negative — c-sig-0252: four spellings of one host stay four distinct byte strings, so one
/// signature can never be valid for all of them. This is the many-to-one regression: a resolver
/// that lowercases, strips `:443` and drops the trailing dot would map all four onto one value.
#[test]
fn c_sig_0252_host_spellings_are_never_folded_together() {
    let spellings = ["example.com", "EXAMPLE.COM", "example.com.", "example.com:443"];
    let resolved: Vec<RawHost> = spellings
        .iter()
        .map(|spelling| resolve("/foo", &[spelling]).expect("resolved"))
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
    assert_eq!(resolve("http://example.com/foo", &["example.com:443"]), Err(HostError::Conflict));
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
    assert_eq!(RawHost::from_host_header(&[b'a'; MAX_HOST_BYTES + 1]), Err(HostError::Invalid));
    assert!(RawHost::from_host_header(&[b'a'; MAX_HOST_BYTES]).is_ok());
}

/// Negative — c-sig-0248c: a value that is ASCII-graphic but is not an authority is refused too.
///
/// The P2-03 draft checked only that every byte was ASCII-graphic, which let `user@host`, a
/// path, a five-digit-overflow port and an empty DNS label through into the canonical request. The
/// P3-01 grammar is the stricter of the two and is what the merged function applies; each of these
/// is a string some other component would parse differently than the signer does.
#[test]
fn c_sig_0248c_a_value_that_is_not_an_authority_is_refused() {
    for bad in [
        "user@b.example.com",
        "b.example.com/path",
        "b.example.com?q=1",
        "b.example.com#f",
        "b.example.com:",
        "b.example.com:99999",
        "b.example.com:80a",
        "b.example.com:1:2",
        ".example.com",
        "a..example.com",
        "[2001:db8::1",
    ] {
        assert_eq!(RawHost::from_host_header(bad.as_bytes()), Err(HostError::Invalid), "must reject {bad:?}");
        assert_eq!(RawHost::from_authority(bad), Err(HostError::Invalid), "must reject {bad:?}");
    }
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
