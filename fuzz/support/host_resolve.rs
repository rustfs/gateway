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

//! The `host_resolve` property: arbitrary `Host` bytes, method and path through acceptance, the
//! shipped `VirtualHostStyle` resolver and the single `(bucket, key)` split.
//!
//! Responsible for: decoding one fuzz input into a method, raw `Host` bytes and a path; accepting
//! it the way the service does; resolving it under [`DOMAINS`]; and asserting what the resolver and
//! `MetaView` promise about every host, accepted or refused.
//! NOT responsible for: choosing a libFuzzer entry point, generating samples (the stable replay in
//! `crates/gateway/tests/host_resolve_replay.rs` does that), authentication, or whether a named
//! bucket exists.
//! Upstream: libFuzzer bytes, a committed seed under `fuzz/seeds/host_resolve/`, or the replay's
//! fixed-seed sampler. Downstream: `fuzz/fuzz_targets/host_resolve.rs` and the replay, which run
//! this same file.
//!
//! # Input layout
//!
//! | Offset | Meaning |
//! | --- | --- |
//! | 0 | method: index into [`METHODS`], modulo its length |
//! | 1 | `n`, the length of the `Host` bytes (clamped to what remains) |
//! | 2..2+n | the raw `Host` header bytes |
//! | 2+n.. | the request path after its leading `/` |
//!
//! # What is asserted, beyond "it did not panic"
//!
//! The oracle reads a host as a list of labels. The resolver matches bytes at a boundary offset.
//! The two agree only if the boundary rule is right, which is the point of writing it that way.
//!
//! 1. **The signature sees the bytes that were sent.** `raw_for_signing` equals the `Host` bytes,
//!    whatever the resolver normalised for matching.
//! 2. **Only a configured domain, on whole labels, can name a bucket.** When no configured domain is
//!    a whole-label suffix of the host, or the host is an address literal, the answer is exactly the
//!    one [`PathStyleOnly`] gives — same target, same `Path` addressing, same hint. Configuring
//!    domains may not change how any other host resolves (s3s#643, s3s#147/#150, s3s#648).
//! 3. **A served host resolves by its prefix shape, and only by it.** Under the longest matching
//!    domain, `<bucket>`, `<bucket>.s3` and `<bucket>.s3.<region>` name that bucket (and region);
//!    every other prefix, the empty one included, is path style with no hint.
//! 4. **The hint fires exactly when it should, and never on a resolution.** A hint only rides a
//!    path-style answer to `PUT`, `DELETE` or `GET /` on an unserved, non-address host whose first
//!    label could be a bucket.
//! 5. **Under a virtual host the path cannot name a bucket.** `MetaView` takes the bucket from the
//!    host, never from the first path segment, and the key it builds is exactly the key the same
//!    object has when addressed path style as `/<bucket><path>`.

#![allow(dead_code)] // The fuzz binary calls `check` only; the replay also reads the constants.

use std::sync::LazyLock;

use http::{HeaderValue, Method, Request, Uri, header::HOST};
use rustfs_gateway::{
    Addressing, BucketName, HostQuery, HostResolver, Limits, MetaView, PathStyleOnly, ResolvedHost, TargetKind, VirtualHostStyle,
    WireRequest,
};

/// The base domains every input is resolved under.
///
/// `example.com` sits under `s3.example.com` so that the longest match is observable: the host
/// `conf-host.s3.s3.example.com` names no region under the longer domain and the region `s3`
/// under the shorter one. `168.1.1` is a legal domain that is a whole-label suffix of the address
/// `192.168.1.1`. `localhost` is the single-label development setup.
pub(crate) const DOMAINS: [&str; 5] = ["mys3.com", "s3.example.com", "example.com", "168.1.1", "localhost"];

/// The methods an input can select: the three the hint is about, and two it is not.
pub(crate) const METHODS: [Method; 5] = [Method::GET, Method::PUT, Method::DELETE, Method::HEAD, Method::POST];

/// How many leading input bytes select the case rather than form the host or the path.
pub(crate) const HEADER_BYTES: usize = 2;

/// The resolver under test, built once.
static RESOLVER: LazyLock<VirtualHostStyle> =
    LazyLock::new(|| VirtualHostStyle::new(DOMAINS).expect("DOMAINS is a constant list of well-formed base domains"));

/// Encodes one case in the input layout. The replay's sampler and the seed files both use it.
pub(crate) fn encode(method: u8, host: &[u8], path_after_slash: &[u8]) -> Vec<u8> {
    let length = u8::try_from(host.len()).unwrap_or(u8::MAX);
    let host = &host[..usize::from(length)];
    let mut input = Vec::with_capacity(HEADER_BYTES + host.len() + path_after_slash.len());
    input.push(method);
    input.push(length);
    input.extend_from_slice(host);
    input.extend_from_slice(path_after_slash);
    input
}

/// What one input did.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The bytes never became an accepted request: not a header value, not a path, or refused by
    /// acceptance. Nothing was resolved.
    NotAccepted,
    /// The request was accepted and resolved.
    Resolved(Resolution),
}

/// An accepted request's resolution and the `(bucket, key)` it produced.
#[derive(Debug)]
pub(crate) struct Resolution {
    /// The resolver's answer.
    pub(crate) resolved: ResolvedHost,
    /// `MetaView`'s bucket and key, or `Err(())` when it refused the path.
    pub(crate) meta: Result<(Option<String>, Option<String>), ()>,
}

/// Runs one input and asserts every property in the module docs.
///
/// Returns `None` for an input shorter than [`HEADER_BYTES`].
pub(crate) fn check(input: &[u8]) -> Option<Outcome> {
    let (&[method, length], rest) = input.split_first_chunk::<HEADER_BYTES>()?;
    let method = &METHODS[usize::from(method) % METHODS.len()];
    let (host_bytes, path_rest) = rest.split_at(usize::from(length).min(rest.len()));
    let path_bytes = [b"/".as_slice(), path_rest].concat();

    let Some(accepted) = accept(method, host_bytes, &path_bytes) else {
        return Some(Outcome::NotAccepted);
    };

    // 1. The signature sees the bytes that were sent.
    assert_eq!(
        accepted.host().raw_for_signing().as_bytes(),
        host_bytes,
        "the signed host is not the host that was sent"
    );

    let host = accepted.host().host_without_port();
    let path = accepted.raw_path().as_str();
    let query = HostQuery {
        host: accepted.host(),
        path,
        method,
    };
    let resolved = RESOLVER.resolve(&query);
    let unconfigured = PathStyleOnly.resolve(&query);

    match served_prefix(host) {
        // 2. Only a configured domain, on whole labels, can name a bucket.
        None => assert_eq!(
            resolved, unconfigured,
            "host {host:?} is under no configured domain and must resolve as if none were configured"
        ),
        // 3. A served host resolves by its prefix shape, and only by it.
        Some(prefix) => match named_by(&prefix) {
            Some((bucket, region)) => {
                let target = if path.strip_prefix('/').unwrap_or(path).is_empty() {
                    TargetKind::Bucket
                } else {
                    TargetKind::Object
                };
                let expected = ResolvedHost::virtual_hosted(target, bucket, region.map(Box::from));
                assert_eq!(resolved, expected, "host {host:?} path {path:?}");
            }
            None => assert_eq!(
                resolved,
                ResolvedHost::standard(unconfigured.target),
                "host {host:?} is served with the unreadable prefix {prefix:?} and must be path style with no hint"
            ),
        },
    }

    // 4. The hint fires exactly when it should, and never on a resolution.
    let looks_virtual_hosted = path == "/"
        && matches!(*method, Method::GET | Method::PUT | Method::DELETE)
        && !is_address(host)
        && host
            .split_once('.')
            .is_some_and(|(first, rest)| !rest.is_empty() && BucketName::new(first).is_ok());
    let hint_expected = served_prefix(host).is_none() && looks_virtual_hosted;
    assert_eq!(resolved.diagnostic.is_some(), hint_expected, "hint on {method} {path:?} at host {host:?}");
    if resolved.diagnostic.is_some() {
        assert_eq!(resolved.addressing, Addressing::Path, "a hint rode a virtual-hosted answer");
    }

    // 5. Under a virtual host the path cannot name a bucket.
    let meta = match MetaView::addressed(&accepted, resolved.target, resolved.bucket().cloned()) {
        Ok(view) => Ok((
            view.bucket().map(|bucket| bucket.as_str().to_owned()),
            view.key().map(|key| key.as_str().to_owned()),
        )),
        Err(_) => Err(()),
    };
    if let Some(bucket) = resolved.bucket() {
        if let Ok((meta_bucket, _)) = &meta {
            assert_eq!(
                meta_bucket.as_deref(),
                Some(bucket.as_str()),
                "the bucket acted on is not the bucket the host named, for path {path:?}"
            );
        }
        assert_eq!(
            meta,
            path_style_meta(bucket, path),
            "host {host:?} path {path:?}: the virtual-hosted (bucket, key) differs from the same object addressed path style"
        );
    }

    Some(Outcome::Resolved(Resolution { resolved, meta }))
}

/// Builds and accepts a request the way the service does, or `None` where either refuses it.
fn accept(method: &Method, host: &[u8], path: &[u8]) -> Option<WireRequest<()>> {
    let host = HeaderValue::from_bytes(host).ok()?;
    let uri = Uri::try_from(path).ok()?;
    let mut request = Request::new(());
    *request.method_mut() = method.clone();
    *request.uri_mut() = uri;
    request.headers_mut().insert(HOST, host);
    WireRequest::accept(request, &Limits::default()).ok()
}

/// The `(bucket, key)` of `/<bucket><path>` addressed path style: the reading a virtual-hosted
/// request for the same object must reproduce.
fn path_style_meta(bucket: &BucketName, path: &str) -> Result<(Option<String>, Option<String>), ()> {
    let target = format!("/{}{path}", bucket.as_str());
    let accepted = accept(&Method::GET, b"s3.example.com", target.as_bytes())
        .expect("a legal bucket label in front of an accepted path is an accepted path");
    let resolved = PathStyleOnly.resolve(&HostQuery {
        host: accepted.host(),
        path: accepted.raw_path().as_str(),
        method: &Method::GET,
    });
    match MetaView::addressed(&accepted, resolved.target, None) {
        Ok(view) => Ok((
            view.bucket().map(|bucket| bucket.as_str().to_owned()),
            view.key().map(|key| key.as_str().to_owned()),
        )),
        Err(_) => Err(()),
    }
}

/// The labels in front of the configured domain with the most labels that ends `host` on whole
/// labels, or `None` when the host is an address or no configured domain ends it.
///
/// Label lists, compared whole: the independent reading of "on a label boundary".
fn served_prefix(host: &str) -> Option<Vec<&str>> {
    if is_address(host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    DOMAINS
        .iter()
        .filter_map(|domain| {
            let suffix: Vec<&str> = domain.split('.').collect();
            let front = labels.len().checked_sub(suffix.len())?;
            (labels[front..] == suffix[..]).then(|| (suffix.len(), labels[..front].to_vec()))
        })
        .max_by_key(|(depth, _)| *depth)
        .map(|(_, prefix)| prefix)
}

/// The bucket and region a served prefix names, from the prefix-shape table.
fn named_by<'a>(prefix: &[&'a str]) -> Option<(BucketName, Option<&'a str>)> {
    let (bucket, region) = match prefix {
        [bucket] | [bucket, "s3"] => (*bucket, None),
        [bucket, "s3", region] if is_plausible_region(region) => (*bucket, Some(*region)),
        _ => return None,
    };
    BucketName::new(bucket).ok().map(|bucket| (bucket, region))
}

/// A region label: 1 to 32 bytes of lower-case letters, digits and `-`, alphanumeric at both ends.
fn is_plausible_region(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |byte: Option<&u8>| byte.is_some_and(u8::is_ascii_alphanumeric);
    (1..=32).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && edge(bytes.first())
        && edge(bytes.last())
}

/// A bracketed IPv6 literal, or four dot-separated runs of decimal digits.
fn is_address(host: &str) -> bool {
    if host.starts_with('[') {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() == 4
        && labels
            .iter()
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
}
