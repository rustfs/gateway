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

//! Responsible for: arbitrary raw host acceptance and virtual-host label-boundary invariants.
//! NOT responsible for: authentication, routing, bucket existence or request bodies.
//! Upstream: libFuzzer and the request-head acceptance boundary.
//! Downstream: the public HostResolver implementation and its path-style fallback.

#![no_main]

use http::{HeaderValue, Request, Uri, header::HOST};
use libfuzzer_sys::fuzz_target;
use rustfs_gateway::{Addressing, HostQuery, HostResolver, Limits, VirtualHostStyle, WireRequest};
use rustfs_gateway_types::BucketName;
use std::sync::LazyLock;

const DOMAINS: [&str; 2] = ["mys3.com", "s3.example.com"];
static RESOLVER: LazyLock<VirtualHostStyle> =
    LazyLock::new(|| VirtualHostStyle::new(DOMAINS).unwrap_or_else(|error| panic!("fixed fuzz domains are invalid: {error}")));

fuzz_target!(|raw: &[u8]| {
    // Invalid wire bytes cannot construct a HostQuery. Exercise that boundary before resolving.
    let Ok(value) = HeaderValue::from_bytes(raw) else {
        return;
    };
    let mut request = Request::new(());
    *request.uri_mut() = Uri::from_static("/bucket/key");
    request.headers_mut().insert(HOST, value);
    let Ok(accepted) = WireRequest::accept(request, &Limits::default()) else {
        return;
    };
    let host = accepted.host().host_without_port();
    // An independent label comparison, not the resolver's byte-offset/suffix algorithm.
    let has_domain_labels = DOMAINS
        .iter()
        .any(|domain| host.rsplit('.').take(domain.split('.').count()).eq(domain.rsplit('.')));
    let resolved = RESOLVER.resolve(&HostQuery {
        host: accepted.host(),
        path: accepted.raw_path().as_str(),
        method: accepted.method(),
    });
    if !has_domain_labels {
        assert_eq!(resolved.addressing, Addressing::Path);
    }
    // The opposite control prevents a resolver that always returns Path from looking correct.
    if let Some((label, rest)) = host.split_once('.')
        && DOMAINS.contains(&rest)
        && let Ok(bucket) = BucketName::new(label)
    {
        assert_eq!(resolved.bucket().map(BucketName::as_str), Some(bucket.as_str()));
    }
    assert_eq!(accepted.host().raw_for_signing().as_str().as_bytes(), raw);
});
