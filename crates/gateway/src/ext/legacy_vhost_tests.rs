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

//! Legacy RustFS's virtual-host reading (rustfs/gateway#1136), pinned to its answers.
//!
//! Responsible for: every reading measured on a legacy build with
//! `RUSTFS_SERVER_DOMAINS=example.com:9411,example.com:9000,s3.local`, and the domain lists legacy
//! RustFS refuses at start-up.
//! NOT responsible for: where the pipeline answers a refusal (`crate::legacy_addressing`), or the
//! objects reached (`compat/sut`'s cases).
//! Upstream: the parent module. Downstream: nothing; this is a leaf test module.

#![allow(clippy::expect_used, clippy::panic)]

use http::Method;
use rustfs_gateway_core::TargetKind;

use super::*;
use crate::ext::host::{Addressing, VhostHint};

fn measured() -> LegacyRustfsVirtualHosts {
    LegacyRustfsVirtualHosts::new(["example.com:9411", "example.com:9000", "s3.local"]).expect("RustFS's list")
}

/// What `resolver` reads `method path` with `Host: host` as: the host-named bucket, or `None` for
/// path style, and the refusal, if any.
fn read(
    resolver: &LegacyRustfsVirtualHosts,
    method: Method,
    path: &str,
    host: &str,
) -> (Option<String>, TargetKind, Option<HostRefusal>) {
    let request = http::Request::builder()
        .method(method.clone())
        .uri(path)
        .header("host", host)
        .body(())
        .expect("a valid request");
    let effective = rustfs_gateway_http::effective_host(&request).expect("an acceptable host");
    let query = HostQuery {
        host: &effective,
        path,
        method: &method,
    };
    let resolved = resolver.resolve(&query);
    let bucket = match &resolved.addressing {
        Addressing::VirtualHosted { bucket, region } => {
            assert_eq!(region, &None, "legacy RustFS reads no region out of a host");
            Some(bucket.as_str().to_owned())
        }
        Addressing::Path => None,
    };
    (bucket, resolved.target, resolver.refusal(&query))
}

fn bucket(host: &str) -> Option<String> {
    read(&measured(), Method::GET, "/k", host).0
}

/// Positive — a host under a domain names the bucket in front of it, whatever port either names.
#[test]
fn a_host_under_a_domain_names_its_bucket_whatever_the_port() {
    for host in [
        "vhb.example.com:9411",
        "vhb.example.com",
        "vhb.example.com:9000",
        "vhb.example.com:1234",
        "vhb.s3.local",
    ] {
        assert_eq!(
            read(&measured(), Method::GET, "/k", host),
            (Some("vhb".to_owned()), TargetKind::Object, None),
            "{host}"
        );
    }
    assert_eq!(read(&measured(), Method::GET, "/", "vhb.example.com").1, TargetKind::Bucket);
}

/// Positive — the whole prefix is the bucket: a dotted bucket, and no region label read out of it.
#[test]
fn the_whole_prefix_is_the_bucket() {
    assert_eq!(bucket("my.dotted.bkt.example.com:9411").as_deref(), Some("my.dotted.bkt"));
    assert_eq!(bucket("vhb.s3.us-west-2.example.com:9411").as_deref(), Some("vhb.s3.us-west-2"));
}

/// Positive — a host no domain matches is its own bucket when, lower-cased, it is a bucket name.
#[test]
fn a_bucket_shaped_host_outside_every_domain_is_a_bucket() {
    assert_eq!(bucket("localhost").as_deref(), Some("localhost"));
    assert_eq!(bucket("other.domain.org").as_deref(), Some("other.domain.org"));
    assert_eq!(bucket("Ex-Ample.COM").as_deref(), Some("ex-ample.com"));
}

/// Positive — the domain itself, an address, and a host whose port makes it no bucket name, are
/// read path-style.
#[test]
fn an_endpoint_an_address_or_a_host_with_a_port_is_path_style() {
    for host in [
        "example.com:9411",
        "example.com",
        "s3.local",
        "localhost:9411",
        "127.0.0.1:9411",
        "[::1]:9411",
        "10.0.0.1",
    ] {
        assert_eq!(read(&measured(), Method::GET, "/vhb/k", host), (None, TargetKind::Object, None), "{host}");
    }
}

/// Positive — RustFS keeps each domain as written and drops a later repeat of its name.
#[test]
fn a_later_repeat_of_a_domain_is_dropped() {
    assert_eq!(measured().domains().collect::<Vec<_>>(), ["example.com:9411", "s3.local"]);
}

/// Negative — a bucket a host names that legacy RustFS's rules refuse is `InvalidBucketName`.
#[test]
fn n_a_refused_host_named_bucket_is_refused() {
    for host in ["VHB.example.com:9411", "Bad_Bkt.example.com:9411", "ab.example.com"] {
        assert_eq!(read(&measured(), Method::GET, "/k", host).2, Some(HostRefusal::RefusedBucket), "{host}");
    }
    // A domain matches case-sensitively, as on legacy RustFS: `vhb.EXAMPLE.com:9411` is under no
    // domain and, with its port, no bucket name, so it is path-style — and its `/k` names the
    // bucket `k`, which the path's own bucket rules refuse (`400 InvalidBucketName` on both).
    assert_eq!(
        read(&measured(), Method::GET, "/k", "vhb.EXAMPLE.com:9411"),
        (None, TargetKind::Bucket, None)
    );
}

/// Negative — a host that is no domain is `InvalidRequest`.
#[test]
fn n_a_host_that_is_no_domain_is_refused() {
    for host in ["my_host:9411", "my_host"] {
        assert_eq!(
            read(&measured(), Method::GET, "/vhb/k", host).2,
            Some(HostRefusal::UnusableHost),
            "{host}"
        );
    }
}

/// Negative — a domain list legacy RustFS refuses at start-up.
#[test]
fn n_a_list_legacy_rustfs_refuses_is_refused() {
    for list in [
        &["exa_mple.com"][..],
        &["example.com:99999"],
        &["example.com:"],
        &["example..com"],
        &["example.com", "s3.example.com"],
        &["s3.example.com", "example.com:9000"],
    ] {
        assert!(LegacyRustfsVirtualHosts::new(list.iter().copied()).is_err(), "{list:?}");
    }
    assert_eq!(
        LegacyRustfsVirtualHosts::new(["example.com", "s3-example.com"]).map(|hosts| hosts.domains().count()),
        Ok(2),
        "a suffix that is not on a label boundary is another domain"
    );
}

/// Negative — with no domain configured every host is path-style, with the hint `PathStyleOnly`
/// gives a misaddressed request, and nothing is refused.
#[test]
fn n_no_domain_reads_every_host_path_style() {
    let none = LegacyRustfsVirtualHosts::new(Vec::<&str>::new()).expect("an empty list");
    for host in ["vhb.example.com", "my_host", "VHB.example.com", "localhost"] {
        assert_eq!(read(&none, Method::GET, "/k", host), (None, TargetKind::Bucket, None), "{host}");
    }
    let request = http::Request::builder()
        .method(Method::PUT)
        .uri("/")
        .header("host", "vhb.example.com")
        .body(())
        .expect("a valid request");
    let effective = rustfs_gateway_http::effective_host(&request).expect("an acceptable host");
    let resolved = none.resolve(&HostQuery {
        host: &effective,
        path: "/",
        method: &Method::PUT,
    });
    assert_eq!(resolved.diagnostic, Some(VhostHint::LooksLikeVhostButNotConfigured));
}
