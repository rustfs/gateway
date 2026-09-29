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

//! Legacy RustFS's virtual hosts as the launcher serves them (rustfs/gateway#1136), with
//! `--server-domains s3.example.com:9100,s3.local` as RustFS reads `RUSTFS_SERVER_DOMAINS`.
//!
//! Responsible for: an object written path-style read back through a host under a domain whatever
//! its port, through a dotted bucket's host and through a CNAME-style host, and written through one
//! and read back path-style; a host that is no domain refused before anything is written.
//! NOT responsible for: the reading itself (`rustfs-gateway`'s `legacy_vhost` tests).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

fn to(host: &str, method: http::Method, target: &str, body: &'static [u8]) -> http::Request<Bytes> {
    signed_to(
        host,
        Some("us-east-1"),
        MAIN_KEY,
        MAIN_SECRET,
        method,
        target,
        Bytes::from_static(body),
        &[],
    )
}

/// A service reading `s3.example.com` (any port) and `s3.local`, with the buckets `vhb`,
/// `my.dotted.bkt` and `cname.example.org`, each holding `k`.
async fn hosted(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &["--server-domains", "s3.example.com:9100,s3.local"]));
    for bucket in ["vhb", "my.dotted.bkt", "cname.example.org"] {
        let created = exchange(&service, as_main(http::Method::PUT, &format!("/{bucket}"), Bytes::new())).await;
        assert_eq!(created.status(), 200, "{bucket}: {}", body_of(&created));
        let written = exchange(
            &service,
            as_main(http::Method::PUT, &format!("/{bucket}/k"), Bytes::from(bucket.to_owned())),
        )
        .await;
        assert_eq!(written.status(), 200, "{bucket}: {}", body_of(&written));
    }
    service
}

/// Positive — an object written path-style is read through a host under a domain whatever its
/// port, through its dotted bucket's host, and through a host that is its bucket's name.
#[tokio::test]
async fn a_host_reads_the_object_legacy_rustfs_reads() {
    let root = TestRoot::new();
    let service = hosted(&root).await;
    for (host, expected) in [
        ("vhb.s3.example.com", "vhb"),
        ("vhb.s3.example.com:9100", "vhb"),
        ("vhb.s3.example.com:1234", "vhb"),
        ("vhb.s3.local", "vhb"),
        ("my.dotted.bkt.s3.example.com", "my.dotted.bkt"),
        ("cname.example.org", "cname.example.org"),
    ] {
        let read = exchange(&service, to(host, http::Method::GET, "/k", b"")).await;
        assert_eq!(read.status(), 200, "{host}: {}", body_of(&read));
        assert_eq!(body_of(&read), expected, "{host}");
    }
}

/// Positive — an object written through a dotted bucket's host is the object path-style reads.
#[tokio::test]
async fn a_write_through_a_host_is_the_path_style_object() {
    let root = TestRoot::new();
    let service = hosted(&root).await;
    let written = exchange(
        &service,
        to("my.dotted.bkt.s3.example.com:9100", http::Method::PUT, "/via-host", b"hosted"),
    )
    .await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    let read = exchange(&service, as_main(http::Method::GET, "/my.dotted.bkt/via-host", Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(read.body().as_ref(), b"hosted");
}

/// Negative — a host that is no domain is `InvalidRequest`, and a bucket a host names that legacy
/// RustFS's rules refuse is `InvalidBucketName`; nothing is written.
#[tokio::test]
async fn n_a_host_legacy_rustfs_refuses_writes_nothing() {
    let root = TestRoot::new();
    let service = hosted(&root).await;
    for (host, target, code) in [
        ("my_host:9100", "/vhb/refused", "InvalidRequest"),
        ("Bad_Bkt.s3.example.com", "/refused", "InvalidBucketName"),
    ] {
        let refused = exchange(&service, to(host, http::Method::PUT, target, b"no")).await;
        assert_eq!(refused.status(), 400, "{host}: {}", body_of(&refused));
        assert!(
            body_of(&refused).contains(&format!("<Code>{code}</Code>")),
            "{host}: {}",
            body_of(&refused)
        );
    }
    let listing = exchange(&service, as_main(http::Method::GET, "/vhb?list-type=2", Bytes::new())).await;
    assert!(!body_of(&listing).contains("refused"), "{}", body_of(&listing));
}
