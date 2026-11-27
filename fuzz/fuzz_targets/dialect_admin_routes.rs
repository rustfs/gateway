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

//! Fuzzes `rustfs-gateway-dialect-rustfs-admin` and `rustfs-gateway-dialect-minio` request
//! routing, STS form claim dispatch, and MinIO persisted lifecycle XML decoding.
//!
//! Responsible for: exercising the compiled gateway service with both dialects mounted across
//! arbitrary HTTP methods, paths, queries, headers, and bodies, plus `MinioLifecycleDialect`
//! persisted XML parsing and fail-closed rewrite enforcement.
//! NOT responsible for: backend handler semantics or S3 differential comparisons.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway`, `rustfs-gateway-dialect-rustfs-admin`,
//! and `rustfs-gateway-dialect-minio`.

#![no_main]

use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use libfuzzer_sys::fuzz_target;
use rustfs_gateway::{
    Body, Credentials, DenyAllAuthorizer, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials,
};
use rustfs_gateway_dialect_minio::{MinioLifecycleDialect, replication_dialect};
use rustfs_gateway_dialect_rustfs_admin::rustfs_admin_dialect;
use tokio::runtime::Runtime;
use tower::ServiceExt;

const METHODS: [Method; 6] = [
    Method::GET,
    Method::PUT,
    Method::POST,
    Method::DELETE,
    Method::HEAD,
    Method::OPTIONS,
];

const PATH_PREFIXES: [&str; 9] = [
    "/rustfs/admin/v3/",
    "/minio/admin/v3/",
    "/_iceberg/v1/",
    "/iceberg/v1/",
    "/profile/cpu",
    "/profile/memory",
    "/",
    "/bkt",
    "/bkt/key",
];

struct Harness {
    runtime: Runtime,
    service: S3Service,
    lifecycle: MinioLifecycleDialect,
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fuzz runtime builds");
        let creds = Arc::new(
            StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid synthetic credentials")),
        );
        let auth = SigV4Authenticator::new(creds, RegionSet::new(["us-east-1"]).expect("non-empty regions"));
        let admin = rustfs_admin_dialect().expect("rustfs admin dialect builds");
        let minio = replication_dialect().expect("minio replication dialect builds");
        let service = ServiceBuilder::new()
            .authenticator(auth)
            .authorizer(DenyAllAuthorizer)
            .dialect(&admin)
            .dialect(&minio)
            .build()
            .expect("service with both dialects builds");
        let lifecycle = MinioLifecycleDialect::new().expect("minio lifecycle dialect builds");
        Harness {
            runtime,
            service,
            lifecycle,
        }
    })
}

fn take_slice<'a>(input: &mut &'a [u8], max_len: usize) -> &'a [u8] {
    let Some((&len, rest)) = input.split_first() else {
        return &[];
    };
    let n = usize::from(len).min(max_len).min(rest.len());
    let (head, tail) = rest.split_at(n);
    *input = tail;
    head
}

fuzz_target!(|input: &[u8]| {
    let h = harness();
    let mut rest = input;
    let mode = rest.first().copied().unwrap_or_default();
    rest = rest.get(1..).unwrap_or_default();

    // Exercise MinIO persisted lifecycle XML decoder and fail-closed rewrite invariant.
    let persisted = h.lifecycle.decode_persisted(rest);
    if persisted.value().is_err() {
        assert!(h.lifecycle.rewrite(&persisted).is_err(), "failed persisted decode must block rewrite");
    } else {
        let _ = h.lifecycle.rewrite(&persisted);
    }

    // Exercise compiled routing and claim dispatch across admin, Iceberg, STS form, and replica routes.
    let method = METHODS[usize::from(mode) % METHODS.len()].clone();
    let prefix = PATH_PREFIXES[usize::from(mode >> 3) % PATH_PREFIXES.len()];
    let suffix = String::from_utf8_lossy(take_slice(&mut rest, 128));
    let query = String::from_utf8_lossy(take_slice(&mut rest, 128));
    let target = if query.is_empty() {
        format!("{prefix}{suffix}")
    } else {
        format!("{prefix}{suffix}?{query}")
    };
    let uri = Uri::try_from(target.as_str()).unwrap_or_else(|_| Uri::from_static("/"));
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "s3.example.com")
        .body(Body::from(Bytes::copy_from_slice(&rest[..rest.len().min(4096)])))
        .expect("request builds");

    if mode & 0x80 != 0 {
        req.headers_mut().insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    }
    let _ = h.runtime.block_on(h.service.clone().oneshot(req));
});
