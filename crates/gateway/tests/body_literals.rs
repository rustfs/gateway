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

//! MinIO's bare body literal through a whole service (rustfs/backlog#1677, R6).
//!
//! Responsible for: `ServiceBuilder::accept_minio_body_literals` handing PutBucketVersioning and
//! PutObjectLockConfiguration handlers the `Enabled` document for a body that is the bare word,
//! while the default assembly answers it `400 MalformedXML` before any handler, and the switch
//! reaches no other operation and no other spelling.
//! NOT responsible for: the expansion itself (`rustfs-gateway-core`'s codec tests), the stored
//! configuration (`compat-sut` and the seam diff), or the digest rules (checked over the bytes that
//! arrived, in the core tests).
//! Upstream: `S3Service` with recording handlers. Downstream: none.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::{BODY_LITERAL_OPERATIONS, Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, dto};

use super::tagging_reachability::content_md5;
use crate::support;

/// What each handler was handed: the operation and the one member the literal sets.
#[derive(Default)]
struct Recorded(Mutex<Vec<(&'static str, Option<String>)>>);

struct Backend(Arc<Recorded>);

impl Backend {
    fn record(&self, operation: &'static str, value: Option<String>) {
        self.0
            .0
            .lock()
            .expect("the record is never poisoned")
            .push((operation, value));
    }
}

impl Handler<dto::PutBucketVersioning> for Backend {
    async fn call(&self, request: Req<dto::PutBucketVersioning>) -> HandlerResult<dto::PutBucketVersioning> {
        let status = request.into_input().versioning_configuration.status;
        self.record("PutBucketVersioning", status.map(|status| status.as_str().to_owned()));
        Ok(Resp::new(dto::PutBucketVersioningOutput::default()))
    }
}

impl Handler<dto::PutObjectLockConfiguration> for Backend {
    async fn call(&self, request: Req<dto::PutObjectLockConfiguration>) -> HandlerResult<dto::PutObjectLockConfiguration> {
        let configuration = request.into_input().object_lock_configuration;
        let enabled = configuration.object_lock_enabled.map(|enabled| enabled.as_str().to_owned());
        assert!(configuration.rule.is_none(), "the literal sets no rule");
        self.record("PutObjectLockConfiguration", enabled);
        Ok(Resp::new(dto::PutObjectLockConfigurationOutput::default()))
    }
}

impl Handler<dto::PutBucketAccelerateConfiguration> for Backend {
    async fn call(
        &self,
        request: Req<dto::PutBucketAccelerateConfiguration>,
    ) -> HandlerResult<dto::PutBucketAccelerateConfiguration> {
        let status = request.into_input().accelerate_configuration.status;
        self.record("PutBucketAccelerateConfiguration", status.map(|status| status.as_str().to_owned()));
        Ok(Resp::new(dto::PutBucketAccelerateConfigurationOutput::default()))
    }
}

fn service(accept_literals: bool) -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let backend = Arc::new(Backend(Arc::clone(&recorded)));
    let mut builder: ServiceBuilder = support::wired_at_signed_time();
    if accept_literals {
        builder = builder.accept_minio_body_literals();
    }
    let service = builder
        .register::<dto::PutBucketVersioning, _>(Arc::clone(&backend))
        .register::<dto::PutObjectLockConfiguration, _>(Arc::clone(&backend))
        .register::<dto::PutBucketAccelerateConfiguration, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, recorded)
}

/// One signed write of `body`, with its own `Content-MD5` (both literal operations require one).
async fn put(service: &S3Service, target: &str, body: &[u8]) -> (http::StatusCode, String) {
    let digest = content_md5(body);
    let request = support::signed_target_with_body_and_headers(
        http::Method::PUT,
        target,
        &[("content-md5", &digest)],
        Bytes::copy_from_slice(body),
    );
    support::exchange(service, request).await
}

fn handed(recorded: &Recorded) -> Vec<(&'static str, Option<String>)> {
    recorded.0.lock().expect("the record is never poisoned").clone()
}

#[test]
fn the_switch_covers_exactly_the_two_literal_operations() {
    let mut operations = BODY_LITERAL_OPERATIONS.to_vec();
    operations.sort_unstable();
    assert_eq!(operations, ["PutBucketVersioning", "PutObjectLockConfiguration"]);
}

/// Positive — under the switch both operations' handlers are handed `Enabled` for the bare word,
/// padded with ASCII whitespace or not.
#[tokio::test]
async fn under_the_switch_the_literal_reaches_both_handlers_as_enabled() {
    let (service, recorded) = service(true);
    for body in [b"Enabled".as_slice(), b" Enabled\r\n"] {
        for target in ["/bucket?versioning", "/bucket?object-lock"] {
            let (status, answer) = put(&service, target, body).await;
            assert_eq!(status, http::StatusCode::OK, "{target} {body:?}: {answer}");
        }
    }
    let enabled = Some("Enabled".to_owned());
    assert_eq!(
        handed(&recorded),
        [
            ("PutBucketVersioning", enabled.clone()),
            ("PutObjectLockConfiguration", enabled.clone()),
            ("PutBucketVersioning", enabled.clone()),
            ("PutObjectLockConfiguration", enabled),
        ]
    );
}

/// Negative — the default assembly answers the literal `400 MalformedXML` before any handler.
#[tokio::test]
async fn n_by_default_the_literal_is_malformed_and_reaches_no_handler() {
    let (service, recorded) = service(false);
    for target in ["/bucket?versioning", "/bucket?object-lock"] {
        let (status, answer) = put(&service, target, b"Enabled").await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{target}: {answer}");
        assert_eq!(support::element_text(&answer, "Code"), Some("MalformedXML"), "{target}");
    }
    assert!(handed(&recorded).is_empty());
}

/// Negative — under the switch every other spelling is still malformed, and the switch reaches no
/// operation whose document has no literal.
#[tokio::test]
async fn n_under_the_switch_no_other_spelling_or_operation_is_read_as_the_literal() {
    let (service, recorded) = service(true);
    for body in [b"enabled".as_slice(), b"Suspended", b"EnabledX", b"Enabled\0"] {
        for target in ["/bucket?versioning", "/bucket?object-lock"] {
            let (status, answer) = put(&service, target, body).await;
            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{target} {body:?}: {answer}");
            assert_eq!(support::element_text(&answer, "Code"), Some("MalformedXML"), "{target} {body:?}");
        }
    }
    let (status, answer) = put(&service, "/bucket?accelerate", b"Enabled").await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(support::element_text(&answer, "Code"), Some("MalformedXML"));
    assert!(handed(&recorded).is_empty());
}
