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

//! PutBucketVersioning decode: the MinIO body literal, the one bucket configuration write where the
//! gateway and the pinned s3s disagree about what a body is.
//!
//! Responsible for: sending the same bytes through the generated `PutBucketVersioning` decoder and
//! through the pinned s3s service (built with its `minio` feature, as RustFS builds it), whose
//! handler records the input it is handed, and pinning where the two part: a body that is the bare
//! text `Enabled`. The test carries its ruling id; the register's guard refuses one without.
//! NOT responsible for: the wire answer (`c-bucketconfig-0060` pins it end to end), storing the
//! configuration, or deciding the ruling (`migration_inventory/request_divergences.rs` does).
//! Upstream: `block_on` and the seam revision bound in `super`. Downstream: the request-divergence
//! register.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

use super::{HOST, block_on, oracle, s3s};

const TARGET: &str = "/photos?versioning";
/// The document form, with its Content-MD5.
const DOCUMENT: (&[u8], &str) = (
    b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    "8qj8HSeDu3APPMQZVG06WQ==",
);
/// The bare literal s3s accepts, with its Content-MD5.
const BARE_ENABLED: (&[u8], &str) = (b"Enabled", "ANI6duQ7Rtrp7Hqp3L67Mg==");
/// The bare literal s3s does not accept, with its Content-MD5.
const BARE_SUSPENDED: (&[u8], &str) = (b"Suspended", "i/kGgzzHrqgIT1UiF+2cHQ==");
/// The accepted literal with ASCII whitespace around it, with its Content-MD5.
const BARE_ENABLED_PADDED: (&[u8], &str) = (b" Enabled\r\n", "BKzQxDfNlKIVG9VEBNH8MQ==");

fn head(body: &[u8], md5: &str) -> http::request::Builder {
    http::Request::builder()
        .method("PUT")
        .uri(format!("http://{HOST}{TARGET}"))
        .header("host", HOST)
        .header("content-md5", md5)
        .header("content-length", body.len().to_string())
}

/// The status the generated decoder read, or its error code.
fn gateway(sample: (&[u8], &str)) -> Result<Option<String>, String> {
    decoded(sample, false)
}

/// The same, on a view the RustFS profile marks to read MinIO's body literal.
fn rustfs_profile(sample: (&[u8], &str)) -> Result<Option<String>, String> {
    decoded(sample, true)
}

fn decoded((body, md5): (&[u8], &str), literals: bool) -> Result<Option<String>, String> {
    let request = head(body, md5).body(()).map_err(|error| format!("fixture head: {error}"))?;
    let wire = WireRequest::accept(request, &Limits::default()).map_err(|error| format!("wire refusal: {error:?}"))?;
    let view = MetaView::of(&wire, TargetKind::Bucket).map_err(|error| error.code().as_str().to_owned())?;
    let view = if literals { view.with_body_literals() } else { view };
    dto::PutBucketVersioning::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(body)))
        .map(|input| input.versioning_configuration.status.map(|status| status.as_str().to_owned()))
        .map_err(|error| error.code().as_str().to_owned())
}

/// What the pinned s3s service did with one body.
#[derive(Debug, PartialEq, Eq)]
struct OracleAnswer {
    status: u16,
    /// The status the `put_bucket_versioning` handler was handed, when it was reached.
    handed: Option<Option<String>>,
    /// The `<Code>` of the error document, when the answer is one.
    code: Option<String>,
}

/// An s3s backend whose only handler records the versioning input it is handed.
struct RecordingS3 {
    captured: Arc<Mutex<Option<oracle::PutBucketVersioningInput>>>,
}

impl s3s::S3 for RecordingS3 {
    // The pinned trait is declared with `#[async_trait]`; this is the signature that attribute
    // expands a `&self` method to, as in the PutObject harness.
    fn put_bucket_versioning<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::PutBucketVersioningInput>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<oracle::PutBucketVersioningOutput>>> + Send + 'future>>
    where
        'life0: 'future,
        Self: 'future,
    {
        let captured = Arc::clone(&self.captured);
        Box::pin(async move {
            if let Ok(mut slot) = captured.lock() {
                *slot = Some(request.input);
            }
            Ok(s3s::S3Response::new(oracle::PutBucketVersioningOutput::default()))
        })
    }
}

fn s3s_exchange((body, md5): (&[u8], &str)) -> OracleAnswer {
    let captured = Arc::new(Mutex::new(None));
    let service = s3s::service::S3ServiceBuilder::new(RecordingS3 {
        captured: Arc::clone(&captured),
    })
    .build();
    let request = head(body, md5)
        .body(s3s::Body::from(Bytes::copy_from_slice(body)))
        .expect("the fixture request is valid");
    let response = block_on(service.call(request)).expect("the s3s service answers");
    let (parts, mut answer) = response.into_parts();
    let answer = block_on(answer.store_all_limited(1 << 20)).expect("the s3s answer is readable");
    let text = String::from_utf8_lossy(&answer);
    let code = text
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.to_owned());
    let handed = captured
        .lock()
        .expect("the recording slot is not poisoned")
        .take()
        .map(|input| input.versioning_configuration.status.map(|status| status.as_str().to_owned()));
    OracleAnswer {
        status: parts.status.as_u16(),
        handed,
        code,
    }
}

// ── named divergence ──────────────────────────────────────────────────────────────────────────

/// The bare text `Enabled` as the whole body: s3s, built with `minio`, hands its handler Status
/// Enabled; the gateway refuses it as `MalformedXML` by default, because only a view the RustFS
/// profile marks reads the literal and the body is otherwise the document (`c-bucketconfig-0060`,
/// decided in rustfs/gateway#715).
/// Both stacks agree on the XML document — the control that makes the refusal about the literal —
/// and on a bare `Suspended`, which s3s reads as XML and refuses too: the literal it accepts is
/// `Enabled` alone.
///
/// Ruling: `rd-cfg-0001`
#[test]
fn a_bare_enabled_versioning_body_is_refused_by_the_gateway_and_accepted_by_s3s() {
    let enabled = Some(Some("Enabled".to_owned()));

    assert_eq!(gateway(DOCUMENT), Ok(Some("Enabled".to_owned())), "the gateway reads the document");
    let document = s3s_exchange(DOCUMENT);
    assert_eq!(
        (document.status, &document.handed),
        (200, &enabled),
        "s3s reads the document: {document:?}"
    );

    assert_eq!(gateway(BARE_ENABLED), Err("MalformedXML".to_owned()), "the gateway refuses the literal");
    let bare = s3s_exchange(BARE_ENABLED);
    assert_eq!((bare.status, &bare.handed), (200, &enabled), "s3s reads the literal as Enabled: {bare:?}");

    assert_eq!(gateway(BARE_SUSPENDED), Err("MalformedXML".to_owned()));
    let suspended = s3s_exchange(BARE_SUSPENDED);
    assert_eq!(
        suspended,
        OracleAnswer {
            status: 400,
            handed: None,
            code: Some("MalformedXML".to_owned()),
        },
        "s3s has no Suspended literal"
    );
}

// ── the RustFS profile ────────────────────────────────────────────────────────────────────────

/// On a view the RustFS profile marks (`ServiceBuilder::accept_minio_body_literals`), the gateway
/// reads the literal as the legacy stack does: `Enabled`, trimmed of ASCII whitespace, is Status
/// Enabled on both, the document is unchanged, and a bare `Suspended` is refused by both. The
/// whole input RustFS is handed is compared through the production seam by the seam diff
/// (`put-bucket-versioning-bare-enabled*`).
#[test]
fn under_the_rustfs_profile_the_bare_literal_reads_as_the_legacy_stack_reads_it() {
    let enabled = Some(Some("Enabled".to_owned()));
    for sample in [BARE_ENABLED, BARE_ENABLED_PADDED, DOCUMENT] {
        assert_eq!(rustfs_profile(sample), Ok(Some("Enabled".to_owned())), "{:?}", sample.0);
        let legacy = s3s_exchange(sample);
        assert_eq!((legacy.status, &legacy.handed), (200, &enabled), "{legacy:?}");
    }
    assert_eq!(rustfs_profile(BARE_SUSPENDED), Err("MalformedXML".to_owned()));
    assert_eq!(s3s_exchange(BARE_SUSPENDED).status, 400);
    // The default is untouched: an unmarked view still refuses the padded literal.
    assert_eq!(gateway(BARE_ENABLED_PADDED), Err("MalformedXML".to_owned()));
}
