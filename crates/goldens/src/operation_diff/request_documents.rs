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

//! Request documents decoded by the gateway and converted through the generated seam, against the
//! pinned legacy stack's own service (built with MinIO support, as RustFS builds it), compared at
//! the document the RustFS body is handed (rustfs/gateway#1078).
//!
//! Responsible for: the harness — one request document through the gateway's generated decoder
//! and the seam's input conversion, and through the legacy service, whose handlers record the
//! document they are handed — and the proof that an empty required enumeration element reaches
//! the RustFS body as the same empty value on both stacks, which is what RustFS then judges (it
//! refuses an empty lifecycle status and stores an empty `Payer`).
//! NOT responsible for: what RustFS does with a document (its own handlers, behind the seam), or
//! persistence (the `dto_bridge` tests).
//! Upstream: the harness, the generated seam. Downstream: nothing.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

use super::put_object::md5_base64;
use super::s3s::{Body as LegacyBody, S3, S3Request, S3Response, S3Result, service::S3ServiceBuilder};
use super::seam::generated::ops::{
    put_bucket_encryption, put_bucket_lifecycle_configuration, put_bucket_replication, put_bucket_request_payment,
    restore_object,
};
use super::{HOST, block_on, oracle};

/// The request documents this harness writes, one per operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Document {
    Lifecycle,
    Replication,
    RequestPayment,
    Encryption,
    Restore,
}

impl Document {
    fn method(self) -> &'static str {
        match self {
            Self::Restore => "POST",
            _ => "PUT",
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::Lifecycle => "/photos?lifecycle",
            Self::Replication => "/photos?replication",
            Self::RequestPayment => "/photos?requestPayment",
            Self::Encryption => "/photos?encryption",
            Self::Restore => "/photos/key?restore",
        }
    }

    fn kind(self) -> TargetKind {
        match self {
            Self::Restore => TargetKind::Object,
            _ => TargetKind::Bucket,
        }
    }
}

/// What the RustFS body was handed — the document, in the legacy stack's `Debug` spelling — or the
/// `<Code>` a stack refused the request with before any body ran.
pub(crate) type Handed = Result<String, String>;

fn head(document: Document, body: &[u8]) -> http::request::Builder {
    http::Request::builder()
        .method(document.method())
        .uri(format!("http://{HOST}{}", document.target()))
        .header("host", HOST)
        .header("content-md5", md5_base64(body))
        .header("content-length", body.len().to_string())
}

fn decode<O: OperationCodec>(document: Document, body: &[u8]) -> Result<O::Input, String> {
    let request = head(document, body).body(()).map_err(|error| format!("fixture head: {error}"))?;
    let wire = WireRequest::accept(request, &Limits::default()).map_err(|error| format!("wire refusal: {error:?}"))?;
    let view = MetaView::of(&wire, document.kind()).map_err(|error| error.code().as_str().to_owned())?;
    O::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(body))).map_err(|error| error.code().as_str().to_owned())
}

/// The document the gateway hands the RustFS body: decoded, then converted through the seam.
pub(crate) fn gateway(document: Document, body: &[u8]) -> Handed {
    let seam = |error: &dyn std::fmt::Display| format!("seam: {error}");
    match document {
        Document::Lifecycle => {
            let input = decode::<dto::PutBucketLifecycleConfiguration>(document, body)?;
            let converted = put_bucket_lifecycle_configuration::input_to_s3s(input).map_err(|error| seam(&error))?;
            Ok(format!("{:?}", converted.lifecycle_configuration))
        }
        Document::Replication => {
            let input = decode::<dto::PutBucketReplication>(document, body)?;
            let converted = put_bucket_replication::input_to_s3s(input).map_err(|error| seam(&error))?;
            Ok(format!("{:?}", converted.replication_configuration))
        }
        Document::RequestPayment => {
            let input = decode::<dto::PutBucketRequestPayment>(document, body)?;
            let converted = put_bucket_request_payment::input_to_s3s(input).map_err(|error| seam(&error))?;
            Ok(format!("{:?}", converted.request_payment_configuration))
        }
        Document::Encryption => {
            let input = decode::<dto::PutBucketEncryption>(document, body)?;
            let converted = put_bucket_encryption::input_to_s3s(input).map_err(|error| seam(&error))?;
            Ok(format!("{:?}", converted.server_side_encryption_configuration))
        }
        Document::Restore => {
            let input = decode::<dto::RestoreObject>(document, body)?;
            let converted = restore_object::input_to_s3s(input).map_err(|error| seam(&error))?;
            Ok(format!("{:?}", converted.restore_request))
        }
    }
}

/// A legacy-stack backend whose document writes record the document they are handed.
struct Recording {
    handed: Arc<Mutex<Option<String>>>,
}

type Answer<T> = Pin<Box<dyn Future<Output = S3Result<S3Response<T>>> + Send + 'static>>;

impl Recording {
    fn record<T: Default + Send + 'static>(&self, handed: String) -> Answer<T> {
        if let Ok(mut slot) = self.handed.lock() {
            *slot = Some(handed);
        }
        Box::pin(async { Ok(S3Response::new(T::default())) })
    }
}

impl S3 for Recording {
    // The pinned trait is declared with `#[async_trait]`; these are the signatures that attribute
    // expands a `&self` method to, as in the PutObject harness.
    fn put_bucket_lifecycle_configuration<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::PutBucketLifecycleConfigurationInput>,
    ) -> Answer<oracle::PutBucketLifecycleConfigurationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.lifecycle_configuration))
    }

    fn put_bucket_replication<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::PutBucketReplicationInput>,
    ) -> Answer<oracle::PutBucketReplicationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.replication_configuration))
    }

    fn put_bucket_request_payment<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::PutBucketRequestPaymentInput>,
    ) -> Answer<oracle::PutBucketRequestPaymentOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.request_payment_configuration))
    }

    fn put_bucket_encryption<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::PutBucketEncryptionInput>,
    ) -> Answer<oracle::PutBucketEncryptionOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.server_side_encryption_configuration))
    }

    fn restore_object<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::RestoreObjectInput>,
    ) -> Answer<oracle::RestoreObjectOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.restore_request))
    }
}

/// The document the legacy stack's service hands its handler, or the `<Code>` it refused with.
pub(crate) fn legacy(document: Document, body: &[u8]) -> Handed {
    let handed = Arc::new(Mutex::new(None));
    let service = S3ServiceBuilder::new(Recording {
        handed: Arc::clone(&handed),
    })
    .build();
    let request = head(document, body)
        .body(LegacyBody::from(Bytes::copy_from_slice(body)))
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call(request)).map_err(|error| format!("legacy service: {error:?}"))?;
    let (_, mut answer) = response.into_parts();
    let answer = block_on(answer.store_all_limited(1 << 20)).map_err(|error| format!("legacy answer: {error}"))?;
    let recorded = handed.lock().map_err(|_| "the recording slot is poisoned".to_owned())?.take();
    recorded.ok_or_else(|| {
        let text = String::from_utf8_lossy(&answer).into_owned();
        text.split_once("<Code>")
            .and_then(|(_, rest)| rest.split_once("</Code>"))
            .map_or(text.clone(), |(code, _)| code.to_owned())
    })
}

// ── an empty required enumeration element (rustfs/gateway#1078, row 3) ────────────────────────

const REPLICATION_HEAD: &str = "<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><ID>r</ID><Priority>1</Priority><Filter><Prefix></Prefix></Filter>";
const DESTINATION: &str = "<Destination><Bucket>arn:aws:s3:::dst</Bucket>";

/// Every required enumeration a request document carries, emptied, as `(document, position, body)`.
fn empty_required_enumerations() -> Vec<(Document, &'static str, String)> {
    let replication = |rule: &str, destination: &str| {
        format!("{REPLICATION_HEAD}{rule}{DESTINATION}{destination}</Destination></Rule></ReplicationConfiguration>")
    };
    let enabled = "<Status>Enabled</Status>";
    vec![
        (
            Document::Lifecycle,
            "LifecycleRule.Status",
            "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>logs/</Prefix></Filter><Status></Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>".to_owned(),
        ),
        (Document::Replication, "ReplicationRule.Status", replication("<Status/>", "")),
        (
            Document::Replication,
            "DeleteReplication.Status",
            replication(&format!("{enabled}<DeleteReplication><Status></Status></DeleteReplication>"), ""),
        ),
        (
            Document::Replication,
            "ExistingObjectReplication.Status",
            replication(&format!("{enabled}<ExistingObjectReplication><Status/></ExistingObjectReplication>"), ""),
        ),
        (
            Document::Replication,
            "ReplicaModifications.Status",
            replication(
                &format!("{enabled}<SourceSelectionCriteria><ReplicaModifications><Status></Status></ReplicaModifications></SourceSelectionCriteria>"),
                "",
            ),
        ),
        (
            Document::Replication,
            "SseKmsEncryptedObjects.Status",
            replication(
                &format!("{enabled}<SourceSelectionCriteria><SseKmsEncryptedObjects><Status/></SseKmsEncryptedObjects></SourceSelectionCriteria>"),
                "",
            ),
        ),
        (Document::Replication, "Metrics.Status", replication(enabled, "<Metrics><Status></Status></Metrics>")),
        (
            Document::Replication,
            "ReplicationTime.Status",
            replication(enabled, "<ReplicationTime><Status/><Time><Minutes>15</Minutes></Time></ReplicationTime>"),
        ),
        (
            Document::RequestPayment,
            "RequestPaymentConfiguration.Payer",
            "<RequestPaymentConfiguration><Payer></Payer></RequestPaymentConfiguration>".to_owned(),
        ),
        (
            Document::Encryption,
            "ServerSideEncryptionByDefault.SSEAlgorithm",
            "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm/></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".to_owned(),
        ),
        (
            Document::Restore,
            "GlacierJobParameters.Tier",
            "<RestoreRequest><Days>1</Days><GlacierJobParameters><Tier></Tier></GlacierJobParameters></RestoreRequest>".to_owned(),
        ),
        (
            Document::Restore,
            "SelectParameters.ExpressionType",
            "<RestoreRequest><Type>SELECT</Type><SelectParameters><InputSerialization><CSV/></InputSerialization><ExpressionType/><Expression>SELECT * FROM S3Object</Expression><OutputSerialization><CSV/></OutputSerialization></SelectParameters></RestoreRequest>".to_owned(),
        ),
        (
            Document::Restore,
            "Encryption.EncryptionType",
            "<RestoreRequest><Type>SELECT</Type><OutputLocation><S3><BucketName>out</BucketName><Prefix>p/</Prefix><Encryption><EncryptionType></EncryptionType></Encryption></S3></OutputLocation></RestoreRequest>".to_owned(),
        ),
    ]
}

/// Positive — every required enumeration element sent empty reaches the RustFS body as the same
/// empty value on both stacks. The legacy stack decodes it into the value RustFS then judges; the
/// gateway used to answer `500` before any body ran.
#[test]
fn an_empty_required_enumeration_is_handed_over_alike() {
    for (document, position, body) in empty_required_enumerations() {
        let legacy = legacy(document, body.as_bytes());
        let handed = legacy.clone().unwrap_or_else(|code| panic!("{position}: the legacy stack refused with {code}"));
        assert!(handed.contains("(\"\")"), "{position}: the legacy stack handed no empty value: {handed}");
        assert_eq!(gateway(document, body.as_bytes()), legacy, "{position}");
    }
}

/// Negative — the same members *absent* are refused by both stacks before any body runs, with the
/// same code: the empty value is a value, and no value is not.
#[test]
fn n_an_absent_required_enumeration_is_refused_alike() {
    for (document, position, body) in empty_required_enumerations() {
        let emptied = position.rsplit('.').next().expect("a member");
        let absent = body
            .replace(&format!("<{emptied}></{emptied}>"), "")
            .replace(&format!("<{emptied}/>"), "");
        assert_ne!(absent, body, "{position}: the fixture carried no empty {emptied}");
        let legacy = legacy(document, absent.as_bytes());
        assert!(legacy.is_err(), "{position}: the legacy stack handed over {legacy:?}");
        assert_eq!(gateway(document, absent.as_bytes()), legacy, "{position}");
    }
}
