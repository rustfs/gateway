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
//! Responsible for: the harness — one request document of any of the twenty-four operations that
//! read one, through the gateway's generated decoder under either [`DocumentReading`] (the RustFS
//! one with MinIO's body literal read, as the RustFS profile assembles it) and the seam's input
//! conversion, and through the legacy service, whose handlers record the document
//! they are handed — and, in the submodules, the proofs built on it: the empty required
//! enumeration (`empty_enumeration`), and the RustFS profile's reading against the legacy stack
//! over a sample of every document and every perturbation of it (`parity`, `perturb`, `samples`).
//! NOT responsible for: what RustFS does with a document (its own handlers, behind the seam), or
//! persistence (the `dto_bridge` tests).
//! Upstream: the harness, the generated seam. Downstream: nothing.
//!
//! Two documents are not converted through the seam, so only their verdict is compared:
//! `SelectObjectContent`, whose seam stays hand-written (rustfs/backlog#1730), and
//! `UpdateObjectEncryption`, which RustFS does not implement.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::BODY_LITERAL_OPERATIONS;
use rustfs_gateway_core::DocumentReading;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

use super::put_object::md5_base64;
use super::s3s::{Body as LegacyBody, S3, S3Request, S3Response, S3Result, service::S3ServiceBuilder};
use super::seam::generated::ops;
use super::{HOST, block_on, oracle};

mod divergences;
mod empty_enumeration;
mod parity;
mod perturb;
mod samples;

/// The operations that read an XML request document (`PutBucketPolicy` reads JSON).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Op {
    CompleteMultipartUpload,
    CreateBucket,
    DeleteObjects,
    PutBucketAccelerateConfiguration,
    PutBucketAcl,
    PutBucketCors,
    PutBucketEncryption,
    PutBucketLifecycleConfiguration,
    PutBucketLogging,
    PutBucketNotificationConfiguration,
    PutBucketReplication,
    PutBucketRequestPayment,
    PutBucketTagging,
    PutBucketVersioning,
    PutBucketWebsite,
    PutObjectAcl,
    PutObjectLegalHold,
    PutObjectLockConfiguration,
    PutObjectRetention,
    PutObjectTagging,
    PutPublicAccessBlock,
    RestoreObject,
    SelectObjectContent,
    UpdateObjectEncryption,
}

impl Op {
    /// Every operation, in name order.
    pub(crate) const ALL: [Self; 24] = [
        Self::CompleteMultipartUpload,
        Self::CreateBucket,
        Self::DeleteObjects,
        Self::PutBucketAccelerateConfiguration,
        Self::PutBucketAcl,
        Self::PutBucketCors,
        Self::PutBucketEncryption,
        Self::PutBucketLifecycleConfiguration,
        Self::PutBucketLogging,
        Self::PutBucketNotificationConfiguration,
        Self::PutBucketReplication,
        Self::PutBucketRequestPayment,
        Self::PutBucketTagging,
        Self::PutBucketVersioning,
        Self::PutBucketWebsite,
        Self::PutObjectAcl,
        Self::PutObjectLegalHold,
        Self::PutObjectLockConfiguration,
        Self::PutObjectRetention,
        Self::PutObjectTagging,
        Self::PutPublicAccessBlock,
        Self::RestoreObject,
        Self::SelectObjectContent,
        Self::UpdateObjectEncryption,
    ];

    fn request(self) -> (&'static str, &'static str, TargetKind) {
        use TargetKind::{Bucket, Object};
        match self {
            Self::CompleteMultipartUpload => ("POST", "/photos/key?uploadId=u", Object),
            Self::CreateBucket => ("PUT", "/photos", Bucket),
            Self::DeleteObjects => ("POST", "/photos?delete", Bucket),
            Self::PutBucketAccelerateConfiguration => ("PUT", "/photos?accelerate", Bucket),
            Self::PutBucketAcl => ("PUT", "/photos?acl", Bucket),
            Self::PutBucketCors => ("PUT", "/photos?cors", Bucket),
            Self::PutBucketEncryption => ("PUT", "/photos?encryption", Bucket),
            Self::PutBucketLifecycleConfiguration => ("PUT", "/photos?lifecycle", Bucket),
            Self::PutBucketLogging => ("PUT", "/photos?logging", Bucket),
            Self::PutBucketNotificationConfiguration => ("PUT", "/photos?notification", Bucket),
            Self::PutBucketReplication => ("PUT", "/photos?replication", Bucket),
            Self::PutBucketRequestPayment => ("PUT", "/photos?requestPayment", Bucket),
            Self::PutBucketTagging => ("PUT", "/photos?tagging", Bucket),
            Self::PutBucketVersioning => ("PUT", "/photos?versioning", Bucket),
            Self::PutBucketWebsite => ("PUT", "/photos?website", Bucket),
            Self::PutObjectAcl => ("PUT", "/photos/key?acl", Object),
            Self::PutObjectLegalHold => ("PUT", "/photos/key?legal-hold", Object),
            Self::PutObjectLockConfiguration => ("PUT", "/photos?object-lock", Bucket),
            Self::PutObjectRetention => ("PUT", "/photos/key?retention", Object),
            Self::PutObjectTagging => ("PUT", "/photos/key?tagging", Object),
            Self::PutPublicAccessBlock => ("PUT", "/photos?publicAccessBlock", Bucket),
            Self::RestoreObject => ("POST", "/photos/key?restore", Object),
            Self::SelectObjectContent => ("POST", "/photos/key?select&select-type=2", Object),
            Self::UpdateObjectEncryption => ("PUT", "/photos/key?encryption", Object),
        }
    }
}

/// What the RustFS body was handed — the document, in the legacy stack's `Debug` spelling, or
/// [`ACCEPTED`] for the two documents only a verdict is compared for — or the `<Code>` a stack
/// refused the request with before any body ran.
pub(crate) type Handed = Result<String, String>;

/// The verdict of a document no conversion compares member by member.
pub(crate) const ACCEPTED: &str = "<accepted>";

fn head(op: Op, body: &[u8]) -> http::request::Builder {
    let (method, target, _) = op.request();
    http::Request::builder()
        .method(method)
        .uri(format!("http://{HOST}{target}"))
        .header("host", HOST)
        .header("content-md5", md5_base64(body))
        .header("content-length", body.len().to_string())
}

fn decode<O: OperationCodec>(op: Op, reading: DocumentReading, body: &[u8]) -> Result<O::Input, String> {
    let request = head(op, body).body(()).map_err(|error| format!("fixture head: {error}"))?;
    let wire = WireRequest::accept(request, &Limits::default()).map_err(|error| format!("wire refusal: {error:?}"))?;
    let view = MetaView::of(&wire, op.request().2)
        .map_err(|error| error.code().as_str().to_owned())?
        .with_document_reading(reading);
    // The RustFS profile reads MinIO's bare body literal as well (`accept_minio_body_literals`), on
    // exactly the operations it names; an `Op` is spelled as its operation.
    let literal = reading == DocumentReading::RustFs && BODY_LITERAL_OPERATIONS.contains(&format!("{op:?}").as_str());
    let view = if literal { view.with_body_literals() } else { view };
    O::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(body))).map_err(|error| error.code().as_str().to_owned())
}

/// Decodes `$op` and converts it through its generated seam, handing over `$member`.
macro_rules! through_seam {
    ($op:expr, $reading:expr, $body:expr, $codec:ty, $seam:ident, $member:ident) => {{
        let input = decode::<$codec>($op, $reading, $body)?;
        let converted = ops::$seam::input_to_s3s(input).map_err(|error| format!("seam: {error}"))?;
        Ok(format!("{:?}", converted.$member))
    }};
}

/// The document the gateway hands the RustFS body, read the way `reading` says.
pub(crate) fn gateway(op: Op, reading: DocumentReading, body: &[u8]) -> Handed {
    use Op as O;
    match op {
        O::CompleteMultipartUpload => through_seam!(
            op,
            reading,
            body,
            dto::CompleteMultipartUpload,
            complete_multipart_upload,
            multipart_upload
        ),
        O::CreateBucket => through_seam!(op, reading, body, dto::CreateBucket, create_bucket, create_bucket_configuration),
        O::DeleteObjects => through_seam!(op, reading, body, dto::DeleteObjects, delete_objects, delete),
        O::PutBucketAccelerateConfiguration => through_seam!(
            op,
            reading,
            body,
            dto::PutBucketAccelerateConfiguration,
            put_bucket_accelerate_configuration,
            accelerate_configuration
        ),
        O::PutBucketAcl => through_seam!(op, reading, body, dto::PutBucketAcl, put_bucket_acl, access_control_policy),
        O::PutBucketCors => through_seam!(op, reading, body, dto::PutBucketCors, put_bucket_cors, cors_configuration),
        O::PutBucketEncryption => through_seam!(
            op,
            reading,
            body,
            dto::PutBucketEncryption,
            put_bucket_encryption,
            server_side_encryption_configuration
        ),
        O::PutBucketLifecycleConfiguration => through_seam!(
            op,
            reading,
            body,
            dto::PutBucketLifecycleConfiguration,
            put_bucket_lifecycle_configuration,
            lifecycle_configuration
        ),
        O::PutBucketLogging => through_seam!(op, reading, body, dto::PutBucketLogging, put_bucket_logging, bucket_logging_status),
        O::PutBucketNotificationConfiguration => through_seam!(
            op,
            reading,
            body,
            dto::PutBucketNotificationConfiguration,
            put_bucket_notification_configuration,
            notification_configuration
        ),
        O::PutBucketReplication => through_seam!(
            op,
            reading,
            body,
            dto::PutBucketReplication,
            put_bucket_replication,
            replication_configuration
        ),
        O::PutBucketRequestPayment => through_seam!(
            op,
            reading,
            body,
            dto::PutBucketRequestPayment,
            put_bucket_request_payment,
            request_payment_configuration
        ),
        O::PutBucketTagging => through_seam!(op, reading, body, dto::PutBucketTagging, put_bucket_tagging, tagging),
        O::PutBucketVersioning => through_seam!(
            op,
            reading,
            body,
            dto::PutBucketVersioning,
            put_bucket_versioning,
            versioning_configuration
        ),
        O::PutBucketWebsite => through_seam!(op, reading, body, dto::PutBucketWebsite, put_bucket_website, website_configuration),
        O::PutObjectAcl => through_seam!(op, reading, body, dto::PutObjectAcl, put_object_acl, access_control_policy),
        O::PutObjectLegalHold => through_seam!(op, reading, body, dto::PutObjectLegalHold, put_object_legal_hold, legal_hold),
        O::PutObjectLockConfiguration => through_seam!(
            op,
            reading,
            body,
            dto::PutObjectLockConfiguration,
            put_object_lock_configuration,
            object_lock_configuration
        ),
        O::PutObjectRetention => through_seam!(op, reading, body, dto::PutObjectRetention, put_object_retention, retention),
        O::PutObjectTagging => through_seam!(op, reading, body, dto::PutObjectTagging, put_object_tagging, tagging),
        O::PutPublicAccessBlock => through_seam!(
            op,
            reading,
            body,
            dto::PutPublicAccessBlock,
            put_public_access_block,
            public_access_block_configuration
        ),
        O::RestoreObject => through_seam!(op, reading, body, dto::RestoreObject, restore_object, restore_request),
        O::SelectObjectContent => decode::<dto::SelectObjectContent>(op, reading, body).map(|_| ACCEPTED.to_owned()),
        O::UpdateObjectEncryption => decode::<dto::UpdateObjectEncryption>(op, reading, body).map(|_| ACCEPTED.to_owned()),
    }
}

/// A legacy-stack backend whose document handlers record the document they are handed.
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

/// One recording handler per operation. The pinned trait is declared with `#[async_trait]`; these
/// are the signatures that attribute expands a `&self` method to, as in the PutObject harness.
macro_rules! recording {
    ($($method:ident($input:ident) -> $output:ident: $handed:expr;)*) => {
        impl S3 for Recording {
            $(
                fn $method<'life0, 'future>(&'life0 self, request: S3Request<oracle::$input>) -> Answer<oracle::$output>
                where
                    'life0: 'future,
                    Self: 'future,
                {
                    let handed: fn(&oracle::$input) -> String = $handed;
                    self.record(handed(&request.input))
                }
            )*
        }
    };
}

recording! {
    complete_multipart_upload(CompleteMultipartUploadInput) -> CompleteMultipartUploadOutput: |input| format!("{:?}", input.multipart_upload);
    // The three members of an AWS model revision the gateway model does not carry are validated by
    // both stacks and read by neither RustFS nor the seam (`overrides.rs`, `NOT_IN_MODEL`): what is
    // compared is the configuration without them.
    create_bucket(CreateBucketInput) -> CreateBucketOutput: |input| {
        let configuration = input.create_bucket_configuration.clone().map(|mut configuration| {
            configuration.bucket = None;
            configuration.location = None;
            configuration.tags = None;
            configuration
        });
        format!("{configuration:?}")
    };
    delete_objects(DeleteObjectsInput) -> DeleteObjectsOutput: |input| format!("{:?}", input.delete);
    put_bucket_accelerate_configuration(PutBucketAccelerateConfigurationInput) -> PutBucketAccelerateConfigurationOutput:
        |input| format!("{:?}", input.accelerate_configuration);
    put_bucket_acl(PutBucketAclInput) -> PutBucketAclOutput: |input| format!("{:?}", input.access_control_policy);
    put_bucket_cors(PutBucketCorsInput) -> PutBucketCorsOutput: |input| format!("{:?}", input.cors_configuration);
    put_bucket_encryption(PutBucketEncryptionInput) -> PutBucketEncryptionOutput:
        |input| format!("{:?}", input.server_side_encryption_configuration);
    put_bucket_lifecycle_configuration(PutBucketLifecycleConfigurationInput) -> PutBucketLifecycleConfigurationOutput:
        |input| format!("{:?}", input.lifecycle_configuration);
    put_bucket_logging(PutBucketLoggingInput) -> PutBucketLoggingOutput: |input| format!("{:?}", input.bucket_logging_status);
    put_bucket_notification_configuration(PutBucketNotificationConfigurationInput) -> PutBucketNotificationConfigurationOutput:
        |input| format!("{:?}", input.notification_configuration);
    put_bucket_replication(PutBucketReplicationInput) -> PutBucketReplicationOutput:
        |input| format!("{:?}", input.replication_configuration);
    put_bucket_request_payment(PutBucketRequestPaymentInput) -> PutBucketRequestPaymentOutput:
        |input| format!("{:?}", input.request_payment_configuration);
    put_bucket_tagging(PutBucketTaggingInput) -> PutBucketTaggingOutput: |input| format!("{:?}", input.tagging);
    put_bucket_versioning(PutBucketVersioningInput) -> PutBucketVersioningOutput:
        |input| format!("{:?}", input.versioning_configuration);
    put_bucket_website(PutBucketWebsiteInput) -> PutBucketWebsiteOutput: |input| format!("{:?}", input.website_configuration);
    put_object_acl(PutObjectAclInput) -> PutObjectAclOutput: |input| format!("{:?}", input.access_control_policy);
    put_object_legal_hold(PutObjectLegalHoldInput) -> PutObjectLegalHoldOutput: |input| format!("{:?}", input.legal_hold);
    put_object_lock_configuration(PutObjectLockConfigurationInput) -> PutObjectLockConfigurationOutput:
        |input| format!("{:?}", input.object_lock_configuration);
    put_object_retention(PutObjectRetentionInput) -> PutObjectRetentionOutput: |input| format!("{:?}", input.retention);
    put_object_tagging(PutObjectTaggingInput) -> PutObjectTaggingOutput: |input| format!("{:?}", input.tagging);
    put_public_access_block(PutPublicAccessBlockInput) -> PutPublicAccessBlockOutput:
        |input| format!("{:?}", input.public_access_block_configuration);
    restore_object(RestoreObjectInput) -> RestoreObjectOutput: |input| format!("{:?}", input.restore_request);
    select_object_content(SelectObjectContentInput) -> SelectObjectContentOutput: |_| ACCEPTED.to_owned();
    update_object_encryption(UpdateObjectEncryptionInput) -> UpdateObjectEncryptionOutput: |_| ACCEPTED.to_owned();
}

/// The document the legacy stack's service hands its handler, or the `<Code>` it refused with.
pub(crate) fn legacy(op: Op, body: &[u8]) -> Handed {
    let handed = Arc::new(Mutex::new(None));
    let service = S3ServiceBuilder::new(Recording {
        handed: Arc::clone(&handed),
    })
    .build();
    let request = head(op, body)
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
