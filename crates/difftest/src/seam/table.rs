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

//! The one table of the seam decode diff: every covered operation, how the RustFS adapter
//! converts its gateway request into the pinned legacy input, and its census module.
//!
//! Responsible for: [`SEAM_OPERATIONS`]; the conversion each operation's gateway handler runs —
//! the generated seam for most, the hand-written seam for `PutObject` and `GetBucketLocation`,
//! the authorized copy source supplied to `CopyObject` and `UploadPartCopy`, the raw query and
//! header lines handed to the three operations with a member only the legacy decoder reads, and
//! the authorized key list patched into `DeleteObjects` — each exactly as the RustFS adapter does it; the legacy
//! recorder's handler for each operation; and the census lookups by operation name.
//! NOT responsible for: sending or comparing (`stacks.rs`, `mod.rs`).
//! Upstream: the compat seam and its census. Downstream: `stacks.rs`, `mod.rs`.
//!
//! `SelectObjectContent` is the one covered operation left out: its seam is hand-written and owned
//! by rustfs/backlog#1730, and its request document and event-stream answer are a later slice.

use std::any::Any;
use std::sync::Arc;

use rustfs_gateway::dto;
use rustfs_gateway::{CopySourceForm, CopySourceResources, Operation, Req, ServiceBuilder};
use rustfs_gateway_core::codec::OperationCodec;
use rustfs_gateway_types::compat::ConversionError;
use rustfs_gateway_types::compat::s3s_0_17_0 as seam;

use super::stacks::{LegacyRecorder, SeamRecorder, record};
use crate::oracle::{Answered, recorded};
use crate::s3s;
use s3s::dto as legacy;
use seam::generated::{census, ops};
use seam::leaf::RequestWire;
use seam::request_context::GatewayRequestContext;

/// What one gateway handler hands the RustFS app layer: the converted input, or the member the
/// conversion refused, and the live body when the input carries one.
pub(crate) type Converted = (Result<Box<dyn Any + Send>, ConversionError>, Option<legacy::StreamingBlob>);

/// A gateway operation the seam diff covers.
pub(crate) trait SeamConverted: OperationCodec + Sized {
    /// Converts the gateway request as the RustFS adapter does.
    fn convert(request: Req<Self>) -> Converted;
}

fn boxed<T: Any + Send>(converted: Result<T, ConversionError>) -> Result<Box<dyn Any + Send>, ConversionError> {
    converted.map(|input| Box::new(input) as Box<dyn Any + Send>)
}

const fn refused(field: &'static str, reason: &'static str) -> ConversionError {
    ConversionError { field, reason }
}

/// The authorized copy source as the legacy input holds it, as the RustFS adapter builds it: the
/// gateway moves `x-amz-copy-source` into the derived resources and clears the input member. Only
/// the bucket/key form has a legacy spelling the adapter can build; any other form is refused
/// rather than rewritten into a bucket name.
fn copy_source<O>(request: &Req<O>) -> Result<legacy::CopySource, ConversionError>
where
    O: Operation<DerivedResources = CopySourceResources>,
{
    let source = request
        .resources()
        .source()
        .resolve(request.read_proof())
        .ok_or(refused("copy_source", "the copy source reached the handler unauthorized"))?;
    if source.form() != CopySourceForm::Path {
        return Err(refused("copy_source", "only a bucket/key copy source has a legacy spelling"));
    }
    Ok(legacy::CopySource::Bucket {
        bucket: source.bucket().as_str().into(),
        key: source.key().as_str().into(),
        version_id: source.version_id().map(Into::into),
    })
}

/// The authorized key list as the legacy input holds it, as the RustFS adapter patches it in: the
/// gateway moves every key and version into the derived resources and clears the input list.
fn delete_list(request: &Req<dto::DeleteObjects>) -> Result<Vec<legacy::ObjectIdentifier>, ConversionError> {
    let objects = request
        .resources()
        .resolve(request.read_proof())
        .ok_or(refused("delete", "the delete list reached the handler unauthorized"))?;
    Ok(objects
        .map(|(key, version_id)| legacy::ObjectIdentifier {
            key: key.as_str().to_owned(),
            version_id: version_id.map(str::to_owned),
            ..Default::default()
        })
        .collect())
}

/// The raw query and header lines of `request`, as the RustFS adapter reads them from the
/// handler's request context for the members only the legacy decoder reads.
fn raw_wire<O: Operation>(request: &Req<O>) -> (String, http::HeaderMap) {
    let context = request.context();
    (
        context.raw_query().to_owned(),
        GatewayRequestContext::raw_headers(context.headers().iter_raw()),
    )
}

macro_rules! convert {
    (plain, $method:ident, $request:ident) => {
        (boxed(ops::$method::input_to_s3s($request.into_input())), None)
    };
    (plain_wire, $method:ident, $request:ident) => {{
        let (raw_query, headers) = raw_wire(&$request);
        let wire = RequestWire {
            raw_query: &raw_query,
            headers: &headers,
        };
        (boxed(ops::$method::input_to_s3s($request.into_input(), &wire)), None)
    }};
    (copy, $method:ident, $request:ident) => {
        match copy_source(&$request) {
            Ok(source) => (boxed(ops::$method::input_to_s3s($request.into_input(), source)), None),
            Err(error) => (Err(error), None),
        }
    };
    (copy_wire, $method:ident, $request:ident) => {{
        let (raw_query, headers) = raw_wire(&$request);
        let wire = RequestWire {
            raw_query: &raw_query,
            headers: &headers,
        };
        match copy_source(&$request) {
            Ok(source) => (boxed(ops::$method::input_to_s3s($request.into_input(), source, &wire)), None),
            Err(error) => (Err(error), None),
        }
    }};
    (delete_objects, $method:ident, $request:ident) => {{
        let objects = delete_list(&$request);
        let converted = ops::$method::input_to_s3s($request.into_input()).and_then(|mut input| {
            input.delete.objects = objects?;
            Ok(input)
        });
        (boxed(converted), None)
    }};
    (put_object, $method:ident, $request:ident) => {
        match seam::put_object::input_to_s3s($request.into_input()) {
            Ok(mut input) => {
                let body = input.body.take();
                (boxed(Ok(input)), body)
            }
            Err(error) => (Err(error), None),
        }
    };
    (upload_part, $method:ident, $request:ident) => {
        match ops::$method::input_to_s3s($request.into_input()) {
            Ok(mut input) => {
                let body = input.body.take();
                (boxed(Ok(input)), body)
            }
            Err(error) => (Err(error), None),
        }
    };
    (location, $method:ident, $request:ident) => {
        (boxed(Ok(seam::get_bucket_location::input_to_s3s($request.into_input()))), None)
    };
}

macro_rules! take_body {
    (put_object, $input:ident) => {
        $input.body.take()
    };
    (upload_part, $input:ident) => {
        $input.body.take()
    };
    ($other:ident, $input:ident) => {
        None
    };
}

macro_rules! seam_operations {
    ($($kind:ident $op:ident / $method:ident($input:ident, $output:ident) => $census:ident;)+) => {
        /// Every operation the seam decode diff covers: every operation of the seam but
        /// `SelectObjectContent`.
        pub(crate) const SEAM_OPERATIONS: &[&str] = &[$(stringify!($op)),+];

        $(impl SeamConverted for dto::$op {
            fn convert(request: Req<Self>) -> Converted {
                convert!($kind, $method, request)
            }
        })+

        /// Registers the seam recorder for every covered operation.
        pub(crate) fn register(builder: ServiceBuilder, recorder: &Arc<SeamRecorder>) -> ServiceBuilder {
            builder $(.register::<dto::$op, _>(Arc::clone(recorder)))+
        }

        impl s3s::S3 for LegacyRecorder {
            // The pinned trait is declared with `#[async_trait]`; these are the signatures that
            // attribute expands a `&self` method to, spelled out as `oracle.rs` does.
            $(fn $method<'life0, 'future>(
                &'life0 self,
                request: s3s::S3Request<legacy::$input>,
            ) -> Answered<'future, legacy::$output>
            where
                'life0: 'future,
                Self: 'future,
            {
                #[allow(unused_mut, reason = "only an input with a body is changed")]
                let mut input = request.input;
                let body = take_body!($kind, input);
                Box::pin(async move {
                    record(&self.slot, stringify!($op), Ok(Box::new(input)), body).await;
                    recorded()
                })
            })+
        }

        /// Every member path of the covered operation's legacy input.
        pub(crate) fn input_paths(operation: &str) -> Option<&'static [&'static str]> {
            match operation {
                $(stringify!($op) => Some(census::$census::PATHS),)+
                _ => None,
            }
        }

        /// The member paths the legacy input of `operation` holds, and — when the gateway handed the
        /// same operation an input too — the member paths at which the two differ. Both recordings
        /// are taken whole (an owned downcast), so no reference into a type-erased value outlives
        /// this call.
        pub(crate) fn compare(
            operation: &str,
            gateway: Option<Box<dyn Any + Send>>,
            legacy: Box<dyn Any + Send>,
        ) -> Result<(Vec<String>, Vec<String>), String> {
            match operation {
                $(stringify!($op) => {
                    let legacy = legacy
                        .downcast::<legacy::$input>()
                        .map_err(|_| format!("a {} recording is not its legacy input", stringify!($op)))?;
                    let mut present = Vec::new();
                    census::$census::present("", &legacy, &mut present);
                    let mut differing = Vec::new();
                    if let Some(gateway) = gateway {
                        let gateway = gateway
                            .downcast::<legacy::$input>()
                            .map_err(|_| format!("a {} gateway recording is not its legacy input", stringify!($op)))?;
                        census::$census::differences("", &gateway, &legacy, &mut differing);
                    }
                    Ok((present, differing))
                })+
                other => Err(format!("{other} is not a covered operation")),
            }
        }
    };
}

seam_operations! {
    plain AbortMultipartUpload / abort_multipart_upload(AbortMultipartUploadInput, AbortMultipartUploadOutput) => abort_multipart_upload_input;
    plain CompleteMultipartUpload / complete_multipart_upload(CompleteMultipartUploadInput, CompleteMultipartUploadOutput) => complete_multipart_upload_input;
    copy_wire CopyObject / copy_object(CopyObjectInput, CopyObjectOutput) => copy_object_input;
    plain CreateBucket / create_bucket(CreateBucketInput, CreateBucketOutput) => create_bucket_input;
    plain_wire CreateMultipartUpload / create_multipart_upload(CreateMultipartUploadInput, CreateMultipartUploadOutput) => create_multipart_upload_input;
    plain_wire DeleteBucket / delete_bucket(DeleteBucketInput, DeleteBucketOutput) => delete_bucket_input;
    plain DeleteBucketCors / delete_bucket_cors(DeleteBucketCorsInput, DeleteBucketCorsOutput) => delete_bucket_cors_input;
    plain DeleteBucketEncryption / delete_bucket_encryption(DeleteBucketEncryptionInput, DeleteBucketEncryptionOutput) => delete_bucket_encryption_input;
    plain DeleteBucketLifecycle / delete_bucket_lifecycle(DeleteBucketLifecycleInput, DeleteBucketLifecycleOutput) => delete_bucket_lifecycle_input;
    plain DeleteBucketPolicy / delete_bucket_policy(DeleteBucketPolicyInput, DeleteBucketPolicyOutput) => delete_bucket_policy_input;
    plain DeleteBucketReplication / delete_bucket_replication(DeleteBucketReplicationInput, DeleteBucketReplicationOutput) => delete_bucket_replication_input;
    plain DeleteBucketTagging / delete_bucket_tagging(DeleteBucketTaggingInput, DeleteBucketTaggingOutput) => delete_bucket_tagging_input;
    plain DeleteBucketWebsite / delete_bucket_website(DeleteBucketWebsiteInput, DeleteBucketWebsiteOutput) => delete_bucket_website_input;
    plain DeleteObject / delete_object(DeleteObjectInput, DeleteObjectOutput) => delete_object_input;
    plain DeleteObjectTagging / delete_object_tagging(DeleteObjectTaggingInput, DeleteObjectTaggingOutput) => delete_object_tagging_input;
    delete_objects DeleteObjects / delete_objects(DeleteObjectsInput, DeleteObjectsOutput) => delete_objects_input;
    plain DeletePublicAccessBlock / delete_public_access_block(DeletePublicAccessBlockInput, DeletePublicAccessBlockOutput) => delete_public_access_block_input;
    plain GetBucketAccelerateConfiguration / get_bucket_accelerate_configuration(GetBucketAccelerateConfigurationInput, GetBucketAccelerateConfigurationOutput) => get_bucket_accelerate_configuration_input;
    plain GetBucketAcl / get_bucket_acl(GetBucketAclInput, GetBucketAclOutput) => get_bucket_acl_input;
    plain GetBucketCors / get_bucket_cors(GetBucketCorsInput, GetBucketCorsOutput) => get_bucket_cors_input;
    plain GetBucketEncryption / get_bucket_encryption(GetBucketEncryptionInput, GetBucketEncryptionOutput) => get_bucket_encryption_input;
    plain GetBucketLifecycleConfiguration / get_bucket_lifecycle_configuration(GetBucketLifecycleConfigurationInput, GetBucketLifecycleConfigurationOutput) => get_bucket_lifecycle_configuration_input;
    location GetBucketLocation / get_bucket_location(GetBucketLocationInput, GetBucketLocationOutput) => get_bucket_location_input;
    plain GetBucketLogging / get_bucket_logging(GetBucketLoggingInput, GetBucketLoggingOutput) => get_bucket_logging_input;
    plain GetBucketNotificationConfiguration / get_bucket_notification_configuration(GetBucketNotificationConfigurationInput, GetBucketNotificationConfigurationOutput) => get_bucket_notification_configuration_input;
    plain GetBucketPolicy / get_bucket_policy(GetBucketPolicyInput, GetBucketPolicyOutput) => get_bucket_policy_input;
    plain GetBucketPolicyStatus / get_bucket_policy_status(GetBucketPolicyStatusInput, GetBucketPolicyStatusOutput) => get_bucket_policy_status_input;
    plain GetBucketReplication / get_bucket_replication(GetBucketReplicationInput, GetBucketReplicationOutput) => get_bucket_replication_input;
    plain GetBucketRequestPayment / get_bucket_request_payment(GetBucketRequestPaymentInput, GetBucketRequestPaymentOutput) => get_bucket_request_payment_input;
    plain GetBucketTagging / get_bucket_tagging(GetBucketTaggingInput, GetBucketTaggingOutput) => get_bucket_tagging_input;
    plain GetBucketVersioning / get_bucket_versioning(GetBucketVersioningInput, GetBucketVersioningOutput) => get_bucket_versioning_input;
    plain GetBucketWebsite / get_bucket_website(GetBucketWebsiteInput, GetBucketWebsiteOutput) => get_bucket_website_input;
    plain GetObject / get_object(GetObjectInput, GetObjectOutput) => get_object_input;
    plain GetObjectAcl / get_object_acl(GetObjectAclInput, GetObjectAclOutput) => get_object_acl_input;
    plain GetObjectAttributes / get_object_attributes(GetObjectAttributesInput, GetObjectAttributesOutput) => get_object_attributes_input;
    plain GetObjectLegalHold / get_object_legal_hold(GetObjectLegalHoldInput, GetObjectLegalHoldOutput) => get_object_legal_hold_input;
    plain GetObjectLockConfiguration / get_object_lock_configuration(GetObjectLockConfigurationInput, GetObjectLockConfigurationOutput) => get_object_lock_configuration_input;
    plain GetObjectRetention / get_object_retention(GetObjectRetentionInput, GetObjectRetentionOutput) => get_object_retention_input;
    plain GetObjectTagging / get_object_tagging(GetObjectTaggingInput, GetObjectTaggingOutput) => get_object_tagging_input;
    plain GetObjectTorrent / get_object_torrent(GetObjectTorrentInput, GetObjectTorrentOutput) => get_object_torrent_input;
    plain GetPublicAccessBlock / get_public_access_block(GetPublicAccessBlockInput, GetPublicAccessBlockOutput) => get_public_access_block_input;
    plain HeadBucket / head_bucket(HeadBucketInput, HeadBucketOutput) => head_bucket_input;
    plain HeadObject / head_object(HeadObjectInput, HeadObjectOutput) => head_object_input;
    plain ListBuckets / list_buckets(ListBucketsInput, ListBucketsOutput) => list_buckets_input;
    plain ListMultipartUploads / list_multipart_uploads(ListMultipartUploadsInput, ListMultipartUploadsOutput) => list_multipart_uploads_input;
    plain ListObjectVersions / list_object_versions(ListObjectVersionsInput, ListObjectVersionsOutput) => list_object_versions_input;
    plain ListObjects / list_objects(ListObjectsInput, ListObjectsOutput) => list_objects_input;
    plain ListObjectsV2 / list_objects_v2(ListObjectsV2Input, ListObjectsV2Output) => list_objects_v2input;
    plain ListParts / list_parts(ListPartsInput, ListPartsOutput) => list_parts_input;
    plain PutBucketAccelerateConfiguration / put_bucket_accelerate_configuration(PutBucketAccelerateConfigurationInput, PutBucketAccelerateConfigurationOutput) => put_bucket_accelerate_configuration_input;
    plain PutBucketAcl / put_bucket_acl(PutBucketAclInput, PutBucketAclOutput) => put_bucket_acl_input;
    plain PutBucketCors / put_bucket_cors(PutBucketCorsInput, PutBucketCorsOutput) => put_bucket_cors_input;
    plain PutBucketEncryption / put_bucket_encryption(PutBucketEncryptionInput, PutBucketEncryptionOutput) => put_bucket_encryption_input;
    plain PutBucketLifecycleConfiguration / put_bucket_lifecycle_configuration(PutBucketLifecycleConfigurationInput, PutBucketLifecycleConfigurationOutput) => put_bucket_lifecycle_configuration_input;
    plain PutBucketLogging / put_bucket_logging(PutBucketLoggingInput, PutBucketLoggingOutput) => put_bucket_logging_input;
    plain PutBucketNotificationConfiguration / put_bucket_notification_configuration(PutBucketNotificationConfigurationInput, PutBucketNotificationConfigurationOutput) => put_bucket_notification_configuration_input;
    plain PutBucketPolicy / put_bucket_policy(PutBucketPolicyInput, PutBucketPolicyOutput) => put_bucket_policy_input;
    plain PutBucketReplication / put_bucket_replication(PutBucketReplicationInput, PutBucketReplicationOutput) => put_bucket_replication_input;
    plain PutBucketRequestPayment / put_bucket_request_payment(PutBucketRequestPaymentInput, PutBucketRequestPaymentOutput) => put_bucket_request_payment_input;
    plain PutBucketTagging / put_bucket_tagging(PutBucketTaggingInput, PutBucketTaggingOutput) => put_bucket_tagging_input;
    plain PutBucketVersioning / put_bucket_versioning(PutBucketVersioningInput, PutBucketVersioningOutput) => put_bucket_versioning_input;
    plain PutBucketWebsite / put_bucket_website(PutBucketWebsiteInput, PutBucketWebsiteOutput) => put_bucket_website_input;
    put_object PutObject / put_object(PutObjectInput, PutObjectOutput) => put_object_input;
    plain PutObjectAcl / put_object_acl(PutObjectAclInput, PutObjectAclOutput) => put_object_acl_input;
    plain PutObjectLegalHold / put_object_legal_hold(PutObjectLegalHoldInput, PutObjectLegalHoldOutput) => put_object_legal_hold_input;
    plain PutObjectLockConfiguration / put_object_lock_configuration(PutObjectLockConfigurationInput, PutObjectLockConfigurationOutput) => put_object_lock_configuration_input;
    plain PutObjectRetention / put_object_retention(PutObjectRetentionInput, PutObjectRetentionOutput) => put_object_retention_input;
    plain PutObjectTagging / put_object_tagging(PutObjectTaggingInput, PutObjectTaggingOutput) => put_object_tagging_input;
    plain PutPublicAccessBlock / put_public_access_block(PutPublicAccessBlockInput, PutPublicAccessBlockOutput) => put_public_access_block_input;
    plain RestoreObject / restore_object(RestoreObjectInput, RestoreObjectOutput) => restore_object_input;
    upload_part UploadPart / upload_part(UploadPartInput, UploadPartOutput) => upload_part_input;
    copy UploadPartCopy / upload_part_copy(UploadPartCopyInput, UploadPartCopyOutput) => upload_part_copy_input;
}
