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

//! The one table of the seam diffs: every covered operation, how the RustFS adapter converts its
//! gateway request into the pinned legacy input and a legacy answer back, and its census modules.
//!
//! Responsible for: [`SEAM_OPERATIONS`]; the conversion each operation's gateway handler runs —
//! the generated seam for most, the hand-written seam for `PutObject` and `GetBucketLocation`,
//! the authorized copy source supplied to `CopyObject` and `UploadPartCopy`, the raw query and
//! header lines handed to the three operations with a member only the legacy decoder reads, and
//! the authorized key list patched into `DeleteObjects` — each exactly as the RustFS adapter does it; the legacy
//! recorder's handler for each operation; the census lookups by operation name; and, per legacy
//! output, [`LegacyOutput`]: its census and the answer conversion alone.
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
use rustfs_gateway_types::persistence as dto_bridge;

use super::stacks::{LegacyAnswer, LegacyRecorder, SeamRecorder, record, take};
use super::trailers::{attach, legacy_view};
use crate::oracle::{Answered, recorded};
use crate::s3s;
use s3s::dto as legacy;
use seam::generated::{census, ops};
use seam::leaf::RequestWire;
use seam::request_context::GatewayRequestContext;
use seam::trailers::{LegacyTrailers, legacy_checksum_algorithm};

/// What one gateway handler hands the RustFS app layer: the converted input, or the member the
/// conversion refused, the live body when the input carries one, and the trailer handle the RustFS
/// profile's adapter attaches where the legacy stack attaches one.
pub(crate) type Converted = (
    Result<Box<dyn Any + Send>, ConversionError>,
    Option<legacy::StreamingBlob>,
    Option<LegacyTrailers>,
);

/// The configuration bytes one side would store for a configuration write: the gateway's
/// persistence writer on its own input, or the legacy serializer RustFS stores with on the legacy
/// input. `None` for any other operation, or a write carrying no document.
pub(crate) type Stored = Option<Result<Vec<u8>, String>>;

/// A gateway operation the seam diff covers.
pub(crate) trait SeamConverted: OperationCodec + Sized {
    /// Converts the gateway request as the RustFS adapter does.
    fn convert(request: Req<Self>) -> Converted;

    /// The bytes the gateway persistence writer produces for this input's configuration document.
    fn stored(_input: &Self::Input) -> Stored {
        None
    }

    /// A queued [`LegacyAnswer`] of this operation, converted through the seam as the RustFS adapter
    /// converts an answer: the output and the headers the body set, with the gateway writing the
    /// headers after the output (`answer_from_legacy`).
    fn answer(queued: Box<dyn Any + Send>) -> Result<(Self::Output, http::HeaderMap), ConversionError>;
}

/// A covered operation's legacy output — what a RustFS app body returns — with its census and the
/// answer conversion the RustFS adapter runs on it.
pub(crate) trait LegacyOutput: Send + Sized + 'static {
    /// The operation it answers.
    const OPERATION: &'static str;

    /// The member paths this value holds something at.
    fn present(&self) -> Vec<String>;

    /// Converts this output and the headers the body set beside it through the seam, as the RustFS
    /// adapter converts an answer, and reports the member the conversion refused, if it refused.
    fn convert(self, headers: http::HeaderMap) -> Result<(), ConversionError>;
}

/// The queued answer as the legacy answer of output `T`.
fn queued<T: 'static>(queued: Box<dyn Any + Send>) -> Result<LegacyAnswer<T>, ConversionError> {
    queued
        .downcast::<LegacyAnswer<T>>()
        .map(|answer| *answer)
        .map_err(|_| refused("answer", "the queued answer is another operation's"))
}

macro_rules! answer {
    (put_object, $method:ident, $output:ident, $queued:ident) => {{
        let LegacyAnswer { output, headers } = queued::<legacy::$output>($queued)?;
        seam::put_object::answer_from_legacy(output, headers)
    }};
    (location, $method:ident, $output:ident, $queued:ident) => {{
        let LegacyAnswer { output, headers } = queued::<legacy::$output>($queued)?;
        Ok(seam::get_bucket_location::answer_from_legacy(output, headers))
    }};
    ($kind:ident, $method:ident, $output:ident, $queued:ident) => {{
        let LegacyAnswer { output, headers } = queued::<legacy::$output>($queued)?;
        ops::$method::answer_from_legacy(output, headers)
    }};
}

/// A writer's result as stored bytes.
trait IntoStored {
    fn into_stored(self) -> Result<Vec<u8>, String>;
}

impl IntoStored for Vec<u8> {
    fn into_stored(self) -> Result<Vec<u8>, String> {
        Ok(self)
    }
}

impl<E: std::fmt::Display> IntoStored for Result<Vec<u8>, E> {
    fn into_stored(self) -> Result<Vec<u8>, String> {
        self.map_err(|error| error.to_string())
    }
}

/// The bytes RustFS stores for a legacy configuration value: its own `serialize`
/// (rustfs/rustfs `1e7065101d` `crates/ecstore/src/bucket/utils.rs:100-107`), a legacy XML
/// serializer over an empty buffer, no declaration.
fn legacy_stored<T: s3s::xml::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::with_capacity(256);
    {
        let mut serializer = s3s::xml::Serializer::new(&mut buffer);
        value.serialize(&mut serializer).map_err(|error| error.to_string())?;
    }
    Ok(buffer)
}

/// Each configuration write's gateway writer, by the member holding the document on each side:
/// `gateway`/`legacy` are `required` or `optional`.
macro_rules! stored {
    (PutBucketLifecycleConfiguration) => { stored!(@optional lifecycle_configuration, dto_bridge::serialize_lifecycle_dto); };
    (PutBucketReplication) => { stored!(@required replication_configuration, dto_bridge::serialize_replication_dto); };
    (PutBucketNotificationConfiguration) => { stored!(@required notification_configuration, dto_bridge::serialize_notification_dto); };
    (PutBucketCors) => { stored!(@required cors_configuration, dto_bridge::serialize_cors_dto); };
    (PutBucketEncryption) => { stored!(@required server_side_encryption_configuration, dto_bridge::serialize_bucket_encryption_dto); };
    (PutBucketTagging) => { stored!(@required tagging, dto_bridge::serialize_tagging_dto); };
    (PutBucketVersioning) => { stored!(@required versioning_configuration, dto_bridge::serialize_versioning_dto); };
    (PutObjectLockConfiguration) => { stored!(@required object_lock_configuration, dto_bridge::serialize_object_lock_dto); };
    (PutPublicAccessBlock) => { stored!(@required public_access_block_configuration, dto_bridge::serialize_public_access_block_dto); };
    (PutBucketWebsite) => { stored!(@required website_configuration, dto_bridge::serialize_website_dto); };
    (PutBucketLogging) => { stored!(@required bucket_logging_status, dto_bridge::serialize_bucket_logging_dto); };
    (PutBucketAccelerateConfiguration) => { stored!(@required accelerate_configuration, dto_bridge::serialize_accelerate_dto); };
    (PutBucketRequestPayment) => { stored!(@required request_payment_configuration, dto_bridge::serialize_request_payment_dto); };
    (@required $member:ident, $writer:path) => {
        fn stored(input: &Self::Input) -> Stored {
            Some($writer(&input.$member).into_stored())
        }
    };
    (@optional $member:ident, $writer:path) => {
        fn stored(input: &Self::Input) -> Stored {
            input.$member.as_ref().map(|value| $writer(value).into_stored())
        }
    };
    ($other:ident) => {};
}

/// The legacy side of [`stored!`]: the same document, serialized as RustFS stores it.
macro_rules! legacy_stored {
    (PutBucketLifecycleConfiguration, $input:ident) => {
        $input.lifecycle_configuration.as_ref().map(legacy_stored)
    };
    (PutBucketReplication, $input:ident) => {
        Some(legacy_stored(&$input.replication_configuration))
    };
    (PutBucketNotificationConfiguration, $input:ident) => {
        Some(legacy_stored(&$input.notification_configuration))
    };
    (PutBucketCors, $input:ident) => {
        Some(legacy_stored(&$input.cors_configuration))
    };
    (PutBucketEncryption, $input:ident) => {
        Some(legacy_stored(&$input.server_side_encryption_configuration))
    };
    (PutBucketTagging, $input:ident) => {
        Some(legacy_stored(&$input.tagging))
    };
    (PutBucketVersioning, $input:ident) => {
        Some(legacy_stored(&$input.versioning_configuration))
    };
    (PutObjectLockConfiguration, $input:ident) => {
        $input.object_lock_configuration.as_ref().map(legacy_stored)
    };
    (PutPublicAccessBlock, $input:ident) => {
        Some(legacy_stored(&$input.public_access_block_configuration))
    };
    (PutBucketWebsite, $input:ident) => {
        Some(legacy_stored(&$input.website_configuration))
    };
    (PutBucketLogging, $input:ident) => {
        Some(legacy_stored(&$input.bucket_logging_status))
    };
    (PutBucketAccelerateConfiguration, $input:ident) => {
        Some(legacy_stored(&$input.accelerate_configuration))
    };
    (PutBucketRequestPayment, $input:ident) => {
        Some(legacy_stored(&$input.request_payment_configuration))
    };
    ($other:ident, $input:ident) => {
        None
    };
}

/// Every configuration write the stored-bytes comparison covers.
pub(crate) const STORED_OPERATIONS: [&str; 13] = [
    "PutBucketLifecycleConfiguration",
    "PutBucketReplication",
    "PutBucketNotificationConfiguration",
    "PutBucketCors",
    "PutBucketEncryption",
    "PutBucketTagging",
    "PutBucketVersioning",
    "PutObjectLockConfiguration",
    "PutPublicAccessBlock",
    "PutBucketWebsite",
    "PutBucketLogging",
    "PutBucketAccelerateConfiguration",
    "PutBucketRequestPayment",
];

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
        (boxed(ops::$method::input_to_s3s($request.into_input())), None, None)
    };
    (plain_wire, $method:ident, $request:ident) => {{
        let (raw_query, headers) = raw_wire(&$request);
        let wire = RequestWire {
            raw_query: &raw_query,
            headers: &headers,
        };
        (boxed(ops::$method::input_to_s3s($request.into_input(), &wire)), None, None)
    }};
    (copy, $method:ident, $request:ident) => {
        match copy_source(&$request) {
            Ok(source) => (boxed(ops::$method::input_to_s3s($request.into_input(), source)), None, None),
            Err(error) => (Err(error), None, None),
        }
    };
    (copy_wire, $method:ident, $request:ident) => {{
        let (raw_query, headers) = raw_wire(&$request);
        let wire = RequestWire {
            raw_query: &raw_query,
            headers: &headers,
        };
        match copy_source(&$request) {
            Ok(source) => (boxed(ops::$method::input_to_s3s($request.into_input(), source, &wire)), None, None),
            Err(error) => (Err(error), None, None),
        }
    }};
    (delete_objects, $method:ident, $request:ident) => {{
        let objects = delete_list(&$request);
        let converted = ops::$method::input_to_s3s($request.into_input()).and_then(|mut input| {
            input.delete.objects = objects?;
            Ok(input)
        });
        (boxed(converted), None, None)
    }};
    (put_object, $method:ident, $request:ident) => {
        upload!(seam::put_object::input_to_s3s, $request)
    };
    (upload_part, $method:ident, $request:ident) => {
        upload!(ops::$method::input_to_s3s, $request)
    };
    (location, $method:ident, $request:ident) => {
        (boxed(Ok(seam::get_bucket_location::input_to_s3s($request.into_input()))), None, None)
    };
}

/// An upload as the RustFS profile's adapter hands it over (rustfs/gateway#1148): a trailer handle
/// where the legacy stack attaches one, the body wrapped to fill it, and the checksum algorithm the
/// RustFS body reads as the legacy decoder reads it.
macro_rules! upload {
    ($convert:path, $request:ident) => {{
        let (_, headers) = raw_wire(&$request);
        let trailers = attach(&$request, &headers);
        let mut gateway_input = $request.into_input();
        if let Some(trailers) = &trailers {
            gateway_input.body = gateway_input.body.map(|body| trailers.publishing(body));
        }
        let converted = $convert(gateway_input).and_then(|mut input| {
            input.checksum_algorithm = legacy_checksum_algorithm(&headers)?;
            Ok(input)
        });
        match converted {
            Ok(mut input) => {
                let body = input.body.take();
                (boxed(Ok(input)), body, trailers)
            }
            Err(error) => (Err(error), None, None),
        }
    }};
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
    ($($kind:ident $op:ident / $method:ident($input:ident, $output:ident) => $census:ident, $answer_census:ident;)+) => {
        /// Every operation the seam decode diff covers: every operation of the seam but
        /// `SelectObjectContent`.
        pub(crate) const SEAM_OPERATIONS: &[&str] = &[$(stringify!($op)),+];

        $(impl SeamConverted for dto::$op {
            fn convert(request: Req<Self>) -> Converted {
                convert!($kind, $method, request)
            }

            stored!($op);

            fn answer(queued: Box<dyn Any + Send>) -> Result<(Self::Output, http::HeaderMap), ConversionError> {
                answer!($kind, $method, $output, queued)
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
                let stored: Stored = legacy_stored!($op, input);
                let trailers = request.trailing_headers;
                Box::pin(async move {
                    record(&self.slot, stringify!($op), Ok(Box::new(input)), body, stored, || legacy_view(trailers.as_ref())).await;
                    match take(&self.answer).map(|queued| queued.downcast::<LegacyAnswer<legacy::$output>>()) {
                        Some(Ok(answer)) => {
                            let LegacyAnswer { output, headers } = *answer;
                            let mut response = s3s::S3Response::new(output);
                            response.headers = headers;
                            Ok(response)
                        }
                        _ => recorded(),
                    }
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

        $(impl LegacyOutput for legacy::$output {
            const OPERATION: &'static str = stringify!($op);

            fn present(&self) -> Vec<String> {
                let mut present = Vec::new();
                census::$answer_census::present("", self, &mut present);
                present
            }

            fn convert(self, headers: http::HeaderMap) -> Result<(), ConversionError> {
                <dto::$op as SeamConverted>::answer(Box::new(LegacyAnswer { output: self, headers })).map(|_| ())
            }
        })+

        /// Every member path of the covered operation's legacy output.
        pub(crate) fn output_paths(operation: &str) -> Option<&'static [&'static str]> {
            match operation {
                $(stringify!($op) => Some(census::$answer_census::PATHS),)+
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
    plain AbortMultipartUpload / abort_multipart_upload(AbortMultipartUploadInput, AbortMultipartUploadOutput) => abort_multipart_upload_input, abort_multipart_upload_output;
    plain CompleteMultipartUpload / complete_multipart_upload(CompleteMultipartUploadInput, CompleteMultipartUploadOutput) => complete_multipart_upload_input, complete_multipart_upload_output;
    copy_wire CopyObject / copy_object(CopyObjectInput, CopyObjectOutput) => copy_object_input, copy_object_output;
    plain CreateBucket / create_bucket(CreateBucketInput, CreateBucketOutput) => create_bucket_input, create_bucket_output;
    plain_wire CreateMultipartUpload / create_multipart_upload(CreateMultipartUploadInput, CreateMultipartUploadOutput) => create_multipart_upload_input, create_multipart_upload_output;
    plain_wire DeleteBucket / delete_bucket(DeleteBucketInput, DeleteBucketOutput) => delete_bucket_input, delete_bucket_output;
    plain DeleteBucketCors / delete_bucket_cors(DeleteBucketCorsInput, DeleteBucketCorsOutput) => delete_bucket_cors_input, delete_bucket_cors_output;
    plain DeleteBucketEncryption / delete_bucket_encryption(DeleteBucketEncryptionInput, DeleteBucketEncryptionOutput) => delete_bucket_encryption_input, delete_bucket_encryption_output;
    plain DeleteBucketLifecycle / delete_bucket_lifecycle(DeleteBucketLifecycleInput, DeleteBucketLifecycleOutput) => delete_bucket_lifecycle_input, delete_bucket_lifecycle_output;
    plain DeleteBucketPolicy / delete_bucket_policy(DeleteBucketPolicyInput, DeleteBucketPolicyOutput) => delete_bucket_policy_input, delete_bucket_policy_output;
    plain DeleteBucketReplication / delete_bucket_replication(DeleteBucketReplicationInput, DeleteBucketReplicationOutput) => delete_bucket_replication_input, delete_bucket_replication_output;
    plain DeleteBucketTagging / delete_bucket_tagging(DeleteBucketTaggingInput, DeleteBucketTaggingOutput) => delete_bucket_tagging_input, delete_bucket_tagging_output;
    plain DeleteBucketWebsite / delete_bucket_website(DeleteBucketWebsiteInput, DeleteBucketWebsiteOutput) => delete_bucket_website_input, delete_bucket_website_output;
    plain DeleteObject / delete_object(DeleteObjectInput, DeleteObjectOutput) => delete_object_input, delete_object_output;
    plain DeleteObjectTagging / delete_object_tagging(DeleteObjectTaggingInput, DeleteObjectTaggingOutput) => delete_object_tagging_input, delete_object_tagging_output;
    delete_objects DeleteObjects / delete_objects(DeleteObjectsInput, DeleteObjectsOutput) => delete_objects_input, delete_objects_output;
    plain DeletePublicAccessBlock / delete_public_access_block(DeletePublicAccessBlockInput, DeletePublicAccessBlockOutput) => delete_public_access_block_input, delete_public_access_block_output;
    plain GetBucketAccelerateConfiguration / get_bucket_accelerate_configuration(GetBucketAccelerateConfigurationInput, GetBucketAccelerateConfigurationOutput) => get_bucket_accelerate_configuration_input, get_bucket_accelerate_configuration_output;
    plain GetBucketAcl / get_bucket_acl(GetBucketAclInput, GetBucketAclOutput) => get_bucket_acl_input, get_bucket_acl_output;
    plain GetBucketCors / get_bucket_cors(GetBucketCorsInput, GetBucketCorsOutput) => get_bucket_cors_input, get_bucket_cors_output;
    plain GetBucketEncryption / get_bucket_encryption(GetBucketEncryptionInput, GetBucketEncryptionOutput) => get_bucket_encryption_input, get_bucket_encryption_output;
    plain GetBucketLifecycleConfiguration / get_bucket_lifecycle_configuration(GetBucketLifecycleConfigurationInput, GetBucketLifecycleConfigurationOutput) => get_bucket_lifecycle_configuration_input, get_bucket_lifecycle_configuration_output;
    location GetBucketLocation / get_bucket_location(GetBucketLocationInput, GetBucketLocationOutput) => get_bucket_location_input, get_bucket_location_output;
    plain GetBucketLogging / get_bucket_logging(GetBucketLoggingInput, GetBucketLoggingOutput) => get_bucket_logging_input, get_bucket_logging_output;
    plain GetBucketNotificationConfiguration / get_bucket_notification_configuration(GetBucketNotificationConfigurationInput, GetBucketNotificationConfigurationOutput) => get_bucket_notification_configuration_input, get_bucket_notification_configuration_output;
    plain GetBucketPolicy / get_bucket_policy(GetBucketPolicyInput, GetBucketPolicyOutput) => get_bucket_policy_input, get_bucket_policy_output;
    plain GetBucketPolicyStatus / get_bucket_policy_status(GetBucketPolicyStatusInput, GetBucketPolicyStatusOutput) => get_bucket_policy_status_input, get_bucket_policy_status_output;
    plain GetBucketReplication / get_bucket_replication(GetBucketReplicationInput, GetBucketReplicationOutput) => get_bucket_replication_input, get_bucket_replication_output;
    plain GetBucketRequestPayment / get_bucket_request_payment(GetBucketRequestPaymentInput, GetBucketRequestPaymentOutput) => get_bucket_request_payment_input, get_bucket_request_payment_output;
    plain GetBucketTagging / get_bucket_tagging(GetBucketTaggingInput, GetBucketTaggingOutput) => get_bucket_tagging_input, get_bucket_tagging_output;
    plain GetBucketVersioning / get_bucket_versioning(GetBucketVersioningInput, GetBucketVersioningOutput) => get_bucket_versioning_input, get_bucket_versioning_output;
    plain GetBucketWebsite / get_bucket_website(GetBucketWebsiteInput, GetBucketWebsiteOutput) => get_bucket_website_input, get_bucket_website_output;
    plain GetObject / get_object(GetObjectInput, GetObjectOutput) => get_object_input, get_object_output;
    plain GetObjectAcl / get_object_acl(GetObjectAclInput, GetObjectAclOutput) => get_object_acl_input, get_object_acl_output;
    plain GetObjectAttributes / get_object_attributes(GetObjectAttributesInput, GetObjectAttributesOutput) => get_object_attributes_input, get_object_attributes_output;
    plain GetObjectLegalHold / get_object_legal_hold(GetObjectLegalHoldInput, GetObjectLegalHoldOutput) => get_object_legal_hold_input, get_object_legal_hold_output;
    plain GetObjectLockConfiguration / get_object_lock_configuration(GetObjectLockConfigurationInput, GetObjectLockConfigurationOutput) => get_object_lock_configuration_input, get_object_lock_configuration_output;
    plain GetObjectRetention / get_object_retention(GetObjectRetentionInput, GetObjectRetentionOutput) => get_object_retention_input, get_object_retention_output;
    plain GetObjectTagging / get_object_tagging(GetObjectTaggingInput, GetObjectTaggingOutput) => get_object_tagging_input, get_object_tagging_output;
    plain GetObjectTorrent / get_object_torrent(GetObjectTorrentInput, GetObjectTorrentOutput) => get_object_torrent_input, get_object_torrent_output;
    plain GetPublicAccessBlock / get_public_access_block(GetPublicAccessBlockInput, GetPublicAccessBlockOutput) => get_public_access_block_input, get_public_access_block_output;
    plain HeadBucket / head_bucket(HeadBucketInput, HeadBucketOutput) => head_bucket_input, head_bucket_output;
    plain HeadObject / head_object(HeadObjectInput, HeadObjectOutput) => head_object_input, head_object_output;
    plain ListBuckets / list_buckets(ListBucketsInput, ListBucketsOutput) => list_buckets_input, list_buckets_output;
    plain ListMultipartUploads / list_multipart_uploads(ListMultipartUploadsInput, ListMultipartUploadsOutput) => list_multipart_uploads_input, list_multipart_uploads_output;
    plain ListObjectVersions / list_object_versions(ListObjectVersionsInput, ListObjectVersionsOutput) => list_object_versions_input, list_object_versions_output;
    plain ListObjects / list_objects(ListObjectsInput, ListObjectsOutput) => list_objects_input, list_objects_output;
    plain ListObjectsV2 / list_objects_v2(ListObjectsV2Input, ListObjectsV2Output) => list_objects_v2input, list_objects_v2output;
    plain ListParts / list_parts(ListPartsInput, ListPartsOutput) => list_parts_input, list_parts_output;
    plain PutBucketAccelerateConfiguration / put_bucket_accelerate_configuration(PutBucketAccelerateConfigurationInput, PutBucketAccelerateConfigurationOutput) => put_bucket_accelerate_configuration_input, put_bucket_accelerate_configuration_output;
    plain PutBucketAcl / put_bucket_acl(PutBucketAclInput, PutBucketAclOutput) => put_bucket_acl_input, put_bucket_acl_output;
    plain PutBucketCors / put_bucket_cors(PutBucketCorsInput, PutBucketCorsOutput) => put_bucket_cors_input, put_bucket_cors_output;
    plain PutBucketEncryption / put_bucket_encryption(PutBucketEncryptionInput, PutBucketEncryptionOutput) => put_bucket_encryption_input, put_bucket_encryption_output;
    plain PutBucketLifecycleConfiguration / put_bucket_lifecycle_configuration(PutBucketLifecycleConfigurationInput, PutBucketLifecycleConfigurationOutput) => put_bucket_lifecycle_configuration_input, put_bucket_lifecycle_configuration_output;
    plain PutBucketLogging / put_bucket_logging(PutBucketLoggingInput, PutBucketLoggingOutput) => put_bucket_logging_input, put_bucket_logging_output;
    plain PutBucketNotificationConfiguration / put_bucket_notification_configuration(PutBucketNotificationConfigurationInput, PutBucketNotificationConfigurationOutput) => put_bucket_notification_configuration_input, put_bucket_notification_configuration_output;
    plain PutBucketPolicy / put_bucket_policy(PutBucketPolicyInput, PutBucketPolicyOutput) => put_bucket_policy_input, put_bucket_policy_output;
    plain PutBucketReplication / put_bucket_replication(PutBucketReplicationInput, PutBucketReplicationOutput) => put_bucket_replication_input, put_bucket_replication_output;
    plain PutBucketRequestPayment / put_bucket_request_payment(PutBucketRequestPaymentInput, PutBucketRequestPaymentOutput) => put_bucket_request_payment_input, put_bucket_request_payment_output;
    plain PutBucketTagging / put_bucket_tagging(PutBucketTaggingInput, PutBucketTaggingOutput) => put_bucket_tagging_input, put_bucket_tagging_output;
    plain PutBucketVersioning / put_bucket_versioning(PutBucketVersioningInput, PutBucketVersioningOutput) => put_bucket_versioning_input, put_bucket_versioning_output;
    plain PutBucketWebsite / put_bucket_website(PutBucketWebsiteInput, PutBucketWebsiteOutput) => put_bucket_website_input, put_bucket_website_output;
    put_object PutObject / put_object(PutObjectInput, PutObjectOutput) => put_object_input, put_object_output;
    plain PutObjectAcl / put_object_acl(PutObjectAclInput, PutObjectAclOutput) => put_object_acl_input, put_object_acl_output;
    plain PutObjectLegalHold / put_object_legal_hold(PutObjectLegalHoldInput, PutObjectLegalHoldOutput) => put_object_legal_hold_input, put_object_legal_hold_output;
    plain PutObjectLockConfiguration / put_object_lock_configuration(PutObjectLockConfigurationInput, PutObjectLockConfigurationOutput) => put_object_lock_configuration_input, put_object_lock_configuration_output;
    plain PutObjectRetention / put_object_retention(PutObjectRetentionInput, PutObjectRetentionOutput) => put_object_retention_input, put_object_retention_output;
    plain PutObjectTagging / put_object_tagging(PutObjectTaggingInput, PutObjectTaggingOutput) => put_object_tagging_input, put_object_tagging_output;
    plain PutPublicAccessBlock / put_public_access_block(PutPublicAccessBlockInput, PutPublicAccessBlockOutput) => put_public_access_block_input, put_public_access_block_output;
    plain RestoreObject / restore_object(RestoreObjectInput, RestoreObjectOutput) => restore_object_input, restore_object_output;
    upload_part UploadPart / upload_part(UploadPartInput, UploadPartOutput) => upload_part_input, upload_part_output;
    copy UploadPartCopy / upload_part_copy(UploadPartCopyInput, UploadPartCopyOutput) => upload_part_copy_input, upload_part_copy_output;
}
