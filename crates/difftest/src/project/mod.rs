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

//! Which operations the decode diff compares member by member, and the one table that wires each
//! to both stacks.
//!
//! Responsible for: [`DIFFED_OPERATIONS`]; registering the gateway recorder for each; generating
//! the s3s recording backend's method for each; and the two projection macros every family file
//! uses — one reads the gateway input by member name, the other destructures the pinned s3s input
//! with no `..`, so an s3s re-pin that adds a member is a compile error in the family file instead
//! of a member nobody compares.
//! NOT responsible for: any single operation's members (`object.rs`, `listing.rs`, `multipart.rs`,
//! `bucket.rs`), or comparing (`decode.rs`).
//! Upstream: the gateway DTO and the pinned s3s DTO. Downstream: `gateway.rs`, `oracle.rs`.
//!
//! An operation outside this table is still route-diffed — both stacks name the operation they
//! routed to whether or not a handler exists — and a refusal is still compared; only its input
//! members are not.

use std::sync::Arc;

use rustfs_gateway::ServiceBuilder;
use rustfs_gateway::dto;
use rustfs_gateway_core::codec::OperationCodec;
use rustfs_gateway_stream::ByteStream;

use crate::fields::Fields;
use crate::gateway::Recorder;
use crate::oracle::{Answered, RecordingS3, recorded};
use crate::s3s;
use s3s::dto as oracle;

mod bucket;
mod listing;
mod multipart;
mod object;

/// A gateway input as fields, and the live body it carried, if any.
pub(crate) struct Projection {
    pub(crate) fields: Fields,
    pub(crate) body: Option<ByteStream>,
}

/// An s3s input as fields, and the body it carried, if any.
pub(crate) struct OracleProjection {
    pub(crate) fields: Fields,
    pub(crate) body: Option<oracle::StreamingBlob>,
}

/// A gateway operation whose input the diff reads member by member.
pub(crate) trait Projected: OperationCodec + Sized {
    /// The request's input as fields keyed by the s3s member path each corresponds to.
    fn gateway(request: rustfs_gateway::Req<Self>) -> Projection;
}

/// Reads a gateway request's input by member name into [`Projection`], and declares the members
/// read.
///
/// `put` members are required, `opt` members optional; `custom` members are read by the closing
/// block, which returns the body stream (or `None`). An optional `before` block runs first with the
/// whole request, for what only the request carries (a copy source is parsed into the derived
/// resources, not the input). The member list is also exported, so the census test can hold it to
/// the generated DTO field count.
macro_rules! gateway_projection {
    (
        $(#[$meta:meta])*
        fn $name:ident($request:ident: $op:ty => $input:ident) as $members:ident {
            put: [$($put:ident),* $(,)?],
            opt: [$($opt:ident),* $(,)?],
            custom: [$($custom:ident),* $(,)?] $(,)?
        }
        $(before |$before_fields:ident| $before:block)?
        |$fields:ident| $custom_body:block
    ) => {
        /// Every gateway member the projection below reads.
        #[cfg(test)]
        pub(crate) const $members: &[&str] = &[$(stringify!($put),)* $(stringify!($opt),)* $(stringify!($custom),)*];

        $(#[$meta])*
        pub(crate) fn $name($request: rustfs_gateway::Req<$op>) -> $crate::project::Projection {
            #[allow(unused_mut, reason = "a projection without custom members writes nothing more")]
            let mut $fields = $crate::fields::Fields::default();
            $({
                let $before_fields = &mut $fields;
                $before
            })?
            let $input = $request.into_input();
            $( $fields.put(stringify!($put), &$input.$put); )*
            $( $fields.opt(stringify!($opt), $input.$opt.as_ref()); )*
            let body: Option<rustfs_gateway_stream::ByteStream> = $custom_body;
            $crate::project::Projection { fields: $fields, body }
        }
    };
}

/// Destructures a pinned s3s input with no `..` into [`OracleProjection`].
///
/// Same shape as `gateway_projection!`; the closing block reads the `custom` members, which are
/// bound by name, and returns the streaming body (or `None`).
macro_rules! oracle_projection {
    (
        $(#[$meta:meta])*
        fn $name:ident($ty:path) {
            put: [$($put:ident),* $(,)?],
            opt: [$($opt:ident),* $(,)?],
            custom: [$($custom:ident),* $(,)?] $(,)?
        }
        |$fields:ident| $custom_body:block
    ) => {
        $(#[$meta])*
        pub(crate) fn $name(input: $ty) -> $crate::project::OracleProjection {
            let $ty { $($put,)* $($opt,)* $($custom,)* } = input;
            #[allow(unused_mut, reason = "a projection without custom members writes nothing more")]
            let mut $fields = $crate::fields::Fields::default();
            $( $fields.put(stringify!($put), &$put); )*
            $( $fields.opt(stringify!($opt), $opt.as_ref()); )*
            let body: Option<$crate::s3s::dto::StreamingBlob> = $custom_body;
            $crate::project::OracleProjection { fields: $fields, body }
        }
    };
}

pub(crate) use {gateway_projection, oracle_projection};

/// The one table: operation, the s3s trait method and its input/output types, and the two
/// projections.
macro_rules! diffed_operations {
    ($($op:ident / $method:ident($input:ident, $output:ident) => $gateway:path, $oracle:path, $convert:path;)+) => {
        /// Every operation whose input the decode diff compares member by member, and whose output
        /// the encode diff writes on both stacks.
        pub const DIFFED_OPERATIONS: &[&str] = &[$(stringify!($op)),+];

        /// One output a RustFS handler could return, for an operation the diff knows.
        #[allow(clippy::large_enum_variant, reason = "a sample is built once and moved once")]
        pub enum OracleOutput {
            $(
                #[doc = concat!("A ", stringify!($op), " output.")]
                $op(oracle::$output),
            )+
        }

        impl std::fmt::Debug for OracleOutput {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$op(output) => output.fmt(formatter),)+
                }
            }
        }

        impl OracleOutput {
            /// The operation this output answers.
            #[must_use]
            pub const fn operation(&self) -> &'static str {
                match self {
                    $(Self::$op(_) => stringify!($op),)+
                }
            }

            /// The gateway output the gateway codec writes for this one, boxed for the recorder's
            /// answer slot.
            pub(crate) fn into_gateway(self) -> Result<Box<dyn std::any::Any + Send>, crate::convert::Unconvertible> {
                match self {
                    $(Self::$op(output) => $convert(output).map(|converted| Box::new(converted) as Box<dyn std::any::Any + Send>),)+
                }
            }
        }

        #[cfg(test)]
        impl OracleOutput {
            /// `sample` written by both stacks through the production seam, as the RustFS adapter
            /// converts an answer, instead of through this crate's own conversion.
            pub(crate) fn through_seam(
                sample: &crate::OutputSample,
                differ: &crate::seam::SeamDiffer,
            ) -> Result<crate::seam::AnswerDiff, String> {
                let build = std::sync::Arc::clone(&sample.output);
                match (sample.output)() {
                    $(Self::$op(_) => differ.answer_diff(&sample.request, move || match build() {
                        Self::$op(output) => output,
                        other => unreachable!("sample {} built a {} output", stringify!($op), other.operation()),
                    }),)+
                }
            }
        }

        /// Registers the recording handler for every diffed operation.
        pub(crate) fn register(builder: ServiceBuilder, recorder: &Arc<Recorder>) -> ServiceBuilder {
            builder $(.register::<dto::$op, _>(Arc::clone(recorder)))+
        }

        $(impl Projected for dto::$op {
            fn gateway(request: rustfs_gateway::Req<Self>) -> Projection {
                $gateway(request)
            }
        })+

        impl s3s::S3 for RecordingS3 {
            // The pinned trait is declared with `#[async_trait]`; these are the signatures that
            // attribute expands a `&self` method to, spelled out so this crate needs no proc-macro
            // dependency.
            $(fn $method<'life0, 'future>(
                &'life0 self,
                request: s3s::S3Request<oracle::$input>,
            ) -> Answered<'future, oracle::$output>
            where
                'life0: 'future,
                Self: 'future,
            {
                let OracleProjection { fields, body } = $oracle(request.input);
                Box::pin(async move {
                    self.record(fields, body).await;
                    match self.take_answer() {
                        Some(OracleOutput::$op(output)) => Ok(s3s::S3Response::new(output)),
                        _ => recorded(),
                    }
                })
            })+
        }
    };
}

diffed_operations! {
    GetObject / get_object(GetObjectInput, GetObjectOutput) => object::gateway_get_object, object::oracle_get_object, crate::convert::object::get_object;
    HeadObject / head_object(HeadObjectInput, HeadObjectOutput) => object::gateway_head_object, object::oracle_head_object, crate::convert::object::head_object;
    PutObject / put_object(PutObjectInput, PutObjectOutput) => object::gateway_put_object, object::oracle_put_object, crate::convert::object::put_object;
    DeleteObject / delete_object(DeleteObjectInput, DeleteObjectOutput) => object::gateway_delete_object, object::oracle_delete_object, crate::convert::object::delete_object;
    DeleteObjects / delete_objects(DeleteObjectsInput, DeleteObjectsOutput) => object::gateway_delete_objects, object::oracle_delete_objects, crate::convert::object::delete_objects;
    CopyObject / copy_object(CopyObjectInput, CopyObjectOutput) => object::gateway_copy_object, object::oracle_copy_object, crate::convert::object::copy_object;
    ListObjects / list_objects(ListObjectsInput, ListObjectsOutput) => listing::gateway_list_objects, listing::oracle_list_objects, crate::convert::listing::list_objects;
    ListObjectsV2 / list_objects_v2(ListObjectsV2Input, ListObjectsV2Output) => listing::gateway_list_objects_v2, listing::oracle_list_objects_v2, crate::convert::listing::list_objects_v2;
    ListObjectVersions / list_object_versions(ListObjectVersionsInput, ListObjectVersionsOutput) => listing::gateway_list_object_versions, listing::oracle_list_object_versions, crate::convert::listing::list_object_versions;
    ListMultipartUploads / list_multipart_uploads(ListMultipartUploadsInput, ListMultipartUploadsOutput) => listing::gateway_list_multipart_uploads, listing::oracle_list_multipart_uploads, crate::convert::listing::list_multipart_uploads;
    CreateMultipartUpload / create_multipart_upload(CreateMultipartUploadInput, CreateMultipartUploadOutput) => multipart::gateway_create_multipart_upload, multipart::oracle_create_multipart_upload, crate::convert::multipart::create_multipart_upload;
    UploadPart / upload_part(UploadPartInput, UploadPartOutput) => multipart::gateway_upload_part, multipart::oracle_upload_part, crate::convert::multipart::upload_part;
    CompleteMultipartUpload / complete_multipart_upload(CompleteMultipartUploadInput, CompleteMultipartUploadOutput) => multipart::gateway_complete_multipart_upload, multipart::oracle_complete_multipart_upload, crate::convert::multipart::complete_multipart_upload;
    AbortMultipartUpload / abort_multipart_upload(AbortMultipartUploadInput, AbortMultipartUploadOutput) => multipart::gateway_abort_multipart_upload, multipart::oracle_abort_multipart_upload, crate::convert::multipart::abort_multipart_upload;
    ListParts / list_parts(ListPartsInput, ListPartsOutput) => multipart::gateway_list_parts, multipart::oracle_list_parts, crate::convert::multipart::list_parts;
    CreateBucket / create_bucket(CreateBucketInput, CreateBucketOutput) => bucket::gateway_create_bucket, bucket::oracle_create_bucket, crate::convert::bucket::create_bucket;
    DeleteBucket / delete_bucket(DeleteBucketInput, DeleteBucketOutput) => bucket::gateway_delete_bucket, bucket::oracle_delete_bucket, crate::convert::bucket::delete_bucket;
    HeadBucket / head_bucket(HeadBucketInput, HeadBucketOutput) => bucket::gateway_head_bucket, bucket::oracle_head_bucket, crate::convert::bucket::head_bucket;
    ListBuckets / list_buckets(ListBucketsInput, ListBucketsOutput) => bucket::gateway_list_buckets, bucket::oracle_list_buckets, crate::convert::listing::list_buckets;
    GetBucketLocation / get_bucket_location(GetBucketLocationInput, GetBucketLocationOutput) => bucket::gateway_get_bucket_location, bucket::oracle_get_bucket_location, crate::convert::bucket::get_bucket_location;
    GetBucketVersioning / get_bucket_versioning(GetBucketVersioningInput, GetBucketVersioningOutput) => bucket::gateway_get_bucket_versioning, bucket::oracle_get_bucket_versioning, crate::convert::bucket::get_bucket_versioning;
    PutBucketVersioning / put_bucket_versioning(PutBucketVersioningInput, PutBucketVersioningOutput) => bucket::gateway_put_bucket_versioning, bucket::oracle_put_bucket_versioning, crate::convert::bucket::put_bucket_versioning;
}

/// Every gateway member each diffed operation's projection reads, for the census test.
#[cfg(test)]
pub(crate) const GATEWAY_MEMBER_CENSUS: &[(&str, &[&str])] = &[
    ("GetObjectInput", object::GET_OBJECT_MEMBERS),
    ("HeadObjectInput", object::HEAD_OBJECT_MEMBERS),
    ("PutObjectInput", object::PUT_OBJECT_MEMBERS),
    ("DeleteObjectInput", object::DELETE_OBJECT_MEMBERS),
    ("DeleteObjectsInput", object::DELETE_OBJECTS_MEMBERS),
    ("CopyObjectInput", object::COPY_OBJECT_MEMBERS),
    ("ListObjectsInput", listing::LIST_OBJECTS_MEMBERS),
    ("ListObjectsV2Input", listing::LIST_OBJECTS_V2_MEMBERS),
    ("ListObjectVersionsInput", listing::LIST_OBJECT_VERSIONS_MEMBERS),
    ("ListMultipartUploadsInput", listing::LIST_MULTIPART_UPLOADS_MEMBERS),
    ("CreateMultipartUploadInput", multipart::CREATE_MULTIPART_UPLOAD_MEMBERS),
    ("UploadPartInput", multipart::UPLOAD_PART_MEMBERS),
    ("CompleteMultipartUploadInput", multipart::COMPLETE_MULTIPART_UPLOAD_MEMBERS),
    ("AbortMultipartUploadInput", multipart::ABORT_MULTIPART_UPLOAD_MEMBERS),
    ("ListPartsInput", multipart::LIST_PARTS_MEMBERS),
    ("CreateBucketInput", bucket::CREATE_BUCKET_MEMBERS),
    ("DeleteBucketInput", bucket::DELETE_BUCKET_MEMBERS),
    ("HeadBucketInput", bucket::HEAD_BUCKET_MEMBERS),
    ("ListBucketsInput", bucket::LIST_BUCKETS_MEMBERS),
    ("GetBucketLocationInput", bucket::GET_BUCKET_LOCATION_MEMBERS),
    ("GetBucketVersioningInput", bucket::GET_BUCKET_VERSIONING_MEMBERS),
    ("PutBucketVersioningInput", bucket::PUT_BUCKET_VERSIONING_MEMBERS),
];
