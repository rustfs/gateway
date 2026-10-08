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

//! `--register-only`: the reference backend's registry, cut down to the named operations.
//!
//! Responsible for: the one table from an operation name to the backend handler registered for
//! it, and registering exactly the named rows. An endpoint built this way answers every other
//! operation `501 NotImplemented`, which is the negative control of the client matrix's
//! `sut-unregistered` status (rustfs/backlog#2758).
//! NOT responsible for: the rest of the assembly — profile, authenticator, authorizer and limits
//! stay exactly those of `crate::service::build_service` — nor for any handler behaviour.
//! Upstream: `crate::parse_options`, which validates names against [`REGISTRABLE`], and
//! `crate::service::build_service`. Downstream: `rustfs-gateway`'s `ServiceBuilder::register`.
//!
//! The table is written once, here, and `service/tests/register_only_tests.rs` holds it equal to
//! the backend's own registry in both directions, so a name can be neither missing nor invented.

use std::sync::Arc;

use rustfs_gateway::{ServiceBuilder, dto};
use rustfs_gateway_fs::FsBackend;

macro_rules! registrable {
    ($($operation:ident,)+) => {
        /// Every operation name `--register-only` accepts: the reference backend's whole registry.
        pub(crate) const REGISTRABLE: &[&str] = &[$(stringify!($operation),)+];

        /// Registers the one operation `name` names, or returns `None` for a name not in the table.
        fn register_one(builder: ServiceBuilder, backend: &Arc<FsBackend>, name: &str) -> Option<ServiceBuilder> {
            match name {
                $(stringify!($operation) => Some(builder.register::<dto::$operation, _>(Arc::clone(backend))),)+
                _ => None,
            }
        }
    };
}

registrable! {
    AbortMultipartUpload,
    CompleteMultipartUpload,
    CopyObject,
    CreateBucket,
    CreateMultipartUpload,
    DeleteBucket,
    DeleteBucketCors,
    DeleteBucketEncryption,
    DeleteBucketLifecycle,
    DeleteBucketPolicy,
    DeleteBucketTagging,
    DeleteObject,
    DeleteObjectTagging,
    DeleteObjects,
    DeletePublicAccessBlock,
    GetBucketAcl,
    GetBucketCors,
    GetBucketEncryption,
    GetBucketLifecycleConfiguration,
    GetBucketLocation,
    GetBucketPolicy,
    GetBucketPolicyStatus,
    GetBucketTagging,
    GetBucketVersioning,
    GetObject,
    GetObjectAcl,
    GetObjectAttributes,
    GetObjectTagging,
    GetPublicAccessBlock,
    HeadBucket,
    HeadObject,
    ListBuckets,
    ListMultipartUploads,
    ListObjectVersions,
    ListObjects,
    ListObjectsV2,
    ListParts,
    PostObject,
    PutBucketAcl,
    PutBucketCors,
    PutBucketEncryption,
    PutBucketLifecycleConfiguration,
    PutBucketPolicy,
    PutBucketTagging,
    PutBucketVersioning,
    PutObject,
    PutObjectAcl,
    PutObjectTagging,
    PutPublicAccessBlock,
    UploadPart,
    UploadPartCopy,
}

/// Registers exactly `names` on `builder`.
///
/// # Errors
///
/// An invalid-input error for a name outside [`REGISTRABLE`]; `crate::parse_options` refuses those
/// first, so this is the second line, not the first.
pub(crate) fn register_only(
    mut builder: ServiceBuilder,
    backend: &Arc<FsBackend>,
    names: &[String],
) -> std::io::Result<ServiceBuilder> {
    for name in names {
        builder = register_one(builder, backend, name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--register-only names {name:?}, which the reference backend does not register"),
            )
        })?;
    }
    Ok(builder)
}
