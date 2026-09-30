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

//! The object names RustFS's storage refuses, refused where RustFS refuses them
//! (rustfs/gateway#1145).
//!
//! Responsible for: the rule ([`rustfs_storage_refuses`]), and the layers ([`StorageNames`]) that
//! answer a key, a copy source's key, a browser form's key or a listing prefix the rule refuses as
//! RustFS answers it, without the backend being reached; the rule is also handed to the backend
//! for batch deletes (`crate::service::open_backend`).
//! NOT responsible for: the keys the RustFS profile accepts at all (the gateway's key floor), or
//! the operations the reference backend does not implement.
//! Upstream: `crate::service`, which installs the layers. Downstream: nothing.
//!
//! # The rule, from source and from a run
//!
//! RustFS's storage refuses a key or a listing prefix when, leading `/` and `\` skipped, a segment
//! between `/` or `\` separators is `.` or `..` once the whitespace around it is trimmed, when it
//! holds `//` or a NUL, or when it is longer than 32 KiB (`has_bad_path_component` and
//! `is_valid_object_prefix`, `crates/ecstore/src/bucket/utils.rs:109-176` on rustfs/rustfs
//! `e870a6d25b`), with `400 InvalidArgument` "Invalid argument". The reference backend hashes keys
//! onto its disk and would store every one of those names, so without these layers the launcher
//! served and stored objects RustFS never holds.
//!
//! Where RustFS answers, measured on a legacy build: in its handlers, so after authentication,
//! authorization and the decode of a request document (an anonymous request is `403`, a malformed
//! tagging document `MalformedXML`); on a bucket that does not exist `404 NoSuchBucket` comes
//! first, except on the object tagging and ACL operations, which judge the name first. A copy looks
//! up its destination bucket and its source bucket before either name; a part copy judges its own
//! key before its upload, and its source after the upload. A batch delete answers each refused key
//! with its own error entry and deletes the others; on a bucket with versioning enabled legacy
//! RustFS answers them as deleted instead and records its delete marker under the path its disk
//! resolves them to — a storage defect reported to the maintainers, which the launcher does not
//! reproduce. The gateway hands the backend the key legacy RustFS hands its storage (the difftest
//! RustFS-profile key rows), so behind the gateway RustFS's own storage keeps answering these names
//! itself.
//!
//! Legacy-compat (rustfs/backlog#2684): RustFS's storage layout leaks into its API here — `a//b`
//! and `a/./b` are keys S3 stores. Kept so the launcher neither serves nor stores an object RustFS
//! never holds; the intended future behaviour is a key rule of the protocol, not of one storage's
//! layout.

use std::sync::Arc;

use rustfs_gateway::{
    BoxFuture, ErrorCode, HandlerError, HandlerErrorContext, HandlerResult, Next, OpLayer, Req, ServiceBuilder, dto,
};
use rustfs_gateway_fs::FsBackend;

/// The longest name RustFS's storage looks at before refusing it outright.
const MAX_JUDGED_BYTES: usize = 32 << 10;

/// Whether RustFS's storage refuses `name`, a decoded key or listing prefix: see the module
/// documentation for the rule and where it comes from.
#[must_use]
pub(crate) fn rustfs_storage_refuses(name: &str) -> bool {
    if name.len() > MAX_JUDGED_BYTES || name.contains("//") || name.contains('\0') {
        return true;
    }
    // Leading separators only yield empty segments, which are never `.` or `..`.
    name.split(['/', '\\']).any(|segment| matches!(segment.trim(), "." | ".."))
}

/// RustFS's answer to a name its storage refuses.
fn refused() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, "Invalid argument")
}

/// The reference backend's own answer to a bucket that does not exist.
fn missing_bucket() -> HandlerError {
    HandlerErrorContext::missing_bucket().into()
}

/// What RustFS asks first about a request whose name its storage refuses.
#[derive(Clone, Copy)]
enum Order {
    /// Whether the bucket exists, then the name.
    BucketFirst,
    /// The name, whatever the bucket.
    NameFirst,
}

/// The layers, sharing the backend they ask whether a bucket exists.
pub(crate) struct StorageNames {
    backend: Arc<FsBackend>,
}

impl StorageNames {
    async fn bucket_missing(&self, bucket: &str) -> bool {
        matches!(self.backend.bucket_policy(bucket).await, Err(error) if error.code() == &ErrorCode::NO_SUCH_BUCKET)
    }

    /// RustFS's answer to `name` in `bucket` under `order`, or `None` when its storage keeps the
    /// name.
    async fn judge(&self, order: Order, bucket: &str, name: &str) -> Option<HandlerError> {
        if !rustfs_storage_refuses(name) {
            return None;
        }
        match order {
            Order::BucketFirst if self.bucket_missing(bucket).await => Some(missing_bucket()),
            Order::BucketFirst | Order::NameFirst => Some(refused()),
        }
    }
}

/// A layer for each operation that names an object key, in the order RustFS judges it.
macro_rules! key_layers {
    ($($operation:ident: $order:ident),+ $(,)?) => {$(
        impl OpLayer<dto::$operation> for StorageNames {
            fn wrap<'a>(
                &'a self,
                request: Req<dto::$operation>,
                next: Next<'a, dto::$operation>,
            ) -> BoxFuture<'a, HandlerResult<dto::$operation>> {
                Box::pin(async move {
                    let input = request.input();
                    if let Some(refusal) = self.judge(Order::$order, input.bucket.as_str(), input.key.as_str()).await {
                        return Err(refusal);
                    }
                    next.run(request).await
                })
            }
        }
    )+};
}

key_layers! {
    AbortMultipartUpload: BucketFirst,
    CompleteMultipartUpload: BucketFirst,
    CreateMultipartUpload: BucketFirst,
    DeleteObject: BucketFirst,
    GetObject: BucketFirst,
    HeadObject: BucketFirst,
    ListParts: BucketFirst,
    PostObject: BucketFirst,
    PutObject: BucketFirst,
    UploadPart: BucketFirst,
    DeleteObjectTagging: NameFirst,
    GetObjectAcl: NameFirst,
    GetObjectTagging: NameFirst,
    PutObjectAcl: NameFirst,
    PutObjectTagging: NameFirst,
}

/// A layer for each listing, whose `prefix` RustFS's storage judges after the bucket lookup.
macro_rules! prefix_layers {
    ($($operation:ident),+ $(,)?) => {$(
        impl OpLayer<dto::$operation> for StorageNames {
            fn wrap<'a>(
                &'a self,
                request: Req<dto::$operation>,
                next: Next<'a, dto::$operation>,
            ) -> BoxFuture<'a, HandlerResult<dto::$operation>> {
                Box::pin(async move {
                    let input = request.input();
                    if let Some(prefix) = input.prefix.as_deref()
                        && let Some(refusal) = self.judge(Order::BucketFirst, input.bucket.as_str(), prefix).await
                    {
                        return Err(refusal);
                    }
                    next.run(request).await
                })
            }
        }
    )+};
}

prefix_layers!(ListMultipartUploads, ListObjectVersions, ListObjects, ListObjectsV2);

/// A copy: both buckets are looked up before either name is judged, and a missing source bucket
/// is answered as the reference backend answers it for a copy.
impl OpLayer<dto::CopyObject> for StorageNames {
    fn wrap<'a>(
        &'a self,
        request: Req<dto::CopyObject>,
        next: Next<'a, dto::CopyObject>,
    ) -> BoxFuture<'a, HandlerResult<dto::CopyObject>> {
        Box::pin(async move {
            let input = request.input();
            let source = request.resources().source().resolve(request.read_proof());
            let source_refused = source
                .as_ref()
                .is_some_and(|source| rustfs_storage_refuses(source.key().as_str()));
            if rustfs_storage_refuses(input.key.as_str()) || source_refused {
                if self.bucket_missing(input.bucket.as_str()).await {
                    return Err(missing_bucket());
                }
                if let Some(source) = &source
                    && self.bucket_missing(source.bucket().as_str()).await
                {
                    return Err(missing_bucket().as_copy_source_refusal());
                }
                return Err(refused());
            }
            next.run(request).await
        })
    }
}

/// A part copy: its own key is judged before its upload is looked up, and its source after.
///
/// This backend cannot be asked whether an upload exists without running the part copy, so a
/// refused source under an upload that does not exist is `400 InvalidArgument` here where RustFS
/// answers `404 NoSuchUpload`; nothing is stored either way.
impl OpLayer<dto::UploadPartCopy> for StorageNames {
    fn wrap<'a>(
        &'a self,
        request: Req<dto::UploadPartCopy>,
        next: Next<'a, dto::UploadPartCopy>,
    ) -> BoxFuture<'a, HandlerResult<dto::UploadPartCopy>> {
        Box::pin(async move {
            let input = request.input();
            if let Some(refusal) = self
                .judge(Order::BucketFirst, input.bucket.as_str(), input.key.as_str())
                .await
            {
                return Err(refusal);
            }
            let source = request.resources().source().resolve(request.read_proof());
            if let Some(source) = &source
                && rustfs_storage_refuses(source.key().as_str())
            {
                if self.bucket_missing(input.bucket.as_str()).await || self.bucket_missing(source.bucket().as_str()).await {
                    return Err(missing_bucket());
                }
                return Err(refused());
            }
            next.run(request).await
        })
    }
}

/// Installs the layers on every operation of the reference backend that names a key, a copy
/// source or a listing prefix; a batch delete is the backend's (`crate::service::open_backend`).
pub(crate) fn refuse_where_rustfs_storage_does(builder: ServiceBuilder, backend: &Arc<FsBackend>) -> ServiceBuilder {
    let names = Arc::new(StorageNames {
        backend: Arc::clone(backend),
    });
    builder
        .op_layer::<dto::AbortMultipartUpload, _>(Arc::clone(&names))
        .op_layer::<dto::CompleteMultipartUpload, _>(Arc::clone(&names))
        .op_layer::<dto::CopyObject, _>(Arc::clone(&names))
        .op_layer::<dto::CreateMultipartUpload, _>(Arc::clone(&names))
        .op_layer::<dto::DeleteObject, _>(Arc::clone(&names))
        .op_layer::<dto::DeleteObjectTagging, _>(Arc::clone(&names))
        .op_layer::<dto::GetObject, _>(Arc::clone(&names))
        .op_layer::<dto::GetObjectAcl, _>(Arc::clone(&names))
        .op_layer::<dto::GetObjectTagging, _>(Arc::clone(&names))
        .op_layer::<dto::HeadObject, _>(Arc::clone(&names))
        .op_layer::<dto::ListMultipartUploads, _>(Arc::clone(&names))
        .op_layer::<dto::ListObjectVersions, _>(Arc::clone(&names))
        .op_layer::<dto::ListObjects, _>(Arc::clone(&names))
        .op_layer::<dto::ListObjectsV2, _>(Arc::clone(&names))
        .op_layer::<dto::ListParts, _>(Arc::clone(&names))
        .op_layer::<dto::PostObject, _>(Arc::clone(&names))
        .op_layer::<dto::PutObject, _>(Arc::clone(&names))
        .op_layer::<dto::PutObjectAcl, _>(Arc::clone(&names))
        .op_layer::<dto::PutObjectTagging, _>(Arc::clone(&names))
        .op_layer::<dto::UploadPart, _>(Arc::clone(&names))
        .op_layer::<dto::UploadPartCopy, _>(names)
}

#[cfg(test)]
mod tests {
    use super::rustfs_storage_refuses;

    /// Negative — every shape RustFS's storage refuses, measured on a legacy build.
    #[test]
    fn n_every_shape_rustfs_s_storage_refuses_is_refused() {
        for name in [
            "a/./b=",
            "a/./b",
            "./b",
            "a/.",
            ".",
            "..",
            "a/../b",
            "a/..",
            "../b",
            "a//b",
            "a/b//",
            "//a",
            "a/ ../b",
            "a/.. /b",
            "a/\t./b",
            "a/..\u{a0}/b",
            "a/\u{85}../b",
            "a/\u{3000}./b",
            "a\\..\\b",
            "\\..\\b",
            "a\\.",
            "a\0b",
        ] {
            assert!(rustfs_storage_refuses(name), "{name:?}");
        }
        assert!(rustfs_storage_refuses(&"k".repeat((32 << 10) + 1)));
    }

    /// Positive — the names RustFS's storage keeps, the empty prefix included.
    #[test]
    fn the_names_rustfs_s_storage_keeps_are_kept() {
        for name in [
            "",
            "a/b=",
            "a/.b",
            "a/..b",
            "a/b.",
            "a/b/",
            "a/...",
            ".b",
            "..b",
            "/a",
            "\\a",
            "a\\b",
            "a%2F..%2Fb",
        ] {
            assert!(!rustfs_storage_refuses(name), "{name:?}");
        }
        assert!(!rustfs_storage_refuses(&"k".repeat(32 << 10)));
    }
}
