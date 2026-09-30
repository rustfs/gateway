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

//! The object names RustFS refuses, refused where RustFS refuses them (rustfs/gateway#1145,
//! rustfs/gateway#1153).
//!
//! Responsible for: three rules — its storage's name rule ([`rustfs_storage_refuses`]), its disk's
//! segment length ([`rustfs_disk_refuses`]) and its object handlers' control characters
//! ([`rustfs_handlers_refuse`]) — and the layers ([`StorageNames`]) that answer a key, a copy
//! source's key, a browser form's key or a listing prefix a rule refuses as RustFS answers it,
//! without the backend being reached; the first two are also handed to the backend for batch
//! deletes (`crate::service::open_backend`, [`rustfs_storage_or_disk_refuses`]).
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
//!
//! # A segment RustFS's disk cannot name
//!
//! Every `/`-separated segment of a key becomes one directory entry on RustFS's disk, so a segment
//! longer than 255 bytes (`NAME_MAX`), or 246 for the last one of a key that ends in `/`, whose
//! entry carries the `__XLDIR__` suffix, can never be stored (`object_key_segments_fit_on_disk`,
//! `crates/ecstore/src/bucket/utils.rs:276-300` on rustfs/rustfs `3268c42e00`). Only `/` separates;
//! a backslash is part of the segment, and the length is in bytes. Measured on a legacy build
//! (rustfs/rustfs `528a36814`): PutObject, GetObject, a browser form, a copy's source and a part
//! copy's source under an existing upload are always `400 InvalidArgument` "Invalid argument",
//! after the bucket lookup. HeadObject, DeleteObject, CreateMultipartUpload, a copy's destination
//! and the object tagging and ACL operations (name first there too) are `400` only while no
//! parent directory of the key exists on its disk; once one does — for a flat key the bucket's
//! own, so always — its disk fails on the name and they are `500 InternalError`, and a batch
//! delete answers such a key `InternalError` instead of `InvalidArgument`. The launcher has no
//! directories to consult, so it answers the deterministic `400` wherever legacy RustFS answers
//! one of the two: the `500` is a difference left here, where it lives. An operation on an upload
//! under such a key is `404 NoSuchUpload` on both, since no upload can start there, and a listing
//! with such a prefix is `200` on both, except that legacy RustFS answers `503 SlowDownRead` when
//! the long segment is a directory of the prefix (another answer of its disk, not reproduced).
//!
//! # A control character in a key
//!
//! Legacy RustFS's PutObject, GetObject, HeadObject, DeleteObject and CopyObject handlers, and its
//! browser-form upload, refuse a key holding a NUL, CR or LF with `400 InvalidArgument` "Object key
//! contains invalid control characters: " followed by the key as Rust's `Debug` renders it
//! (`validate_object_key`, `rustfs/src/storage/ecfs_extend.rs:334-355`; called at
//! `rustfs/src/app/object/get.rs:2455`, `head.rs:323`, `put.rs:1268`, `delete.rs:935` and
//! `copy.rs:255-256`, source before destination, on rustfs/rustfs `3268c42e00`). Measured on the
//! same build: GetObject and HeadObject refuse before the bucket lookup, the others after it, a
//! copy after both of its buckets; no other operation checks it, so a multipart upload stores such
//! a key and GetObject then refuses to read it, as here. A NUL is also refused by the storage rule,
//! with that rule's sentence, on every operation these handlers do not cover.
//!
//! Two of these refusals are answered before the layers run, and the difference is the RustFS
//! profile's rather than the launcher's; nothing is stored either way. A NUL is refused by the
//! profile's key floor with `400 InvalidArgument` and a sentence of its own ("the name contains a
//! NUL byte"). A browser form whose key holds any of the three is refused by the profile's form
//! reader as `400 MalformedPOSTRequest`, where legacy RustFS reads the form and its handler answers
//! `400 InvalidArgument` with the sentence above, `404 NoSuchBucket` first on a missing bucket
//! (rustfs/gateway#1167).
//!
//! Legacy-compat (rustfs/backlog#2684): an object a multipart upload stored under a CR or LF key
//! cannot be read, overwritten or deleted by key, only listed; the intended behaviour is one key
//! rule applied by every operation that names a key.

use std::sync::Arc;

use rustfs_gateway::{
    BoxFuture, ErrorCode, HandlerError, HandlerErrorContext, HandlerResult, Next, OpLayer, Req, ServiceBuilder, dto,
};
use rustfs_gateway_fs::FsBackend;

/// The longest name RustFS's storage looks at before refusing it outright.
const MAX_JUDGED_BYTES: usize = 32 << 10;

/// The longest segment RustFS's disk can name: `NAME_MAX`.
const MAX_SEGMENT_BYTES: usize = 255;

/// What RustFS appends to the last segment of a key that ends in `/` before it reaches its disk.
const DIRECTORY_SUFFIX: &str = "__XLDIR__";

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

/// Whether RustFS's disk cannot name a segment of `key`, a decoded key: see the module
/// documentation for the rule and where it comes from.
#[must_use]
pub(crate) fn rustfs_disk_refuses(key: &str) -> bool {
    let directory = key.ends_with('/');
    let segments: Vec<&str> = key.split('/').collect();
    let last = segments.iter().rposition(|segment| !segment.is_empty());
    segments.iter().enumerate().any(|(index, segment)| {
        let budget = if directory && Some(index) == last {
            MAX_SEGMENT_BYTES - DIRECTORY_SUFFIX.len()
        } else {
            MAX_SEGMENT_BYTES
        };
        segment.len() > budget
    })
}

/// Whether legacy RustFS's object handlers refuse `key`, a decoded key, for a control character.
#[must_use]
pub(crate) fn rustfs_handlers_refuse(key: &str) -> bool {
    key.contains(['\0', '\n', '\r'])
}

/// Whether RustFS's storage refuses `name` or its disk cannot name it: what a batch delete answers
/// with its own error entry, and what a copy or part copy refuses in its source. Neither checks
/// control characters.
#[must_use]
pub(crate) fn rustfs_storage_or_disk_refuses(name: &str) -> bool {
    rustfs_storage_refuses(name) || rustfs_disk_refuses(name)
}

/// RustFS's answer to a name its storage refuses or its disk cannot name.
fn refused() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, "Invalid argument")
}

/// Legacy RustFS's handlers' answer to a control character in `key`.
fn control_refusal(key: &str) -> HandlerError {
    HandlerError::new(
        ErrorCode::INVALID_ARGUMENT,
        format!("Object key contains invalid control characters: {key:?}"),
    )
}

/// The reference backend's own answer to a bucket that does not exist.
fn missing_bucket() -> HandlerError {
    HandlerErrorContext::missing_bucket().into()
}

/// What RustFS asks first about a request whose name it refuses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    /// Whether the bucket exists, then the name.
    BucketFirst,
    /// The name, whatever the bucket.
    NameFirst,
}

/// What legacy RustFS judges about one operation's key, in its order.
#[derive(Clone, Copy)]
struct KeyRules {
    /// When its handler checks for a control character, if it does; before the storage rule.
    control: Option<Order>,
    /// When its storage judges the name, and the segment rule with it.
    storage: Order,
    /// Whether a segment its disk cannot name is refused here, rather than by an upload lookup
    /// that fails first.
    segments: bool,
}

impl KeyRules {
    /// PutObject, DeleteObject and a browser form: the bucket, the handler's check, the storage.
    const WRITE: Self = Self {
        control: Some(Order::BucketFirst),
        storage: Order::BucketFirst,
        segments: true,
    };
    /// GetObject and HeadObject: the handler's check before anything, then the bucket.
    const READ: Self = Self {
        control: Some(Order::NameFirst),
        storage: Order::BucketFirst,
        segments: true,
    };
    /// CreateMultipartUpload: no handler check; the bucket, then the storage and the disk.
    const UPLOAD_START: Self = Self {
        control: None,
        storage: Order::BucketFirst,
        segments: true,
    };
    /// An operation on an upload: its lookup answers a key no upload can exist under.
    const UPLOAD: Self = Self {
        control: None,
        storage: Order::BucketFirst,
        segments: false,
    };
    /// The object tagging and ACL operations: the name first, whatever the bucket.
    const SUBRESOURCE: Self = Self {
        control: None,
        storage: Order::NameFirst,
        segments: true,
    };
}

/// The layers, sharing the backend they ask whether a bucket exists.
pub(crate) struct StorageNames {
    backend: Arc<FsBackend>,
}

impl StorageNames {
    async fn bucket_missing(&self, bucket: &str) -> bool {
        matches!(self.backend.bucket_policy(bucket).await, Err(error) if error.code() == &ErrorCode::NO_SUCH_BUCKET)
    }

    /// RustFS's answer to the key `name` in `bucket` under `rules`, or `None` when it keeps it.
    async fn judge(&self, rules: KeyRules, bucket: &str, name: &str) -> Option<HandlerError> {
        let control = rules.control.filter(|_| rustfs_handlers_refuse(name));
        if control == Some(Order::NameFirst) {
            return Some(control_refusal(name));
        }
        let storage = rustfs_storage_refuses(name) || (rules.segments && rustfs_disk_refuses(name));
        if control.is_none() && !storage {
            return None;
        }
        if (control.is_some() || rules.storage == Order::BucketFirst) && self.bucket_missing(bucket).await {
            return Some(missing_bucket());
        }
        Some(if control.is_some() { control_refusal(name) } else { refused() })
    }

    /// A listing prefix: judged by the storage rule alone, after the bucket lookup.
    async fn judge_prefix(&self, bucket: &str, prefix: &str) -> Option<HandlerError> {
        if !rustfs_storage_refuses(prefix) {
            return None;
        }
        Some(if self.bucket_missing(bucket).await {
            missing_bucket()
        } else {
            refused()
        })
    }
}

/// A layer for each operation that names an object key, with the rules RustFS applies to it.
macro_rules! key_layers {
    ($($operation:ident: $rules:ident),+ $(,)?) => {$(
        impl OpLayer<dto::$operation> for StorageNames {
            fn wrap<'a>(
                &'a self,
                request: Req<dto::$operation>,
                next: Next<'a, dto::$operation>,
            ) -> BoxFuture<'a, HandlerResult<dto::$operation>> {
                Box::pin(async move {
                    let input = request.input();
                    if let Some(refusal) = self.judge(KeyRules::$rules, input.bucket.as_str(), input.key.as_str()).await {
                        return Err(refusal);
                    }
                    next.run(request).await
                })
            }
        }
    )+};
}

key_layers! {
    AbortMultipartUpload: UPLOAD,
    CompleteMultipartUpload: UPLOAD,
    CreateMultipartUpload: UPLOAD_START,
    DeleteObject: WRITE,
    GetObject: READ,
    HeadObject: READ,
    ListParts: UPLOAD,
    PostObject: WRITE,
    PutObject: WRITE,
    UploadPart: UPLOAD,
    DeleteObjectTagging: SUBRESOURCE,
    GetObjectAcl: SUBRESOURCE,
    GetObjectTagging: SUBRESOURCE,
    PutObjectAcl: SUBRESOURCE,
    PutObjectTagging: SUBRESOURCE,
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
                        && let Some(refusal) = self.judge_prefix(input.bucket.as_str(), prefix).await
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
/// is answered as the reference backend answers it for a copy; then the handler's control check,
/// source before destination, then the storage and the disk.
impl OpLayer<dto::CopyObject> for StorageNames {
    fn wrap<'a>(
        &'a self,
        request: Req<dto::CopyObject>,
        next: Next<'a, dto::CopyObject>,
    ) -> BoxFuture<'a, HandlerResult<dto::CopyObject>> {
        Box::pin(async move {
            let input = request.input();
            let source = request.resources().source().resolve(request.read_proof());
            let source_key = source.as_ref().map(|source| source.key().as_str());
            let names = [source_key, Some(input.key.as_str())];
            let controlled = names.into_iter().flatten().find(|name| rustfs_handlers_refuse(name));
            if controlled.is_some() || names.into_iter().flatten().any(rustfs_storage_or_disk_refuses) {
                if self.bucket_missing(input.bucket.as_str()).await {
                    return Err(missing_bucket());
                }
                if let Some(source) = &source
                    && self.bucket_missing(source.bucket().as_str()).await
                {
                    return Err(missing_bucket().as_copy_source_refusal());
                }
                return Err(controlled.map_or_else(refused, control_refusal));
            }
            next.run(request).await
        })
    }
}

/// A part copy: its own key is judged before its upload is looked up, and its source after, by the
/// storage rule and the disk's segment length; its handler does not check control characters.
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
            if let Some(refusal) = self.judge(KeyRules::UPLOAD, input.bucket.as_str(), input.key.as_str()).await {
                return Err(refusal);
            }
            let source = request.resources().source().resolve(request.read_proof());
            if let Some(source) = &source
                && rustfs_storage_or_disk_refuses(source.key().as_str())
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
    use super::{rustfs_disk_refuses, rustfs_handlers_refuse, rustfs_storage_or_disk_refuses, rustfs_storage_refuses};

    /// Negative — every segment RustFS's disk cannot name, measured on a legacy build: over 255
    /// bytes anywhere, over 246 as the last segment of a key ending in `/`, counted in bytes, with
    /// only `/` separating.
    #[test]
    fn n_every_segment_rustfs_s_disk_cannot_name_is_refused() {
        for key in [
            "x".repeat(256),
            format!("q/{}", "x".repeat(256)),
            format!("{}/a", "x".repeat(256)),
            format!("a/{}/b", "x".repeat(256)),
            format!("d/{}/", "z".repeat(247)),
            format!("d/{}//", "z".repeat(247)),
            "\u{e9}".repeat(129),
            format!("a\\{}\\{}", "v".repeat(200), "v".repeat(100)),
        ] {
            assert!(rustfs_disk_refuses(&key), "{} bytes: {:?}", key.len(), &key[..key.len().min(24)]);
            assert!(rustfs_storage_or_disk_refuses(&key), "{:?}", &key[..key.len().min(24)]);
        }
    }

    /// Positive — the segments RustFS's disk names, at and under each budget.
    #[test]
    fn the_segments_rustfs_s_disk_names_are_kept() {
        for key in [
            String::new(),
            "w".repeat(255),
            format!("d/{}/", "z".repeat(246)),
            format!("{}/{}", "a".repeat(255), "b".repeat(255)),
            format!("{}/", "c".repeat(246)),
            "\u{e9}".repeat(127),
        ] {
            assert!(!rustfs_disk_refuses(&key), "{} bytes", key.len());
        }
    }

    /// Negative — a NUL, CR or LF anywhere in a key is refused by legacy RustFS's handlers.
    #[test]
    fn n_a_nul_cr_or_lf_is_refused_by_the_handlers() {
        for key in ["a\nb", "a\rb", "a\0b", "\n", "ab\r"] {
            assert!(rustfs_handlers_refuse(key), "{key:?}");
        }
    }

    /// Positive — every other character, other control characters and encoded spellings included,
    /// is left to the storage rule.
    #[test]
    fn other_characters_pass_the_handlers() {
        for key in ["a\tb", "a b", "a\u{85}b", "a\u{2028}b", "a%0Ab", "a\u{b}b"] {
            assert!(!rustfs_handlers_refuse(key), "{key:?}");
        }
    }

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
