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

//! An upload id is an owned claim until storage proves which bucket and key own it.
//!
//! Responsible for: owning the decoded `uploadId` after the request buffer is gone, rejecting
//! shapes no backend could mint, and performing the single lookup-and-owner exchange that makes
//! the id readable by storage code.
//! NOT responsible for: decoding the query, minting or persisting upload ids, multipart part
//! rules, or rendering the rejection as an HTTP response.
//! Upstream: [`super::name::BucketName`], [`super::name::ObjectKey`] and
//! [`super::error_code::ErrorCode`]. Downstream: generated multipart request DTOs and backends
//! resolving those requests.
//!
//! A caller may construct an [`UploadIdClaim`] when building a request, but construction grants
//! no authority: the claim deliberately has no raw accessor, `Debug`, `Display`, or `PartialEq`.
//! Only [`resolve_upload`] and [`resolve_upload_async`] can inspect it, and only
//! [`ResolvedUploadId`] exposes an id after one lookup has proved both the bucket and key recorded
//! for the upload. Both exchanges share one private shape check and one private ownership check.

use super::{BucketName, ErrorCode, ObjectKey};
use crate::placeholder::WirePlaceholder;

include!("../../../../generated/upload_id_contracts.rs");

const NO_SUCH_UPLOAD: &str =
    "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.";

/// What a backend recorded about an upload when it created it.
pub trait RecordedUpload {
    /// The bucket the upload was created in.
    fn bucket(&self) -> &str;

    /// The key the upload was created for.
    fn key(&self) -> &str;
}

impl<T: RecordedUpload + ?Sized> RecordedUpload for &T {
    fn bucket(&self) -> &str {
        (**self).bucket()
    }

    fn key(&self) -> &str {
        (**self).key()
    }
}

/// The indistinguishable refusal returned for every failed upload-id exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRejection {
    code: ErrorCode,
    reason: &'static str,
}

impl UploadRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// A constant explanation that never includes the rejected id.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    fn no_such_upload() -> Self {
        Self {
            code: ErrorCode::NO_SUCH_UPLOAD,
            reason: NO_SUCH_UPLOAD,
        }
    }
}

/// An owned upload id read from the wire but resolved against no resource.
///
/// [`UploadIdClaim::from_wire`] is public so SDKs and tests can construct request DTOs. It grants
/// no authority: the bytes have no public accessor and can only be spent through
/// [`resolve_upload`] or [`resolve_upload_async`]. The type intentionally implements neither
/// `Debug`, `Display`, nor `PartialEq`, keeping the bearer value out of ordinary logs and
/// comparisons.
#[derive(Clone, Default)]
pub struct UploadIdClaim {
    raw: Box<str>,
}

impl UploadIdClaim {
    /// Owns one already-decoded `uploadId` value without authorizing its use.
    #[must_use]
    pub fn from_wire(raw: impl Into<String>) -> Self {
        Self {
            raw: raw.into().into_boxed_str(),
        }
    }

    /// The claimed bytes, for the migration seam only: the s3s input holds an upload id as a plain
    /// string, and the RustFS body it reaches resolves that id against its own bucket and key.
    #[cfg(any(feature = "compat-s3s-0-17-0", feature = "compat-s3s-rustfs"))]
    pub(crate) fn wire_for_compat_seam(&self) -> &str {
        &self.raw
    }
}

impl WirePlaceholder for UploadIdClaim {
    fn is_wire_placeholder(&self) -> bool {
        self.raw.is_empty()
    }
}

/// An upload id proved to belong to the request's bucket and key.
///
/// The private field and absence of a public constructor make the two exchanges,
/// [`resolve_upload`] and [`resolve_upload_async`], the only producers.
/// The type intentionally implements neither `Debug`, `Display`, nor `PartialEq` because the id
/// remains a bearer value after it has been resolved.
#[derive(Clone, Copy)]
pub struct ResolvedUploadId<'a> {
    id: &'a str,
}

impl<'a> ResolvedUploadId<'a> {
    /// The resolved id, byte for byte as it arrived.
    #[must_use]
    pub const fn id(&self) -> &'a str {
        self.id
    }
}

fn could_have_been_minted(raw: &str) -> bool {
    if raw.is_empty() || raw.starts_with('/') {
        return false;
    }
    if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return false;
    }
    !raw.split('/').any(|segment| segment == "..")
}

/// The shape half of the rule: a claim no backend could have minted never reaches storage.
fn admit(claim: &UploadIdClaim) -> Result<&str, UploadRejection> {
    let id = &*claim.raw;
    if could_have_been_minted(id) {
        Ok(id)
    } else {
        Err(UploadRejection::no_such_upload())
    }
}

/// The ownership half of the rule: an absent record and a record owned by another bucket or key
/// are the same refusal, and only a byte-for-byte match yields a resolved id.
fn settle<'a, R: RecordedUpload>(
    id: &'a str,
    record: Option<R>,
    bucket: &BucketName,
    key: &ObjectKey,
) -> Result<(ResolvedUploadId<'a>, R), UploadRejection> {
    let Some(record) = record else {
        return Err(UploadRejection::no_such_upload());
    };
    if UPLOAD_ID_REQUIRES_BUCKET_AND_KEY && (record.bucket() != bucket.as_str() || record.key() != key.as_str()) {
        return Err(UploadRejection::no_such_upload());
    }
    Ok((ResolvedUploadId { id }, record))
}

/// Exchanges an upload-id claim for the right to act on the upload it names.
///
/// The shape is checked before storage is consulted. A well-shaped id is looked up exactly once,
/// then the recorded bucket and key are compared byte-for-byte with the request. Every refusal is
/// the same [`UploadRejection`] so callers cannot use the response to discover whether a guessed
/// id exists. [`resolve_upload_async`] applies the same rule to an asynchronous, fallible lookup.
///
/// # Errors
///
/// Returns [`UploadRejection`] for an impossible shape, an absent record, or either ownership
/// mismatch.
pub fn resolve_upload<'a, R, L>(
    claim: &'a UploadIdClaim,
    bucket: &BucketName,
    key: &ObjectKey,
    lookup: L,
) -> Result<(ResolvedUploadId<'a>, R), UploadRejection>
where
    R: RecordedUpload,
    L: FnOnce(&str) -> Option<R>,
{
    let id = admit(claim)?;
    settle(id, lookup(id), bucket, key)
}

/// The asynchronous form of [`resolve_upload`], for a backend whose lookup awaits storage and can
/// fail.
///
/// The rule is the synchronous one, shared rather than restated: the shape is checked before the
/// lookup is called, the lookup is called and awaited at most once, and the recorded bucket and
/// key are compared byte-for-byte with the request. Nothing is spawned; the returned future is
/// driven by the caller's runtime.
///
/// The lookup's own failure is a separate channel. The outer `Err(E)` is the caller's error,
/// returned unchanged: it is never folded into [`UploadRejection`] and never read as an absent
/// record, so a storage outage cannot be answered as `NoSuchUpload`. The inner result is exactly
/// what [`resolve_upload`] returns.
///
/// # Errors
///
/// Returns `Err(E)` when the lookup fails, and `Ok(Err(UploadRejection))` for an impossible shape,
/// an absent record, or either ownership mismatch.
pub async fn resolve_upload_async<'a, R, E, L, Fut>(
    claim: &'a UploadIdClaim,
    bucket: &BucketName,
    key: &ObjectKey,
    lookup: L,
) -> Result<Result<(ResolvedUploadId<'a>, R), UploadRejection>, E>
where
    R: RecordedUpload,
    L: FnOnce(&'a str) -> Fut,
    Fut: Future<Output = Result<Option<R>, E>>,
{
    let id = match admit(claim) {
        Ok(id) => id,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let record = lookup(id).await?;
    Ok(settle(id, record, bucket, key))
}
