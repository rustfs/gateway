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

//! The one transition from an S3 failure situation to its observable response shape.
//!
//! Responsible for: authorization masking, contextual status selection, bounded error text,
//! code-to-extra compatibility, and body suppression as one ordered decision.
//! NOT responsible for: XML serialization, connection teardown, or deciding which operation fact
//! occurred. Upstream supplies a named [`ErrorContext`]; the facade consumes [`ErrorResolution`].
//! Upstream: handlers, codecs, authorization and operation helpers. Downstream: the gateway facade.

use std::borrow::Cow;
use std::fmt;

use http::StatusCode;
use rustfs_gateway_types::{BucketName, ETag, ErrorCode, ObjectKey, is_xml_representable};

use crate::ops::shared::bucket_region::{PERMANENT_REDIRECT_MESSAGE, TEMPORARY_REDIRECT_MESSAGE};
use crate::{CodecError, ErrorDetail, ErrorHeader, HandlerError, HttpDate, RedirectTarget, RegionLabel, VersionIdLabel};

mod legacy;
mod validate;

pub use legacy::{LegacyRustfsFacts, LegacyRustfsRefusal};
use validate::{is_contextual, valid_identifier, validate_code, validate_extras, validate_message};

const MAX_CODE_BYTES: usize = 128;
const MAX_MESSAGE_BYTES: usize = 1024;
const MAX_KEY_BYTES: usize = 1024;
const MAX_BUCKET_BYTES: usize = 63;
const MAX_RANGE_BYTES: usize = 16 * 1024;
const MAX_RESOURCE_BYTES: usize = 128;
const CORS_FORBIDDEN_MESSAGE: &str = "CORSResponse: no CORS rule allows this request";
const AUTHORIZATION_SCOPE_MESSAGE: &str = "The authorization header is malformed; the region is wrong.";

/// Which absent object identity the backend looked up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingObject {
    /// The current key.
    Key,
    /// One explicit version of the key.
    Version,
}

/// Whether the caller may learn that an object identity is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceVisibility {
    /// The caller lacks ListBucket and must see `AccessDenied`.
    Hidden,
    /// The caller may see the precise missing-object code.
    Visible,
}

/// The response-method fact that can only suppress a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseKind {
    /// A `HEAD` response: status and permitted headers only.
    Head,
    /// Every non-`HEAD` response.
    Other,
}

/// Whether the facade may render an error document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyPolicy {
    /// No body and therefore no body framing headers.
    None,
    /// Render the canonical `<Error>` document.
    ErrorDocument,
}

/// Why an unresolved error description could not enter the closed resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidErrorContext {
    /// The code needs a named constructor carrying additional facts.
    ContextRequired,
    /// An unknown custom code is not a bounded ASCII identifier.
    InvalidCode,
    /// A delete-marker outcome did not carry a non-empty, bounded, visible-ASCII version id.
    InvalidVersionId,
    /// The instant a delete-marker refusal would report cannot be rendered as a `Last-Modified`.
    InvalidLastModified,
    /// The message is too long or is not XML 1.0 text.
    InvalidMessage,
    /// A detail is too long, malformed, or paired with the wrong code.
    InvalidDetail,
    /// A resolution-owned header or detail was supplied through the ordinary path.
    ReservedExtra,
}

impl fmt::Display for InvalidErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ContextRequired => "the error code requires a named resolution context",
            Self::InvalidCode => "the custom error code is not a bounded identifier",
            Self::InvalidVersionId => "the version id is empty, oversized, or not visible ASCII",
            Self::InvalidLastModified => "the instant is outside the range Last-Modified can express",
            Self::InvalidMessage => "the error message is oversized or not XML text",
            Self::InvalidDetail => "an error detail is malformed or incompatible with its code",
            Self::ReservedExtra => "a resolution-owned extra was supplied through the ordinary path",
        };
        f.write_str(message)
    }
}

impl std::error::Error for InvalidErrorContext {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ErrorCase {
    Ordinary(HandlerError),
    Codec(CodecError),
    MissingObject(MissingObject, ResourceVisibility, Option<ObjectKey>),
    DeleteMissingKey,
    MissingBucket,
    ForeignBucket,
    PermanentRedirect(Option<BucketName>, RegionLabel),
    TemporaryRedirect(RegionLabel, RedirectTarget),
    OwnedBucketRecreation,
    /// The marker's version id is `None` once a copy restricted it (`copy_source_marker`).
    VersionedDeleteMarker(Option<VersionIdLabel>, HttpDate),
    CurrentDeleteMarker(ResourceVisibility, Option<ObjectKey>, Option<VersionIdLabel>, HttpDate),
    AuthorizationScopeMalformed,
    AuthorizationRegionMismatch(RegionLabel),
    NotModified(ETag),
    CorsForbidden,
    /// The RustFS profile's refusal, stated exactly as legacy RustFS writes it (`legacy`).
    Legacy(LegacyRustfsRefusal),
}

/// A closed description of the facts that choose an S3 response shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorContext(ErrorCase);

impl ErrorContext {
    /// Validates a context-free handler refusal before it reaches resolution.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the code needs contextual facts, text is unbounded or invalid,
    /// or an extra is incompatible with the code.
    pub fn ordinary(error: HandlerError) -> Result<Self, InvalidErrorContext> {
        let error = match error.into_context() {
            Ok(context) => return Ok(context),
            Err(error) => error,
        };
        validate_code(error.code())?;
        if is_contextual(error.code()) {
            return Err(InvalidErrorContext::ContextRequired);
        }
        validate_message(error.message())?;
        validate_extras(&error)?;
        Ok(Self(ErrorCase::Ordinary(error)))
    }

    /// Validates a codec refusal and its optional compile-time model-member resource.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the code, message or resource is not admitted.
    pub fn codec(error: CodecError) -> Result<Self, InvalidErrorContext> {
        validate_code(error.code())?;
        if is_contextual(error.code()) {
            return Err(InvalidErrorContext::ContextRequired);
        }
        validate_message(error.message())?;
        if let Some(resource) = error.member()
            && !valid_identifier(resource, MAX_RESOURCE_BYTES, Some(b'_'))
        {
            return Err(InvalidErrorContext::InvalidDetail);
        }
        Ok(Self(ErrorCase::Codec(error)))
    }

    /// A missing key or version, with the visibility fact that prevents existence disclosure.
    #[must_use]
    pub const fn missing_object(kind: MissingObject, visibility: ResourceVisibility) -> Self {
        Self(ErrorCase::MissingObject(kind, visibility, None))
    }

    /// A missing key or version that retains its validated key only when visibility permits it.
    #[must_use]
    pub fn missing_object_for(key: ObjectKey, kind: MissingObject, visibility: ResourceVisibility) -> Self {
        Self(ErrorCase::MissingObject(kind, visibility, Some(key)))
    }

    /// DeleteObject found the bucket and no current key, which is an empty `204` success.
    #[must_use]
    pub const fn delete_missing_key() -> Self {
        Self(ErrorCase::DeleteMissingKey)
    }

    /// The addressed bucket does not exist.
    #[must_use]
    pub const fn missing_bucket() -> Self {
        Self(ErrorCase::MissingBucket)
    }

    /// The bucket exists but belongs to another account and is therefore hidden.
    #[must_use]
    pub const fn foreign_bucket() -> Self {
        Self(ErrorCase::ForeignBucket)
    }

    /// A permanent bucket-region redirect.
    #[must_use]
    pub fn permanent_redirect(region: RegionLabel) -> Self {
        Self(ErrorCase::PermanentRedirect(None, region))
    }

    /// A permanent redirect that retains the validated bucket name in the error document.
    #[must_use]
    pub fn permanent_redirect_for(bucket: BucketName, region: RegionLabel) -> Self {
        Self(ErrorCase::PermanentRedirect(Some(bucket), region))
    }

    /// A temporary endpoint redirect while bucket DNS propagates.
    #[must_use]
    pub fn temporary_redirect(region: RegionLabel, target: RedirectTarget) -> Self {
        Self(ErrorCase::TemporaryRedirect(region, target))
    }

    /// CreateBucket found a bucket already owned by the caller.
    #[must_use]
    pub const fn owned_bucket_recreation() -> Self {
        Self(ErrorCase::OwnedBucketRecreation)
    }

    /// A version-specific read selected a delete marker.
    ///
    /// `last_modified` is when that marker was written, in Unix seconds. AWS answers it on this
    /// refusal, and it is what lets a client tell the marker it just created from an older one.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the version id is not a [`VersionIdLabel`], or when the instant
    /// falls outside the range `Last-Modified` can express.
    pub fn versioned_delete_marker(version_id: &str, last_modified: i64) -> Result<Self, InvalidErrorContext> {
        let (version_id, at) = marker_facts(version_id, last_modified)?;
        Ok(Self(ErrorCase::VersionedDeleteMarker(Some(version_id), at)))
    }

    /// A read that named no version found a delete marker as the current version.
    ///
    /// The same backend fact as [`Self::versioned_delete_marker`] and a different answer: without a
    /// version id the object simply is not there, so this is the `404` a reader expects — carrying
    /// the marker header, so a client can tell "deleted" from "never written".
    ///
    /// `visibility` is the same question [`Self::missing_object`] asks, and it has to be asked here
    /// too: to a caller who may not list the bucket, "there is a deletion recorded at this key" is
    /// strictly more than "there is nothing here", so the marker header would be a better existence
    /// oracle than the `404` it rides on. A hidden resource is answered `AccessDenied` with no
    /// header and no instant.
    ///
    /// The version id is validated whatever the visibility, so a hidden refusal is not a way to pass
    /// one that could not be rendered.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the version id is not a [`VersionIdLabel`], or when the instant
    /// falls outside the range `Last-Modified` can express.
    pub fn current_delete_marker(
        visibility: ResourceVisibility,
        key: Option<ObjectKey>,
        version_id: &str,
        last_modified: i64,
    ) -> Result<Self, InvalidErrorContext> {
        let (version_id, at) = marker_facts(version_id, last_modified)?;
        Ok(Self(ErrorCase::CurrentDeleteMarker(visibility, key, Some(version_id), at)))
    }

    /// A signing credential named a region other than the bucket's bounded region.
    #[must_use]
    pub fn authorization_region_mismatch(region: RegionLabel) -> Self {
        Self(ErrorCase::AuthorizationRegionMismatch(region))
    }

    /// A signing credential's date or service scope disagreed without a region remediation.
    #[must_use]
    pub const fn authorization_scope_malformed() -> Self {
        Self(ErrorCase::AuthorizationScopeMalformed)
    }

    /// A read precondition matched the current entity tag.
    #[must_use]
    pub fn not_modified(etag: ETag) -> Self {
        Self(ErrorCase::NotModified(etag))
    }

    /// A CORS preflight matched no rule.
    #[must_use]
    pub const fn cors_forbidden() -> Self {
        Self(ErrorCase::CorsForbidden)
    }

    /// A refusal exactly as legacy RustFS writes it, for the RustFS profile (rustfs/gateway#1148).
    #[must_use]
    pub fn legacy_rustfs(refusal: LegacyRustfsRefusal) -> Self {
        Self(ErrorCase::Legacy(refusal))
    }

    /// A marker refusal a copy answers for its source, without the marker's version id: on a copy,
    /// `x-amz-version-id` names the version the copy wrote. Every other context is unchanged.
    fn copy_source_marker(self) -> Self {
        match self.0 {
            ErrorCase::VersionedDeleteMarker(_, at) => Self(ErrorCase::VersionedDeleteMarker(None, at)),
            ErrorCase::CurrentDeleteMarker(visibility, key, _, at) => {
                Self(ErrorCase::CurrentDeleteMarker(visibility, key, None, at))
            }
            ErrorCase::Legacy(refusal) => Self(ErrorCase::Legacy(refusal.without_marker_version())),
            other => Self(other),
        }
    }

    fn hide_missing_object(self) -> Self {
        match self.0 {
            ErrorCase::MissingObject(kind, _, _) => Self(ErrorCase::MissingObject(kind, ResourceVisibility::Hidden, None)),
            ErrorCase::CurrentDeleteMarker(_, _, _, at) => {
                Self(ErrorCase::CurrentDeleteMarker(ResourceVisibility::Hidden, None, None, at))
            }
            // A legacy missing object, a current delete marker included, is hidden exactly as the
            // typed ones are: the caller learns nothing the gateway would not tell it.
            ErrorCase::Legacy(refusal) => match refusal.missing_object() {
                Some(kind) => Self(ErrorCase::MissingObject(kind, ResourceVisibility::Hidden, None)),
                None => Self(ErrorCase::Legacy(refusal)),
            },
            other => Self(other),
        }
    }
}

/// A closed context that an authenticated operation handler may return as a [`HandlerError`].
///
/// Its field is private and it deliberately has no generic constructor or conversion from
/// [`ErrorContext`]. In particular, the two authorization-scope contexts are absent: only the
/// built-in verifier may attach trusted remediation metadata to an authentication refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerErrorContext(ErrorContext);

impl HandlerErrorContext {
    /// A missing key or version, with the visibility fact that prevents existence disclosure.
    #[must_use]
    pub const fn missing_object(kind: MissingObject, visibility: ResourceVisibility) -> Self {
        Self(ErrorContext::missing_object(kind, visibility))
    }

    /// A missing key or version that retains its validated key only when visibility permits it.
    #[must_use]
    pub fn missing_object_for(key: ObjectKey, kind: MissingObject, visibility: ResourceVisibility) -> Self {
        Self(ErrorContext::missing_object_for(key, kind, visibility))
    }

    /// DeleteObject found the bucket and no current key, which is an empty `204` success.
    #[must_use]
    pub const fn delete_missing_key() -> Self {
        Self(ErrorContext::delete_missing_key())
    }

    /// The addressed bucket does not exist.
    #[must_use]
    pub const fn missing_bucket() -> Self {
        Self(ErrorContext::missing_bucket())
    }

    /// The bucket exists but belongs to another account and is therefore hidden.
    #[must_use]
    pub const fn foreign_bucket() -> Self {
        Self(ErrorContext::foreign_bucket())
    }

    /// A permanent bucket-region redirect.
    #[must_use]
    pub fn permanent_redirect(region: RegionLabel) -> Self {
        Self(ErrorContext::permanent_redirect(region))
    }

    /// A permanent redirect that retains the validated bucket name in the error document.
    #[must_use]
    pub fn permanent_redirect_for(bucket: BucketName, region: RegionLabel) -> Self {
        Self(ErrorContext::permanent_redirect_for(bucket, region))
    }

    /// A temporary endpoint redirect while bucket DNS propagates.
    #[must_use]
    pub fn temporary_redirect(region: RegionLabel, target: RedirectTarget) -> Self {
        Self(ErrorContext::temporary_redirect(region, target))
    }

    /// CreateBucket found a bucket already owned by the caller.
    #[must_use]
    pub const fn owned_bucket_recreation() -> Self {
        Self(ErrorContext::owned_bucket_recreation())
    }

    /// A version-specific read selected a delete marker.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the version id is not a [`VersionIdLabel`], or when the instant
    /// falls outside the range `Last-Modified` can express.
    pub fn versioned_delete_marker(version_id: &str, last_modified: i64) -> Result<Self, InvalidErrorContext> {
        ErrorContext::versioned_delete_marker(version_id, last_modified).map(Self)
    }

    /// A read that named no version found a delete marker, `version_id`, as the current version.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the version id is not a [`VersionIdLabel`], or when the instant
    /// falls outside the range `Last-Modified` can express.
    pub fn current_delete_marker(
        visibility: ResourceVisibility,
        key: Option<ObjectKey>,
        version_id: &str,
        last_modified: i64,
    ) -> Result<Self, InvalidErrorContext> {
        ErrorContext::current_delete_marker(visibility, key, version_id, last_modified).map(Self)
    }

    /// A read precondition matched the current entity tag.
    #[must_use]
    pub fn not_modified(etag: ETag) -> Self {
        Self(ErrorContext::not_modified(etag))
    }

    /// A refusal exactly as legacy RustFS writes it: the RustFS profile's answer for an error a
    /// RustFS app body returned (rustfs/gateway#1148). Every other deployment answers with the
    /// typed contexts above.
    #[must_use]
    pub fn legacy_rustfs(refusal: LegacyRustfsRefusal) -> Self {
        Self(ErrorContext::legacy_rustfs(refusal))
    }

    pub(crate) fn into_error_context(self) -> ErrorContext {
        self.0
    }

    pub(crate) fn copy_source_marker(self) -> Self {
        Self(self.0.copy_source_marker())
    }

    pub(crate) fn hide_missing_object(self) -> Self {
        Self(self.0.hide_missing_object())
    }
}

/// The complete, read-only response facts selected by [`resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorResolution {
    status: StatusCode,
    code: Option<ErrorCode>,
    body_policy: BodyPolicy,
    message: Option<Cow<'static, str>>,
    headers: Vec<ErrorHeader>,
    details: Vec<ErrorDetail>,
    etag: Option<ETag>,
    resource: Option<Box<str>>,
}

impl ErrorResolution {
    /// The selected HTTP status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The public error code, absent for successful outcomes.
    #[must_use]
    pub const fn code(&self) -> Option<&ErrorCode> {
        self.code.as_ref()
    }

    /// Whether the facade may render an error document.
    #[must_use]
    pub const fn body_policy(&self) -> BodyPolicy {
        self.body_policy
    }

    /// The bounded client-facing message.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The closed response headers selected by resolution.
    #[must_use]
    pub fn headers(&self) -> &[ErrorHeader] {
        &self.headers
    }

    /// The closed document details selected by resolution.
    #[must_use]
    pub fn details(&self) -> &[ErrorDetail] {
        &self.details
    }

    /// The entity tag carried by a `304` response.
    #[must_use]
    pub const fn etag(&self) -> Option<&ETag> {
        self.etag.as_ref()
    }

    /// The validated model-member resource, when a codec refusal names one.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
}

/// Resolves one validated context in the only permitted order.
#[must_use]
pub fn resolve(context: ErrorContext, response: ResponseKind) -> ErrorResolution {
    let mut resolution = match context.0 {
        ErrorCase::Ordinary(error) => ordinary_resolution(error, None),
        ErrorCase::Codec(error) => {
            let resource = error.member().map(Box::<str>::from);
            ordinary_parts(error.code().clone(), error.message().into(), Vec::new(), Vec::new(), resource)
        }
        ErrorCase::MissingObject(kind, visibility, key) => {
            let code = match visibility {
                ResourceVisibility::Hidden => ErrorCode::ACCESS_DENIED,
                ResourceVisibility::Visible => match kind {
                    MissingObject::Key => ErrorCode::NO_SUCH_KEY,
                    MissingObject::Version => ErrorCode::NO_SUCH_VERSION,
                },
            };
            // AWS's own sentence, because `conformance/cases/object/c-object-0007.toml` asserts the
            // whole document byte for byte: this is observable API surface, not internal prose. The
            // version arm keeps the neutral sentence — no case pins `NoSuchVersion`'s wording, and
            // inventing one from memory is how the key arm came to be reworded in the first place.
            let message = match (visibility, kind) {
                (ResourceVisibility::Hidden, _) => "the request is not allowed",
                (ResourceVisibility::Visible, MissingObject::Key) => "The specified key does not exist.",
                (ResourceVisibility::Visible, MissingObject::Version) => "the requested object does not exist",
            };
            let details = match (visibility, key) {
                (ResourceVisibility::Visible, Some(key)) if is_xml_representable(key.as_str()) => {
                    vec![ErrorDetail::Key(Cow::Owned(key.as_str().to_owned()))]
                }
                (ResourceVisibility::Hidden, _) | (ResourceVisibility::Visible, _) => Vec::new(),
            };
            ordinary_parts(code, Cow::Borrowed(message), Vec::new(), details, None)
        }
        ErrorCase::DeleteMissingKey => success(StatusCode::NO_CONTENT),
        ErrorCase::MissingBucket => ordinary_parts(
            ErrorCode::NO_SUCH_BUCKET,
            // Pinned byte-exactly by `c-cors-0025` and `c-lock-0029`; see the key arm above.
            Cow::Borrowed("The specified bucket does not exist"),
            Vec::new(),
            Vec::new(),
            None,
        ),
        ErrorCase::ForeignBucket => ordinary_parts(
            ErrorCode::ACCESS_DENIED,
            Cow::Borrowed("the request is not allowed"),
            Vec::new(),
            Vec::new(),
            None,
        ),
        ErrorCase::PermanentRedirect(bucket, region) => {
            let mut details = Vec::with_capacity(usize::from(bucket.is_some()) + 1);
            if let Some(bucket) = bucket {
                details.push(ErrorDetail::BucketName(Cow::Owned(bucket.as_str().to_owned())));
            }
            details.push(ErrorDetail::Region(region.clone()));
            ordinary_parts(
                ErrorCode::PERMANENT_REDIRECT,
                Cow::Borrowed(PERMANENT_REDIRECT_MESSAGE),
                vec![ErrorHeader::BucketRegion { region }],
                details,
                None,
            )
        }
        ErrorCase::TemporaryRedirect(region, target) => ordinary_parts(
            ErrorCode::TEMPORARY_REDIRECT,
            Cow::Borrowed(TEMPORARY_REDIRECT_MESSAGE),
            vec![
                ErrorHeader::RedirectLocation { target },
                ErrorHeader::BucketRegion { region: region.clone() },
            ],
            vec![ErrorDetail::Region(region)],
            None,
        ),
        ErrorCase::OwnedBucketRecreation => ordinary_parts(
            ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU,
            Cow::Borrowed("Your previous request to create the named bucket succeeded and you already own it."),
            Vec::new(),
            Vec::new(),
            None,
        ),
        // The two answers one backend fact gets. A read that named the marker's version id is told
        // the version is there and this method cannot produce bytes for it; a read that named no
        // version is told the object is not there. Both carry the marker header, because that is
        // the only thing on the wire that separates a deletion from a key that never existed, and
        // both carry the marker's version id and the instant, because a client deciding whether to
        // remove the marker needs both.
        ErrorCase::VersionedDeleteMarker(version_id, at) => ordinary_parts(
            ErrorCode::METHOD_NOT_ALLOWED,
            Cow::Borrowed("The specified method is not allowed against this resource."),
            marker_headers(version_id, at),
            Vec::new(),
            None,
        ),
        // A caller who may not list the bucket learns nothing here, not even that the key was once
        // written: the marker header on a 404 would say "a deletion is recorded at this key", which
        // is a sharper existence oracle than the status it rides on.
        ErrorCase::CurrentDeleteMarker(ResourceVisibility::Hidden, _, _, _) => ordinary_parts(
            ErrorCode::ACCESS_DENIED,
            Cow::Borrowed("the request is not allowed"),
            Vec::new(),
            Vec::new(),
            None,
        ),
        ErrorCase::CurrentDeleteMarker(ResourceVisibility::Visible, key, version_id, at) => {
            let details = match key {
                Some(key) if is_xml_representable(key.as_str()) => {
                    vec![ErrorDetail::Key(Cow::Owned(key.as_str().to_owned()))]
                }
                _ => Vec::new(),
            };
            ordinary_parts(
                ErrorCode::NO_SUCH_KEY,
                Cow::Borrowed("The specified key does not exist."),
                marker_headers(version_id, at),
                details,
                None,
            )
        }
        ErrorCase::AuthorizationScopeMalformed => ordinary_parts(
            ErrorCode::AUTHORIZATION_HEADER_MALFORMED,
            Cow::Borrowed(AUTHORIZATION_SCOPE_MESSAGE),
            Vec::new(),
            Vec::new(),
            None,
        ),
        ErrorCase::AuthorizationRegionMismatch(region) => ordinary_parts(
            ErrorCode::AUTHORIZATION_HEADER_MALFORMED,
            Cow::Borrowed(AUTHORIZATION_SCOPE_MESSAGE),
            Vec::new(),
            vec![ErrorDetail::Region(region)],
            None,
        ),
        ErrorCase::NotModified(etag) => ErrorResolution {
            status: StatusCode::NOT_MODIFIED,
            code: Some(ErrorCode::NOT_MODIFIED),
            body_policy: BodyPolicy::None,
            message: None,
            headers: Vec::new(),
            details: Vec::new(),
            etag: Some(etag),
            resource: None,
        },
        ErrorCase::CorsForbidden => ordinary_parts(
            ErrorCode::ACCESS_FORBIDDEN,
            Cow::Borrowed(CORS_FORBIDDEN_MESSAGE),
            Vec::new(),
            Vec::new(),
            None,
        ),
        ErrorCase::Legacy(refusal) => refusal.resolution(),
    };

    if response == ResponseKind::Head
        || resolution.status == StatusCode::NO_CONTENT
        || resolution.status == StatusCode::NOT_MODIFIED
    {
        resolution.body_policy = BodyPolicy::None;
    }
    resolution
}

fn success(status: StatusCode) -> ErrorResolution {
    ErrorResolution {
        status,
        code: None,
        body_policy: BodyPolicy::None,
        message: None,
        headers: Vec::new(),
        details: Vec::new(),
        etag: None,
        resource: None,
    }
}

fn ordinary_resolution(error: HandlerError, resource: Option<Box<str>>) -> ErrorResolution {
    ordinary_parts(
        error.code().clone(),
        Cow::Owned(error.message().to_owned()),
        error.headers().to_vec(),
        error.details().to_vec(),
        resource,
    )
}

/// The two facts both delete-marker constructors validate, in one place so they cannot disagree.
fn marker_facts(version_id: &str, last_modified: i64) -> Result<(VersionIdLabel, HttpDate), InvalidErrorContext> {
    let version_id = VersionIdLabel::new(version_id).map_err(|_| InvalidErrorContext::InvalidVersionId)?;
    let at = HttpDate::from_unix_seconds(last_modified).map_err(|_| InvalidErrorContext::InvalidLastModified)?;
    Ok((version_id, at))
}

/// The head both visible delete-marker refusals carry; a copy's carries no version id.
fn marker_headers(version_id: Option<VersionIdLabel>, at: HttpDate) -> Vec<ErrorHeader> {
    let version_id = version_id.map(|version_id| ErrorHeader::VersionId { version_id });
    [
        Some(ErrorHeader::DeleteMarker),
        version_id,
        Some(ErrorHeader::LastModified { at }),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn ordinary_parts(
    code: ErrorCode,
    message: Cow<'static, str>,
    headers: Vec<ErrorHeader>,
    details: Vec<ErrorDetail>,
    resource: Option<Box<str>>,
) -> ErrorResolution {
    ErrorResolution {
        status: code.default_status(),
        code: Some(code),
        body_policy: BodyPolicy::ErrorDocument,
        message: Some(message),
        headers,
        details,
        etag: None,
        resource,
    }
}
