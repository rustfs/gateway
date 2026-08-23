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

//! `x-amz-copy-source`: the one parser, and the authorization stage its result cannot skip.
//!
//! Shares: copy_source
//! Members: CopyObject, UploadPartCopy
//!
//! Responsible for: the three grammars the header admits, the order its version suffix is split
//! off in, the second authorization stage the header creates, the self-copy question, and the
//! stricter range rule a copied span is held to — including the one place that rule parts company
//! with `rustfs-gateway-types`' own resolution, see [`resolve_copy_range`].
//! NOT responsible for: reading the header off the request (the generated decoder), evaluating the
//! four copy-source conditions ([`super::precondition`] does that against the source's validators),
//! comparing an entity tag ([`super::etag`]), deciding whether the caller may read the source (an
//! authorizer supplies that verdict; this module only refuses to proceed without it), and copying
//! any bytes.
//! Upstream: `rustfs-gateway-types`' `BucketName`, `ObjectKey`, `RangeParse` and `ErrorCode`.
//! Downstream: [`crate::ops::copy_object`] and [`crate::ops::upload_part_copy`].
//! # Why the source is a type state rather than a check
//!
//! The copy source names a *second* resource, and the caller chose it. Authorizing the destination
//! and not the source is how an attacker with write access to a bucket of their own reads an object
//! they were never granted — the shape of GHSA-mx42 and GHSA-wfxj, where a part copy authorized the
//! upload and not the object it copied from.
//!
//! The rejected alternative was a `check_source_permission()` call in each handler. It has no type
//! relationship to anything, so omitting it compiles, and both advisories are exactly that
//! omission. Here [`CopySourceResources`] is derived before input authorization, dispatch accepts
//! only [`crate::Authorized`], and [`CopySource::resolve`] requires the [`crate::AuthorizedRead`]
//! proof carried by the resulting handler request. The normalized value policy saw is the value
//! storage receives.
//! # Why the version suffix is split before anything is decoded
//!
//! `bucket/a%3Fb?versionId=v1` names the key `a?b` in version `v1`. Decode first and the header
//! becomes `bucket/a?b?versionId=v1`, where no split rule recovers the original: the key's own
//! question mark is now indistinguishable from the separator. So the split happens on the raw
//! bytes, at the last `?`, and each half is decoded afterwards — `q-copy-source-split-0077`.

use percent_encoding::percent_decode_str;
use rustfs_gateway_types::{BucketName, ByteRange, ErrorCode, ObjectKey, RangeParse};

use crate::contracts::{COPY_RANGE_LENGTH_ARITHMETIC, CopyRangeLengthArithmetic};

/// Which of the three grammars a copy-source value was written in.
///
/// The form is kept after parsing because it decides the resource an authorizer writes its policy
/// against: an access point is not the bucket behind it, and an Outposts bucket is not an S3 one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CopySourceForm {
    /// `bucket/key`, with or without a leading slash.
    Path,
    /// `arn:<partition>:s3:<region>:<account>:accesspoint/<name>/object/<key>`.
    AccessPointArn,
    /// `arn:<partition>:s3-outposts:<region>:<account>:outpost/<id>/bucket/<bucket>/object/<key>`.
    OutpostsArn,
}

/// A copy-source value this gateway refuses, with the code it is rendered as.
///
/// The explanation is a `&'static str` chosen from a fixed set. A message assembled from the
/// rejected value would echo a caller-controlled string — including, on this header, the name of a
/// bucket the caller may have no right to learn the existence of — into an error document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySourceRejection {
    code: ErrorCode,
    reason: &'static str,
}

impl CopySourceRejection {
    /// The S3 error code to render.
    #[must_use]
    pub fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// A constant explanation, never built from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Builds a rejection. Private so the set of reasons stays enumerable by reading this file.
    const fn new(code: ErrorCode, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

/// What an authorizer needs in order to decide whether the caller may read the source.
///
/// Deliberately readable without a proof: this is the value the authorization stage is *given*, and
/// a resource nobody can read is a resource nobody can authorize. What stays unreadable is
/// [`ResolvedCopySource`], the value the copy itself is performed against.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceResource {
    form: CopySourceForm,
    /// The access point name, or the Outposts bucket's outpost id. `None` for the path form.
    container: Option<String>,
    identity: crate::ResourceIdentity,
    bucket: BucketName,
    key: ObjectKey,
    version_id: Option<String>,
}

impl SourceResource {
    /// The access point name or outpost id an ARN named, when there was one.
    #[cfg(test)]
    #[must_use]
    fn container(&self) -> Option<&str> {
        self.container.as_deref()
    }

    /// The source bucket.
    #[cfg(test)]
    #[must_use]
    const fn bucket(&self) -> &BucketName {
        &self.bucket
    }
}

/// A parsed but unauthorized copy source.
///
/// The bucket and the key are private and there is no accessor for them. The derived resource view
/// hands the authorizer what it needs; [`CopySource::resolve`] is the only way to the value a copy
/// can be performed against, and it consumes `self` so the unauthorized form cannot be kept around
/// beside the authorized one.
#[derive(Clone, PartialEq, Eq)]
pub struct CopySource {
    resource: SourceResource,
}

impl CopySource {
    /// Parses one `x-amz-copy-source` header value.
    ///
    /// The order is fixed and is the point of the function: the optional `?versionId=` suffix is
    /// split off the **raw** value at its last `?`, and only then is each half percent-decoded.
    ///
    /// # Errors
    ///
    /// Returns a [`CopySourceRejection`] with `InvalidArgument` for an empty value, a value naming
    /// no key, a suffix after the last `?` that is not a version, percent-encoded bytes that are
    /// not UTF-8, and any ARN that is neither of the two S3 forms. An unrecognised ARN is never
    /// demoted to a bucket name: `arn:aws:iam::1:user/bob` would otherwise address a bucket
    /// literally called `arn:aws:iam::1:user`.
    pub fn parse(raw: &str) -> Result<Self, CopySourceRejection> {
        if raw.is_empty() {
            return Err(CopySourceRejection::new(
                ErrorCode::INVALID_ARGUMENT,
                "x-amz-copy-source must name a source object",
            ));
        }

        let (path, version_id) = split_version(raw)?;

        let resource = if path.starts_with("arn:") {
            parse_arn(path)?
        } else {
            parse_path(path)?
        };

        Ok(Self {
            resource: SourceResource { version_id, ..resource },
        })
    }

    /// The grammar the header was written in.
    #[must_use]
    pub const fn form(&self) -> CopySourceForm {
        self.resource.form
    }

    /// Reveals the normalized source only after the framework authorized every derived resource.
    #[must_use]
    pub fn resolve(&self, proof: &crate::AuthorizedRead) -> Option<ResolvedCopySource> {
        proof
            .permits(crate::ResourceRef::copy_source(
                if self.resource.version_id.is_some() {
                    "s3:GetObjectVersion"
                } else {
                    "s3:GetObject"
                },
                &self.resource.bucket,
                &self.resource.key,
                &self.resource.identity,
                self.resource.version_id.as_deref(),
            ))
            .then(|| ResolvedCopySource {
                resource: self.resource.clone(),
            })
    }
}

/// The single normalized source resource derived by either copy operation.
#[derive(Clone, PartialEq, Eq)]
pub struct CopySourceResources {
    source: CopySource,
}

impl CopySourceResources {
    pub(crate) fn parse(raw: &str) -> Result<Self, crate::DerivedResourceError> {
        CopySource::parse(raw)
            .map(|source| Self { source })
            .map_err(|error| crate::DerivedResourceError::new(error.code().clone(), error.reason()))
    }

    /// The sealed source. Its bucket and key require [`crate::AuthorizedRead`] to reveal.
    #[must_use]
    pub const fn source(&self) -> &CopySource {
        &self.source
    }
}

impl crate::DerivedResourceSet for CopySourceResources {
    fn visit(&self, visitor: &mut dyn FnMut(crate::ResourceRef<'_>)) {
        visitor(crate::ResourceRef::copy_source(
            if self.source.resource.version_id.is_some() {
                "s3:GetObjectVersion"
            } else {
                "s3:GetObject"
            },
            &self.source.resource.bucket,
            &self.source.resource.key,
            &self.source.resource.identity,
            self.source.resource.version_id.as_deref(),
        ));
    }
}

/// A copy source the caller has been shown to be allowed to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCopySource {
    resource: SourceResource,
}

impl ResolvedCopySource {
    /// The source bucket.
    #[must_use]
    pub const fn bucket(&self) -> &BucketName {
        &self.resource.bucket
    }

    /// The source key.
    #[must_use]
    pub const fn key(&self) -> &ObjectKey {
        &self.resource.key
    }

    /// The requested source version, when the header carried one.
    #[must_use]
    pub fn version_id(&self) -> Option<&str> {
        self.resource.version_id.as_deref()
    }

    /// The grammar the header was written in.
    #[must_use]
    pub const fn form(&self) -> CopySourceForm {
        self.resource.form
    }

    /// Whether this copy addresses the object it is writing to.
    ///
    /// A version suffix makes it a different representation, so a copy of an *old* version onto the
    /// current key is not a self copy even though the key matches. See [`SelfCopy`] for what the
    /// two answers oblige a handler to do.
    #[must_use]
    pub fn is_self_copy(&self, target_bucket: &BucketName, target_key: &ObjectKey) -> bool {
        self.resource.version_id.is_none() && self.resource.bucket == *target_bucket && self.resource.key == *target_key
    }
}

/// What a self copy is allowed to be.
///
/// AWS refuses a copy onto the same object that changes nothing, and documents the metadata-
/// replacing form as the supported way to rewrite an object's metadata in place. Both halves are
/// one decision, so they are one type: a handler that matches on this cannot implement the first
/// rule and forget the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfCopy {
    /// Not a self copy. Ordinary read-then-write.
    No,
    /// A self copy that replaces metadata. Legal, and the destination's bytes must survive it —
    /// the source has to be read before the target is opened for writing, never after
    /// (`q-copy-self-0080`).
    RewriteMetadata,
    /// A self copy that changes nothing. Refused.
    Illegal,
}

/// Classifies a copy against its destination.
///
/// `changes_something` is the handler's answer to "would anything about the stored object differ
/// afterwards?" — a replacing metadata directive, a new storage class, a new encryption state. It
/// is passed in rather than derived because encryption and storage class are other families' fields
/// and this module may not read them.
#[must_use]
pub fn classify_self_copy(
    source: &ResolvedCopySource,
    target_bucket: &BucketName,
    target_key: &ObjectKey,
    changes_something: bool,
) -> SelfCopy {
    if !source.is_self_copy(target_bucket, target_key) {
        return SelfCopy::No;
    }
    if changes_something {
        SelfCopy::RewriteMetadata
    } else {
        SelfCopy::Illegal
    }
}

impl SelfCopy {
    /// The refusal a self copy that changes nothing is answered with, if it is one.
    #[must_use]
    pub fn rejection(self) -> Option<CopySourceRejection> {
        match self {
            Self::No | Self::RewriteMetadata => None,
            Self::Illegal => Some(CopySourceRejection::new(
                ErrorCode::INVALID_REQUEST,
                "a copy onto the same object must change its metadata, storage class or encryption",
            )),
        }
    }
}

/// The span of a source object a part copy will read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyRange {
    /// First byte, inclusive.
    pub start: u64,
    /// Last byte, inclusive.
    pub end_inclusive: u64,
}

impl CopyRange {
    /// The number of bytes the span carries: `end - start + 1`.
    ///
    /// Both positions are inclusive. Dropping the plus one copies a part one byte short, the upload
    /// completes, and the corruption surfaces on a read rather than on the write that caused it.
    #[must_use]
    pub const fn len(&self) -> u64 {
        match COPY_RANGE_LENGTH_ARITHMETIC {
            CopyRangeLengthArithmetic::Inclusive => self.end_inclusive.saturating_sub(self.start).saturating_add(1),
            CopyRangeLengthArithmetic::Exclusive => self.end_inclusive.saturating_sub(self.start),
        }
    }

    /// Whether the span carries no bytes. Never true for a resolved span; present because clippy
    /// asks for it beside [`CopyRange::len`], and a caller reading a length may as well ask.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Resolves `x-amz-copy-source-range` against the source's length.
///
/// Three rules separate this from an ordinary read range, and every one of them is a refusal where
/// a read would have answered:
///
/// - a span running past the end of the source is **not** clamped, it is refused. A read that asks
///   for more than exists is answered with what exists; a copy that silently copies fewer bytes
///   than the client asked for produces a part nobody notices is short. That is why the parse is
///   matched on directly instead of going through [`RangeParse::resolve`], which trims `bytes=0-100`
///   over a ten-byte source to `0-9` the way RFC 9110 §14.2 asks a *read* to.
/// - more than one span is refused. A read answers a multi-range request with the whole object;
///   there is no such fallback for a copy, and picking the first span would be a guess.
/// - a value that is not a byte range at all is refused. RFC 9110 §14.2 has a recipient ignore an
///   unreadable `Range` and serve the whole representation; doing that here copies the entire
///   source under a header that asked for part of it, with a success attached.
///
/// The refusal is `InvalidArgument`, which is what AWS answers for this header: a `416` belongs to a
/// *read* whose window could not be served, and nothing is being served here. The span is a length
/// the client committed the part to, so one the source cannot honour is a bad argument.
///
/// A `None` header copies the whole source, including a source of zero bytes, which resolves to
/// `None` rather than to an empty span — the copy of nothing is a legal copy and must not be an
/// arithmetic edge (`q-copy-range-0085`).
///
/// # Errors
///
/// Returns a [`CopySourceRejection`] with `InvalidArgument` for a multi-range value, for a value
/// the byte-range grammar does not admit, and for any span the source cannot satisfy in full.
pub fn resolve_copy_range(header: Option<&str>, source_len: u64) -> Result<Option<CopyRange>, CopySourceRejection> {
    let Some(header) = header else {
        return Ok(None);
    };
    if header.contains(',') {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "x-amz-copy-source-range accepts one byte span",
        ));
    }
    let RangeParse::One(range) = RangeParse::parse(header) else {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "x-amz-copy-source-range is not a byte range",
        ));
    };
    // A source of zero bytes has no byte a span could name, so every span is outside it. Answered
    // before the arithmetic rather than saturated through it: `last_byte` is what every arm below
    // compares against, and there is no honest value for it here.
    let Some(last_byte) = source_len.checked_sub(1) else {
        return Err(outside_the_source());
    };
    let (start, end_inclusive) = match range {
        // The end is compared as the client wrote it; `last.min(last_byte)` here would be the clamp
        // this function exists to refuse.
        ByteRange::FromTo { first, last } if first <= last_byte && last <= last_byte => (first, last),
        // `bytes=first-` names the end of the source rather than an offset, so it is never short of
        // what was asked for and never clamped.
        ByteRange::From { first } if first <= last_byte => (first, last_byte),
        // A suffix longer than the source is the same clamp in the other spelling: a read answers
        // `bytes=-100` over ten bytes with all ten, and a copy that did would report success for
        // ninety bytes it never wrote.
        ByteRange::Suffix { length } if length > 0 && length <= source_len => (source_len - length, last_byte),
        _ => return Err(outside_the_source()),
    };
    Ok(Some(CopyRange { start, end_inclusive }))
}

/// The one refusal every span the source cannot satisfy in full shares.
///
/// A constant, like every other reason in this module: a message that named the offsets would echo
/// the caller's own header back into an error document.
fn outside_the_source() -> CopySourceRejection {
    CopySourceRejection::new(ErrorCode::INVALID_ARGUMENT, "x-amz-copy-source-range lies outside the source object")
}

/// Splits the version suffix off the raw header value, before anything is decoded.
///
/// The rule is fixed rather than heuristic: the split is at the **last** `?`, and what follows it
/// must be `versionId=<value>`. A suffix that is anything else is refused instead of being folded
/// back into the key, because folding it back makes the same header mean two things depending on
/// whether the value happens to parse.
fn split_version(raw: &str) -> Result<(&str, Option<String>), CopySourceRejection> {
    let Some((path, query)) = raw.rsplit_once('?') else {
        return Ok((raw, None));
    };
    let Some(value) = query.strip_prefix("versionId=") else {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the only query x-amz-copy-source accepts is versionId",
        ));
    };
    let value = decode(value)?;
    if value.is_empty() {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the versionId of x-amz-copy-source must not be empty",
        ));
    }
    Ok((path, Some(value)))
}

/// Parses `bucket/key`, with or without the leading slash AWS also accepts.
///
/// The bucket and the key are separated on the still-encoded value, so a key containing an encoded
/// slash keeps it rather than being cut at a separator the client escaped on purpose.
fn parse_path(path: &str) -> Result<SourceResource, CopySourceRejection> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let Some((bucket, key)) = path.split_once('/') else {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "x-amz-copy-source must name a key as well as a bucket",
        ));
    };
    Ok(SourceResource {
        form: CopySourceForm::Path,
        container: None,
        identity: crate::ResourceIdentity::Path,
        bucket: bucket_of(&decode(bucket)?)?,
        key: key_of(key)?,
        version_id: None,
    })
}

/// Parses the two S3 ARN spellings, and refuses every other ARN.
fn parse_arn(path: &str) -> Result<SourceResource, CopySourceRejection> {
    // arn : partition : service : region : account : resource…, where the resource half itself
    // contains colons in neither form, so five splits is the whole grammar.
    let mut parts = path.splitn(6, ':');
    let (Some(_arn), Some(partition), Some(service), Some(region), Some(account), Some(resource)) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(unknown_arn());
    };

    match service {
        "s3" => {
            let rest = resource.strip_prefix("accesspoint/").ok_or_else(unknown_arn)?;
            let (name, key) = rest.split_once("/object/").ok_or_else(unknown_arn)?;
            Ok(SourceResource {
                form: CopySourceForm::AccessPointArn,
                container: Some(non_empty(name)?.to_owned()),
                identity: crate::ResourceIdentity::AccessPoint {
                    partition: non_empty(partition)?.to_owned(),
                    region: non_empty(region)?.to_owned(),
                    account: non_empty(account)?.to_owned(),
                    name: non_empty(name)?.to_owned(),
                },
                // An access point is addressed by name; the bucket behind it is resolved by the
                // control plane, so the name is what an authorizer writes its resource against and
                // what stands in for the bucket until then.
                bucket: bucket_of(name)?,
                key: key_of(key)?,
                version_id: None,
            })
        }
        "s3-outposts" => {
            let rest = resource.strip_prefix("outpost/").ok_or_else(unknown_arn)?;
            let (outpost, rest) = rest.split_once("/bucket/").ok_or_else(unknown_arn)?;
            let (bucket, key) = rest.split_once("/object/").ok_or_else(unknown_arn)?;
            Ok(SourceResource {
                form: CopySourceForm::OutpostsArn,
                container: Some(non_empty(outpost)?.to_owned()),
                identity: crate::ResourceIdentity::Outposts {
                    partition: non_empty(partition)?.to_owned(),
                    region: non_empty(region)?.to_owned(),
                    account: non_empty(account)?.to_owned(),
                    outpost_id: non_empty(outpost)?.to_owned(),
                },
                bucket: bucket_of(bucket)?,
                key: key_of(key)?,
                version_id: None,
            })
        }
        _ => Err(unknown_arn()),
    }
}

/// The one refusal every unrecognised ARN shares.
fn unknown_arn() -> CopySourceRejection {
    CopySourceRejection::new(
        ErrorCode::INVALID_ARGUMENT,
        "x-amz-copy-source accepts an access point or Outposts ARN, or a bucket and key",
    )
}

/// Percent-decodes one half of the header, refusing bytes that are not UTF-8.
fn decode(value: &str) -> Result<String, CopySourceRejection> {
    percent_decode_str(value)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| CopySourceRejection::new(ErrorCode::INVALID_ARGUMENT, "x-amz-copy-source is not valid UTF-8 once decoded"))
}

/// Decodes and validates the key half through the same normalisation the request path uses.
///
/// `GHSA-f4vq-9ffr-m8m3` is what happens when this half is judged by looser rules than the
/// destination: authorisation reads a key, storage reads a path. The refusal names the rule and
/// never the value — a message quoting the header back is a header echoed into every log.
fn key_of(encoded: &str) -> Result<ObjectKey, CopySourceRejection> {
    let decoded = decode(encoded)?;
    if decoded.is_empty() {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the key named by x-amz-copy-source is not a valid object key",
        ));
    }
    let mut validation = decoded.clone();
    let mut unsafe_path = key_has_unsafe_path(&validation);
    while !unsafe_path && validation.contains('%') {
        let next = decode(&validation)?;
        if next == validation {
            break;
        }
        unsafe_path = key_has_unsafe_path(&next);
        validation = next;
    }
    if unsafe_path {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the key named by x-amz-copy-source is not a valid object key",
        ));
    }
    ObjectKey::new(decoded).map_err(|_| {
        CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the key named by x-amz-copy-source is not a valid object key",
        )
    })
}

fn key_has_unsafe_path(value: &str) -> bool {
    value.contains('\\') || value.split('/').any(|segment| segment.is_empty() || segment == "..")
}

/// Validates the bucket half.
fn bucket_of(name: &str) -> Result<BucketName, CopySourceRejection> {
    BucketName::new(name).map_err(|_| {
        CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the bucket named by x-amz-copy-source is not a valid bucket name",
        )
    })
}

/// Refuses an empty ARN component.
fn non_empty(value: &str) -> Result<&str, CopySourceRejection> {
    if value.is_empty() { Err(unknown_arn()) } else { Ok(value) }
}

#[cfg(test)]
#[path = "copy_source_security_tests.rs"]
#[allow(clippy::expect_used)]
mod security_tests;

#[cfg(test)]
// Test code only. The crate denies these three so that no request path can panic; a test that
// cannot assert an `Ok` is a test that says less than it should.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_types::dto::{CopyObject, CopyObjectInput};

    use crate::Decision;
    use crate::authz::{DerivedResourceSet, authorize_input, prepare_input};

    pub(super) fn rejected(raw: &str) -> CopySourceRejection {
        match CopySource::parse(raw) {
            Err(error) => error,
            Ok(_) => panic!("copy source should be refused"),
        }
    }

    pub(super) fn resolved(raw: &str) -> ResolvedCopySource {
        let input = CopyObjectInput {
            copy_source: raw.to_owned(),
            ..Default::default()
        };
        let decoded = prepare_input::<CopyObject>(input).expect("parses");
        let authorized = authorize_input(decoded, |_| Decision::Allow).expect("authorized");
        authorized
            .resources()
            .source()
            .resolve(authorized.read_proof())
            .expect("the proof belongs to this source")
    }

    #[test]
    fn the_version_suffix_is_split_before_the_key_is_decoded() {
        let source = resolved("bucket/a%3Fb?versionId=v1");
        assert_eq!(source.key().as_str(), "a?b");
        assert_eq!(source.version_id(), Some("v1"));
    }

    #[test]
    fn a_versioned_source_requires_get_object_version() {
        let input = CopyObjectInput {
            copy_source: "bucket/key?versionId=v1".to_owned(),
            ..Default::default()
        };
        let decoded = prepare_input::<CopyObject>(input).expect("parses");
        let mut actions = Vec::new();
        decoded.resources().visit(&mut |resource| actions.push(resource.action()));
        assert_eq!(actions, ["s3:GetObjectVersion"]);
    }

    #[test]
    fn a_leading_slash_is_accepted_and_means_the_same_thing() {
        assert_eq!(resolved("/bucket/key"), resolved("bucket/key"));
    }

    #[test]
    fn an_encoded_key_decodes_exactly_once_and_byte_for_byte() {
        let source = resolved("bucket/na%C3%AFve%20%E2%82%AC%26%2B%2Fx");
        assert_eq!(source.key().as_str(), "naïve €&+/x");
    }

    #[test]
    fn both_arn_forms_are_recognised() {
        let ap = resolved("arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/dir/key.txt");
        assert_eq!(ap.form(), CopySourceForm::AccessPointArn);
        assert_eq!(ap.key().as_str(), "dir/key.txt");

        let op = CopySource::parse("arn:aws:s3-outposts:us-east-1:1:outpost/op-1/bucket/src-bucket/object/k").expect("parses");
        assert_eq!(op.form(), CopySourceForm::OutpostsArn);
        assert_eq!(op.resource.container(), Some("op-1"));
        assert_eq!(op.resource.bucket().as_str(), "src-bucket");
    }

    #[test]
    fn an_unrecognised_arn_is_refused_rather_than_read_as_a_bucket() {
        let err = rejected("arn:aws:iam::123456789012:user/bob");
        assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn an_empty_or_keyless_value_is_refused() {
        for raw in ["", "bucket", "bucket/", "/bucket"] {
            let err = rejected(raw);
            assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT, "{raw}");
        }
    }

    #[test]
    fn the_handler_resolves_the_same_normalized_resource_authorization_saw() {
        let resolved = resolved("bucket/a%2Fb?versionId=v1");
        assert_eq!(resolved.bucket().as_str(), "bucket");
        assert_eq!(resolved.key().as_str(), "a/b");
        assert_eq!(resolved.version_id(), Some("v1"));
    }

    #[test]
    fn a_self_copy_is_recognised_and_a_versioned_one_is_not() {
        let bucket = BucketName::new("bucket").expect("bucket");
        let key = ObjectKey::new("key").expect("key");
        assert!(resolved("bucket/key").is_self_copy(&bucket, &key));
        assert!(!resolved("bucket/key?versionId=v1").is_self_copy(&bucket, &key));
        assert!(!resolved("bucket/other").is_self_copy(&bucket, &key));
    }

    #[test]
    fn a_self_copy_that_changes_nothing_is_refused_and_one_that_rewrites_metadata_is_not() {
        let bucket = BucketName::new("bucket").expect("bucket");
        let key = ObjectKey::new("key").expect("key");
        let source = resolved("bucket/key");
        assert_eq!(classify_self_copy(&source, &bucket, &key, false), SelfCopy::Illegal);
        assert_eq!(
            classify_self_copy(&source, &bucket, &key, false)
                .rejection()
                .map(|r| r.code().clone()),
            Some(ErrorCode::INVALID_REQUEST)
        );
        assert_eq!(classify_self_copy(&source, &bucket, &key, true), SelfCopy::RewriteMetadata);
        assert!(classify_self_copy(&source, &bucket, &key, true).rejection().is_none());
    }

    #[test]
    fn a_copied_span_is_end_minus_start_plus_one() {
        let span = resolve_copy_range(Some("bytes=0-9"), 100).expect("resolves").expect("a span");
        assert_eq!(span.len(), 10);
        assert!(!span.is_empty());
    }

    #[test]
    fn the_suffix_and_open_ended_forms_parse_as_they_do_for_a_read() {
        let last_five = resolve_copy_range(Some("bytes=-5"), 100).expect("resolves").expect("a span");
        assert_eq!((last_five.start, last_five.end_inclusive), (95, 99));
        let from_three = resolve_copy_range(Some("bytes=3-"), 100).expect("resolves").expect("a span");
        assert_eq!((from_three.start, from_three.end_inclusive), (3, 99));
    }

    #[test]
    fn a_zero_byte_source_copies_without_a_span_and_without_faulting() {
        assert_eq!(resolve_copy_range(None, 0), Ok(None));
        assert_eq!(
            resolve_copy_range(Some("bytes=0-0"), 0).expect_err("refused").code(),
            &ErrorCode::INVALID_ARGUMENT
        );
    }

    /// The rule this function's own doc comment states and a read range does not: a span the source
    /// cannot satisfy in full is refused, never trimmed. `ByteRange::resolve` answers `bytes=0-100`
    /// over ten bytes with `0-9` and `bytes=-100` with all ten — each a part ninety-odd bytes short
    /// of the length the client committed the upload to, with a `200` to go with it.
    #[test]
    fn a_span_the_source_cannot_satisfy_in_full_is_refused_rather_than_clamped() {
        for header in ["bytes=100-200", "bytes=0-100", "bytes=9-10", "bytes=0-10", "bytes=-100"] {
            let err = resolve_copy_range(Some(header), 10).expect_err("refused");
            assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT, "{header}");
        }
        // The boundaries themselves are not refusals: the last byte of a ten-byte source is nine,
        // and a suffix exactly as long as the source is the whole source rather than an overrun.
        let whole = Ok(Some(CopyRange {
            start: 0,
            end_inclusive: 9,
        }));
        assert_eq!(resolve_copy_range(Some("bytes=0-9"), 10), whole);
        assert_eq!(resolve_copy_range(Some("bytes=-10"), 10), whole);
    }

    /// A read ignores a `Range` it cannot parse and serves the whole representation. Doing that on
    /// a copy would write the entire source under a header that asked for part of it.
    #[test]
    fn a_value_that_is_not_a_byte_range_is_refused_rather_than_ignored() {
        for header in ["items=0-1", "bytes=", "bytes=abc", "bytes=5-1", "nonsense"] {
            let err = resolve_copy_range(Some(header), 10).expect_err("refused");
            assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT, "{header}");
        }
    }

    #[test]
    fn more_than_one_span_is_refused() {
        let err = resolve_copy_range(Some("bytes=0-1,5-6"), 100).expect_err("refused");
        assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
    }
}
