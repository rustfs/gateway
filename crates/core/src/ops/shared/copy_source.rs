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
use rustfs_gateway_types::{BucketName, ByteRange, ErrorCode, KeyFloor, NamePolicy, ObjectKey, PathSplit, RangeParse};

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
        Self::parse_under(raw, &NamePolicy::default())
    }

    /// [`CopySource::parse`] with the source key held to `names`' key floor, the floor the
    /// request's own key was held to (rustfs/gateway#1107).
    ///
    /// Under the unconditional floor this is [`CopySource::parse`] exactly: the key is checked at
    /// every decode pass. Under [`KeyFloor::RustfsLegacy`] the source key is the value one decode
    /// produced, held to that floor and the deployment's validator through the same
    /// materialisation a body-carried key goes through, as legacy RustFS reads a copy source's key.
    ///
    /// # Errors
    ///
    /// As [`CopySource::parse`].
    pub fn parse_under(raw: &str, names: &NamePolicy) -> Result<Self, CopySourceRejection> {
        if raw.is_empty() {
            return Err(CopySourceRejection::new(
                ErrorCode::INVALID_ARGUMENT,
                "x-amz-copy-source must name a source object",
            ));
        }

        let (path, version_id) = if names.path_split() == PathSplit::RustfsLegacy {
            split_version_as_legacy_rustfs(raw)?
        } else {
            split_version(raw)?
        };

        let resource = if path.starts_with("arn:") {
            parse_arn(path, names)?
        } else {
            parse_path(path, names)?
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
        Self::parse_under(raw, &NamePolicy::default())
    }

    /// The source, parsed under the naming policy the request was materialised under.
    pub(crate) fn parse_under(raw: &str, names: &NamePolicy) -> Result<Self, crate::DerivedResourceError> {
        CopySource::parse_under(raw, names)
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

/// Splits the version off the raw header value as legacy RustFS does: at the first `?versionId=`,
/// everything else — another `?` among it — belonging to the path.
///
/// Legacy-compat (rustfs/backlog#2684): a `?` that does not begin `versionId=` is key bytes to
/// legacy RustFS, so `x-amz-copy-source: bkt/obj?partNumber=1` copies the object `obj?partNumber=1`
/// (measured on a legacy build), where [`split_version`] refuses it. Kept, under the RustFS
/// profile's path addressing only, so an object whose key holds a `?` stays a copy source under the
/// spelling that reaches it today; the intended future behaviour is [`split_version`].
fn split_version_as_legacy_rustfs(raw: &str) -> Result<(&str, Option<String>), CopySourceRejection> {
    let Some((path, value)) = raw.split_once("?versionId=") else {
        return Ok((raw, None));
    };
    let value = decode(value)?;
    if value.is_empty() {
        // Legacy RustFS's storage refuses an empty version with this code, after authorization.
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the versionId of x-amz-copy-source must not be empty",
        ));
    }
    Ok((path, Some(value)))
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
/// The separator is the first `/` of the *decoded* value, whether the client sent it literally or
/// as `%2F`: aws-sdk-dotnet percent-encodes the whole `bucket/key` value (rustfs/gateway#926). A
/// bucket name cannot contain `/`, so the first decoded slash is always the separator and every
/// later one — literal or encoded — is key bytes. The split is found on the raw value rather than
/// by decoding it whole, so the key half still reaches [`key_of`] undecoded and is decoded exactly
/// once: decoding the whole value first would decode the key a second time.
fn parse_path(path: &str, names: &NamePolicy) -> Result<SourceResource, CopySourceRejection> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let Some((bucket, key)) = split_bucket_key(path) else {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "x-amz-copy-source must name a key as well as a bucket",
        ));
    };
    Ok(SourceResource {
        form: CopySourceForm::Path,
        container: None,
        identity: crate::ResourceIdentity::Path,
        bucket: path_bucket_of(&decode(bucket)?, names)?,
        key: key_of(key, names)?,
        version_id: None,
    })
}

/// Splits the raw `bucket/key` value at the first byte sequence that decodes to `/`.
///
/// A decoded `/` can only come from a literal `/` or from `%2F`/`%2f` — percent decoding is one
/// octet per escape, and no byte of a multi-byte UTF-8 sequence is `0x2F` — so the first of those
/// in the raw value is exactly the first slash of the decoded value. Both halves are returned still
/// encoded.
fn split_bucket_key(path: &str) -> Option<(&str, &str)> {
    ["/", "%2F", "%2f"]
        .into_iter()
        .filter_map(|separator| path.find(separator).map(|at| (at, separator.len())))
        .min_by_key(|&(at, _)| at)
        .map(|(at, len)| (&path[..at], &path[at + len..]))
}

/// Parses the two S3 ARN spellings, and refuses every other ARN.
fn parse_arn(path: &str, names: &NamePolicy) -> Result<SourceResource, CopySourceRejection> {
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
                key: key_of(key, names)?,
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
                key: key_of(key, names)?,
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
fn key_of(encoded: &str, names: &NamePolicy) -> Result<ObjectKey, CopySourceRejection> {
    let decoded = decode(encoded)?;
    if names.key_floor() == KeyFloor::RustfsLegacy {
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads a copy source's key as the one
        // decode of the header and checks only its length, so a source it stores under a control
        // character, a backslash or a literal `%2F` can be copied, and a traversal or an empty key
        // reaches its storage to be refused there (`400 InvalidArgument`, measured on a legacy
        // build). The same materialisation as a body-carried key keeps the source under the key
        // floor the destination is held to; the intended future behaviour is the unconditional
        // check below, with the default floor.
        return ObjectKey::materialize_decoded(&decoded, names).map_err(|_| {
            CopySourceRejection::new(
                ErrorCode::INVALID_ARGUMENT,
                "the key named by x-amz-copy-source is not a valid object key",
            )
        });
    }
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
    // The same materialisation as a body-carried key, so the deployment's validator judges the
    // source as it judges the destination (the floor already ran at every decode pass above).
    ObjectKey::materialize_decoded(&decoded, names).map_err(|_| {
        CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the key named by x-amz-copy-source is not a valid object key",
        )
    })
}

/// The destination's own key floor, applied to the source at every decode pass.
///
/// The same function the request path is judged by (`floor_check_key`), and not a stricter
/// private one: an earlier version refused every key with an empty segment or a backslash, which
/// made `photos/` — the folder marker every console and sync tool writes, and a key `PutObject`
/// accepts — uncopyable, while accepting control characters the destination refuses. One floor
/// for both halves is the whole of the GHSA-f4vq-9ffr-m8m3 lesson; a second spelling of it drifts.
fn key_has_unsafe_path(value: &str) -> bool {
    rustfs_gateway_types::floor_check_key(value).is_err()
}

/// Validates the bucket half of the path form, under the deployment's bucket rules when it reads
/// paths as legacy RustFS does.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS reads a copy source's bucket by its own
/// bucket rules, so an object in a bucket it created under a prefix or suffix the AWS rules reserve
/// (`sthree-x`, `abc-s3alias`) can be copied (measured on a legacy build: `x-amz-copy-source:
/// sthree-x/obj` copies). Kept, under the RustFS profile's path addressing only, so no object
/// RustFS stores stops being a copy source; the intended future behaviour is the AWS rules.
fn path_bucket_of(name: &str, names: &NamePolicy) -> Result<BucketName, CopySourceRejection> {
    if names.path_split() == PathSplit::RustfsLegacy {
        return BucketName::materialize(name, names).map_err(|_| invalid_bucket());
    }
    bucket_of(name)
}

fn invalid_bucket() -> CopySourceRejection {
    CopySourceRejection::new(
        ErrorCode::INVALID_ARGUMENT,
        "the bucket named by x-amz-copy-source is not a valid bucket name",
    )
}

/// Validates the bucket half.
fn bucket_of(name: &str) -> Result<BucketName, CopySourceRejection> {
    BucketName::new(name).map_err(|_| invalid_bucket())
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
#[path = "copy_source_rustfs_tests.rs"]
#[allow(clippy::expect_used)]
mod rustfs_tests;

#[cfg(test)]
#[path = "copy_source_tests.rs"]
// Test code only. The crate denies these three so that no request path can panic; a test that
// cannot assert an `Ok` is a test that says less than it should.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;

#[cfg(test)]
#[path = "copy_source_rustfs_grammar_tests.rs"]
#[allow(clippy::expect_used)]
mod rustfs_grammar_tests;
