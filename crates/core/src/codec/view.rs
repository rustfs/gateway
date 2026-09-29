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

//! What a decoder is allowed to read, and the one place a path is decoded.
//!
//! Responsible for: [`MetaView`] — the head of an accepted request, with the URI labels already
//! split and percent-decoded exactly once — and [`RequestBody`], the four shapes a body can
//! arrive in.
//! NOT responsible for: reading a body byte, accepting a request (`rustfs-gateway-http`), or
//! deciding which operation a request names (`crate::route`).
//! Upstream: `rustfs-gateway-http`'s [`WireRequest`]. Downstream: every generated codec.
//!
//! # Why the path is decoded here and nowhere else
//!
//! `RawPath` is deliberately undecoded and offers no `decode` method: a path that can be decoded
//! anywhere can be decoded twice, and a doubly decoded `%252e%252e` is a traversal no single-decode
//! check would have seen. This is the one place the single decode happens, on the way to a
//! [`rustfs_gateway_types::ObjectKey`], and the result is what every decoder reads.
//!
//! # Where the naming policy enters, and where it must not
//!
//! [`MetaView::of_with`] takes the deployment's [`NamePolicy`] and hands it to
//! `ObjectKey::materialize`, which is the workspace's single normalisation. Everything after this
//! point — governance, authorization, auditing, the codec, the backend — reads the value that came
//! out of it and is never given the path to re-parse.
//!
//! Signature canonicalisation is the one stage that must **not** see it. `rustfs-gateway-sig`
//! builds its canonical request from `WireRequest::raw_path`, the undecoded bytes, and there is no
//! conversion from an [`rustfs_gateway_types::ObjectKey`] back into one. Two different raw paths
//! that normalise to the same key must not share a signature.

use std::borrow::Cow;

use bytes::Bytes;
use http::Method;
use rustfs_gateway_http::{HeaderView, QueryView, WireRequest};
use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::dto::PostObjectInput;
use rustfs_gateway_types::{BucketName, NamePolicy, NameRejection, ObjectKey, PathSplit};

use crate::codec::error::CodecError;
use crate::route::TargetKind;

/// The head of an accepted request, as a decoder sees it.
///
/// Borrows the [`WireRequest`]; it owns nothing but the two decoded URI labels, which cannot be
/// borrowed from the still-encoded path.
#[derive(Debug)]
pub struct MetaView<'a> {
    method: &'a Method,
    headers: HeaderView<'a>,
    query: QueryView<'a>,
    bucket: Option<BucketName>,
    key: Option<ObjectKey>,
    names: NamePolicy,
    /// The object length `content-length` answers with, for an `aws-chunked` body.
    framed_content_length: Option<u64>,
    /// Whether the deployment waived this operation's modelled integrity requirement.
    integrity_optional: bool,
    /// Whether the deployment answers a request-checksum failure with `BadDigest`.
    checksum_failures_as_bad_digest: bool,
    /// A page-size query parameter the deployment clamps to a ceiling instead of refusing.
    page_size_ceiling: Option<PageSizeCeiling>,
    /// Whether an absent `content-length` reads as `0`, because the transport already ended the
    /// body with nothing in it.
    ended_empty: bool,
    /// Legacy RustFS's `encoding-type=url` rule for this listing, under the RustFS profile.
    rustfs_listing: Option<crate::codec::value::RustFsListing>,
    /// Whether the deployment reads an HTTP-date condition in legacy RustFS's one spelling.
    strict_date_conditions: bool,
}

/// A page-size query parameter answered with its ceiling when the request asked for more.
///
/// The RustFS profile's reading of an oversized page size (rustfs/backlog#1677, R1): RustFS lowers
/// `max-keys` to the listing maximum before it lists or echoes it, so a client asking for five
/// thousand reads a page of at most a thousand and `<MaxKeys>1000</MaxKeys>`. Only a value that
/// parses as an integer above the ceiling is replaced; an unparseable or negative value reaches
/// the decoder as sent and is refused there exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSizeCeiling {
    parameter: &'static str,
    ceiling: i32,
}

impl PageSizeCeiling {
    /// Clamps the query parameter `parameter` to `ceiling`.
    #[must_use]
    pub const fn new(parameter: &'static str, ceiling: i32) -> Self {
        Self { parameter, ceiling }
    }

    /// The query parameter this ceiling governs.
    #[must_use]
    pub const fn parameter(&self) -> &'static str {
        self.parameter
    }

    /// The largest page size the parameter is answered with.
    #[must_use]
    pub const fn ceiling(&self) -> i32 {
        self.ceiling
    }

    /// `value` clamped, when it is an integer above the ceiling under the codec's own integer
    /// reading, and `None` otherwise.
    fn clamp(&self, value: &str) -> Option<i32> {
        crate::codec::value::parse_integer(value).filter(|&requested| requested > self.ceiling)?;
        Some(self.ceiling)
    }
}

impl<'a> MetaView<'a> {
    /// Splits an accepted request's path under the default naming policy.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the path does not have the shape the target kind requires, or when a
    /// label is not a valid bucket name or object key. Both are `400`: routing has already decided
    /// which operation this is, so an unusable label is the caller's mistake and not a `501`.
    pub fn of<B>(request: &'a WireRequest<B>, target: TargetKind) -> Result<Self, CodecError> {
        Self::addressed_with(request, target, None, &NamePolicy::default())
    }

    /// Splits an accepted request's path, with the bucket a virtual host already named.
    ///
    /// `host_bucket` is `None` for a path-style request, which is [`MetaView::of`]. When it is
    /// `Some`, the host has named the bucket and the **whole** path is the object key: `GET /b2/key`
    /// on `bucket.example.com` is the object `b2/key` in `bucket`, and never the bucket `b2`. That
    /// is the single-source rule — the resolver decides once where the bucket came from, and this
    /// is the one place the decision is applied. Two readings of the same path, one for routing and
    /// one for authorization, is exactly how a request gets authorized against a bucket it was not
    /// served from.
    ///
    /// # Errors
    ///
    /// As [`MetaView::of`]. A virtual-hosted request whose path does not decode as a key is still
    /// a `400`; the host being right does not make the path readable.
    pub fn addressed<B>(
        request: &'a WireRequest<B>,
        target: TargetKind,
        host_bucket: Option<BucketName>,
    ) -> Result<Self, CodecError> {
        Self::addressed_with(request, target, host_bucket, &NamePolicy::default())
    }

    /// Splits an accepted request's path under the deployment's naming policy.
    ///
    /// The policy is threaded rather than read from a global, because a global would be a second
    /// place the answer could come from and the whole point of this stage is that there is one.
    ///
    /// # Errors
    ///
    /// [`CodecError`], as [`MetaView::of`].
    pub fn of_with<B>(request: &'a WireRequest<B>, target: TargetKind, names: &NamePolicy) -> Result<Self, CodecError> {
        Self::addressed_with(request, target, None, names)
    }

    /// **The one constructor.** Both addressing styles and both policy sources end here.
    ///
    /// The other three are named shorthands for it, so that a virtual-hosted key and a path-style
    /// key cannot be materialised by two different pieces of code. That is not tidiness: if the
    /// host-addressed path went through its own decode, `a//b` would be one key when the client
    /// addressed the bucket by host and another when it addressed it by path, and a policy written
    /// against one spelling would not cover the other.
    ///
    /// # Errors
    ///
    /// [`CodecError`], as [`MetaView::of`].
    pub fn addressed_with<B>(
        request: &'a WireRequest<B>,
        target: TargetKind,
        host_bucket: Option<BucketName>,
        names: &NamePolicy,
    ) -> Result<Self, CodecError> {
        let path = request.raw_path().as_str();
        let (bucket, key) = match host_bucket {
            Some(bucket) => (Some(bucket), vhost_key(path, target, names)?),
            None => split_labels(path, target, names)?,
        };
        Ok(Self {
            method: request.method(),
            headers: request.headers(),
            query: request.query(),
            bucket,
            key,
            names: names.clone(),
            framed_content_length: None,
            integrity_optional: false,
            checksum_failures_as_bad_digest: false,
            page_size_ceiling: None,
            ended_empty: false,
            rustfs_listing: None,
            strict_date_conditions: false,
        })
    }

    /// This view, with `content-length` answered by an `aws-chunked` body's object length.
    ///
    /// For a framed body the object's size is `x-amz-decoded-content-length`, not the wire
    /// `Content-Length`, which counts the chunk framing too — and which a body the transport ends
    /// (`Transfer-Encoding: chunked`, HTTP/2) does not carry at all. The assembly calls this once,
    /// with the decoded length its ingest layer validated against the signature's payload mode, so
    /// that a codec binding `Content-Length` reads the number the decoder holds the body to
    /// (rustfs/gateway#750). Every other header reads exactly as before.
    #[must_use]
    pub fn with_framed_content_length(&self, length: u64) -> Self {
        Self {
            method: self.method,
            headers: self.headers,
            query: self.query,
            bucket: self.bucket.clone(),
            key: self.key.clone(),
            names: self.names.clone(),
            framed_content_length: Some(length),
            integrity_optional: self.integrity_optional,
            checksum_failures_as_bad_digest: self.checksum_failures_as_bad_digest,
            page_size_ceiling: self.page_size_ceiling,
            ended_empty: self.ended_empty,
            rustfs_listing: self.rustfs_listing,
            strict_date_conditions: self.strict_date_conditions,
        }
    }

    /// This view, with the operation's modelled integrity requirement waived.
    ///
    /// The assembly calls this only for an operation its deployment listed in a reviewed client
    /// waiver (rustfs/gateway#916: MinIO SDKs write bucket policies without `Content-MD5`), so
    /// [`crate::codec::value::require_integrity`] admits a body with no integrity claim. A claim
    /// the request does make is still verified: the waiver drops the demand, never the check.
    #[must_use]
    pub fn with_integrity_optional(mut self) -> Self {
        self.integrity_optional = true;
        self
    }

    /// Whether this operation's modelled integrity requirement was waived for this deployment.
    #[must_use]
    pub const fn integrity_optional(&self) -> bool {
        self.integrity_optional
    }

    /// This view, for a deployment that answers a request-checksum failure — an unreadable value, a
    /// missing trailer checksum, a digest that does not match — with `BadDigest`, as legacy RustFS
    /// does (rustfs/gateway#1057). The failure is refused where it always is; only its code
    /// changes, and `Content-MD5` keeps its own codes.
    #[must_use]
    pub const fn with_checksum_failures_as_bad_digest(mut self) -> Self {
        self.checksum_failures_as_bad_digest = true;
        self
    }

    /// Whether this deployment answers a request-checksum failure with `BadDigest`.
    #[must_use]
    pub const fn checksum_failures_as_bad_digest(&self) -> bool {
        self.checksum_failures_as_bad_digest
    }

    /// This view, reading an HTTP-date condition in the one spelling legacy RustFS reads.
    ///
    /// The assembly calls this only for an operation its deployment reads date conditions strictly
    /// on (the RustFS profile, rustfs/backlog#1677 R14), having refused an unreadable one first, so
    /// [`crate::codec::value::date_condition_in`] hands on the instant legacy RustFS would have read
    /// rather than the RFC 9110 reading of the same bytes. Every other member reads as before.
    #[must_use]
    pub const fn with_strict_date_conditions(mut self) -> Self {
        self.strict_date_conditions = true;
        self
    }

    /// Whether this deployment reads an HTTP-date condition in legacy RustFS's one spelling.
    #[must_use]
    pub const fn strict_date_conditions(&self) -> bool {
        self.strict_date_conditions
    }

    /// This view, with one page-size query parameter clamped to its ceiling.
    ///
    /// The assembly calls this only for a listing its deployment clamps (the RustFS profile's
    /// `max-keys`), so every decoder reading the parameter — and so the handler and the
    /// `<MaxKeys>` echo — sees the page size the listing will really serve. Absent, unparseable,
    /// negative and in-range values read exactly as the wire carries them.
    #[must_use]
    pub const fn with_page_size_ceiling(mut self, ceiling: PageSizeCeiling) -> Self {
        self.page_size_ceiling = Some(ceiling);
        self
    }

    /// This view, with an absent `content-length` read as `0`.
    ///
    /// The assembly calls this only for an upload whose transport has already ended the body with
    /// nothing in it — an HTTP/1.1 request with neither `Content-Length` nor `Transfer-Encoding`,
    /// which RFC 9112 §6.3 gives a zero-length body, or an HTTP/2 request whose headers ended the
    /// stream — and only under a deployment that accepts such an upload (the RustFS profile). A
    /// `content-length` the request does carry is read exactly as sent.
    #[must_use]
    pub const fn with_transport_ended_empty_body(mut self) -> Self {
        self.ended_empty = true;
        self
    }

    /// This view, with a listing rendered under legacy RustFS's `encoding-type=url` rule.
    ///
    /// The assembly calls this only for a listing its deployment renders the way legacy RustFS
    /// does (the RustFS profile, rustfs/gateway#1059); every encoder then encodes exactly the
    /// members `listing` names, with `/` kept literal, and echoes `encoding-type` as legacy RustFS
    /// does. See `crate::codec::rustfs_listing`.
    #[must_use]
    pub const fn with_rustfs_listing_encoding(mut self, listing: crate::codec::value::RustFsListing) -> Self {
        self.rustfs_listing = Some(listing);
        self
    }

    /// Legacy RustFS's `encoding-type=url` rule for this listing, when the deployment applies it.
    #[must_use]
    pub const fn rustfs_listing_encoding(&self) -> Option<crate::codec::value::RustFsListing> {
        self.rustfs_listing
    }

    /// The naming policy this view was built under.
    ///
    /// Read by the decoders that have a second name to materialise — `x-amz-copy-source` is the
    /// one — so that the source of a copy is judged by the same rules as its destination. A copy
    /// whose source went through different rules than its destination is the shape of
    /// `GHSA-f4vq-9ffr-m8m3`.
    #[must_use]
    pub fn names(&self) -> &NamePolicy {
        &self.names
    }

    /// The request method. Needed by encoders, because a `HEAD` response never carries a body.
    #[must_use]
    pub fn method(&self) -> &'a Method {
        self.method
    }

    /// The value of a header, with repeated field lines joined the way RFC 9110 §5.3 defines them.
    ///
    /// Borrows when the field appears once, which is every request in practice; the owned form is
    /// built only for the repeated case.
    ///
    /// # Why the repeats are joined rather than reduced to the first
    ///
    /// Because "one field whose value is the members joined by commas" is what the message
    /// *means*, and taking the first line is a decoder answering a request the client did not
    /// send. The family where that difference is a security property rather than a nicety is the
    /// conditional headers: two `If-Match` lines joined produce a value no entity-tag parser
    /// accepts, so the request is refused instead of being evaluated against whichever of the
    /// client's two conditions happened to arrive first — a compare-and-swap defeated by a
    /// header-parsing shortcut.
    ///
    /// That outcome is not written here. It falls out of the joined value reaching the type the
    /// binding declares, which is the only place a wire refusal belongs.
    ///
    /// The headers acceptance already treats as single-valued — `authorization`, `content-length`,
    /// `content-md5`, `content-type`, `range` and the rest of
    /// `rustfs_gateway_http::SINGLE_VALUED_HEADERS` — never reach here repeated at all: a request
    /// carrying two of them is refused before a codec runs. So this rule governs everything else,
    /// which is where the conditional headers live.
    ///
    /// A field line whose bytes are not UTF-8 is skipped, exactly as `HeaderView::get_str` skips
    /// an unreadable single value: acceptance has already refused that case for every header this
    /// gateway treats as significant.
    ///
    /// For a framed body two headers read as the *object's* rather than the wire's: `content-length`
    /// is the decoded length (rustfs/gateway#750), and `content-encoding` is the client's value
    /// with the `aws-chunked` token removed — absent when that token was the whole value
    /// (rustfs/gateway#813). `aws-chunked` names the framing the ingest layer has already decoded,
    /// and a backend that stored it would tell a later reader to un-chunk a body that is not.
    ///
    /// Under [`MetaView::with_transport_ended_empty_body`] an absent `content-length` reads as `0`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<Cow<'a, str>> {
        let name = http::HeaderName::from_bytes(name.as_bytes()).ok()?;
        if let Some(length) = self.framed_content_length
            && name == http::header::CONTENT_LENGTH
        {
            return Some(Cow::Owned(length.to_string()));
        }
        if self.framed_content_length.is_some() && name == http::header::CONTENT_ENCODING {
            return without_aws_chunked(&self.header_text(&name)?);
        }
        if self.ended_empty && name == http::header::CONTENT_LENGTH {
            return self.header_text(&name).or(Some(Cow::Borrowed("0")));
        }
        self.header_text(&name)
    }

    /// One header as the wire carries it, multi-line values joined with `, `.
    fn header_text(&self, name: &http::HeaderName) -> Option<Cow<'a, str>> {
        let name = name.clone();
        if !self.headers.is_multi(&name) {
            return self.headers.get_str(&name).map(Cow::Borrowed);
        }
        let mut joined = String::new();
        let mut lines = 0usize;
        for (each, value) in self.headers.iter_text() {
            if *each != name {
                continue;
            }
            if lines > 0 {
                joined.push_str(", ");
            }
            joined.push_str(value);
            lines = lines.saturating_add(1);
        }
        if lines == 0 {
            return None;
        }
        Some(Cow::Owned(joined))
    }

    /// Every header under a prefix, as `(suffix, value)` pairs with the prefix stripped.
    ///
    /// The suffix is lowercased by the transport already; user metadata keys are returned in that
    /// form, which is the form AWS returns them in too.
    pub fn headers_with_prefix(&self, prefix: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.headers
            .iter_text()
            .filter_map(move |(name, value)| name.as_str().strip_prefix(prefix).map(|suffix| (suffix, value)))
    }

    /// A query parameter, percent-decoded exactly once.
    ///
    /// `None` covers "absent"; a present parameter with an empty value is `Some("")`, because
    /// `?prefix=` and no `prefix` at all are different requests.
    ///
    /// A parameter the deployment clamps ([`MetaView::with_page_size_ceiling`]) reads as its
    /// ceiling when the request asked for more.
    #[must_use]
    pub fn query(&self, key: &str) -> Option<Cow<'a, str>> {
        let value = self.query.get(key).map(decode_component)?;
        if let Some(ceiling) = self.page_size_ceiling
            && ceiling.parameter == key
            && let Some(clamped) = ceiling.clamp(&value)
        {
            return Some(Cow::Owned(clamped.to_string()));
        }
        Some(value)
    }

    /// Whether a query parameter is present, whatever its value.
    #[must_use]
    pub fn has_query(&self, key: &str) -> bool {
        self.query.contains(key)
    }

    /// The bucket the path addressed, when it addressed one.
    #[must_use]
    pub fn bucket(&self) -> Option<&BucketName> {
        self.bucket.as_ref()
    }

    /// The object key the path addressed, when it addressed one.
    #[must_use]
    pub fn key(&self) -> Option<&ObjectKey> {
        self.key.as_ref()
    }

    /// The bucket, or the error a decoder raises when the route promised one and the path had none.
    ///
    /// # Errors
    ///
    /// [`CodecError::invalid_argument`] naming the member.
    pub fn require_bucket(&self) -> Result<BucketName, CodecError> {
        self.bucket
            .clone()
            .ok_or_else(|| CodecError::invalid_argument("the request path names no bucket").about("Bucket"))
    }

    /// The object key, or the error a decoder raises when the route promised one and the path had
    /// none.
    ///
    /// # Errors
    ///
    /// [`CodecError::invalid_argument`] naming the member.
    pub fn require_key(&self) -> Result<ObjectKey, CodecError> {
        self.key
            .clone()
            .ok_or_else(|| CodecError::invalid_argument("the request path names no object key").about("Key"))
    }
}

/// The object key of a virtual-hosted request: the whole path, decoded once.
///
/// No bucket is taken here, because the host already supplied it. A `Service` target cannot occur
/// on a virtual host — the host names a bucket, so there is no service-root request to be had —
/// and is treated as the bucket root rather than being given a key it does not have.
fn vhost_key(path: &str, target: TargetKind, names: &NamePolicy) -> Result<Option<ObjectKey>, CodecError> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    match target {
        TargetKind::Service | TargetKind::Bucket => Ok(None),
        // `materialize` under the *same* policy `split_labels` uses, not merely the same function.
        // A virtual-hosted key that went through the default policy while a path-style one went
        // through the deployment's would make `a//b` two different objects depending on how the
        // client spelled the bucket — the drift this module exists to prevent, arriving through
        // the addressing style rather than through a second decoder.
        TargetKind::Object => ObjectKey::materialize(trimmed, names).map(Some).map_err(key_rejected),
    }
}

/// Splits a request path into the labels the target kind declares.
fn split_labels(
    path: &str,
    target: TargetKind,
    names: &NamePolicy,
) -> Result<(Option<BucketName>, Option<ObjectKey>), CodecError> {
    if names.path_split() == PathSplit::RustfsLegacy {
        return super::legacy_path::legacy_labels(path, target, names);
    }
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    match target {
        TargetKind::Service => Ok((None, None)),
        TargetKind::Bucket => {
            let name = trimmed.strip_suffix('/').unwrap_or(trimmed);
            Ok((Some(bucket_of(name, names)?), None))
        }
        TargetKind::Object => {
            let (name, key) = trimmed
                .split_once('/')
                .ok_or_else(|| CodecError::invalid_argument("the request path names no object key").about("Key"))?;
            // `materialize` is the single normalisation: one decode, the slash policy, the safety
            // floor, then the deployment's validator. Nothing downstream re-reads the path.
            let key = ObjectKey::materialize(key, names).map_err(key_rejected)?;
            Ok((Some(bucket_of(name, names)?), Some(key)))
        }
    }
}

/// Turns a refused key into the error the caller sees.
///
/// The rejection's own reason is used, and the value never is: a message that echoed the key back
/// would put whatever the caller sent into a log line and an error body.
pub(crate) fn key_rejected(rejection: NameRejection) -> CodecError {
    CodecError::new(rejection.key_error_code(), rejection.reason()).about("Key")
}

/// A raw bucket label under exactly the rules a path-style S3 request's first segment meets.
///
/// For a claimed row that binds a template parameter as its authorisation bucket (ADR-0025): the
/// raw segment goes through this, never the decoded parameter value, so an escaped spelling is
/// refused here exactly as it is for `/{bucket}`.
///
/// # Errors
///
/// `InvalidBucketName`, about `Bucket`, never echoing the value.
pub fn bucket_label(raw: &str, names: &NamePolicy) -> Result<BucketName, CodecError> {
    bucket_of(raw, names)
}

fn bucket_of(raw: &str, names: &NamePolicy) -> Result<BucketName, CodecError> {
    // A bucket label is never percent-encoded on the wire: the naming rules admit only characters
    // that need no escaping, so a `%` here is a spelling no client produces — and the floor
    // refuses one that carries a `%` rather than decoding it.
    //
    // `InvalidBucketName`, not the generic `InvalidArgument`: AWS answers a name that breaks the
    // bucket naming rules with its own code on every operation, and an SDK branching on it —
    // `CreateBucket` is the one that has to — cannot tell a bad name from any other bad parameter
    // when both arrive as `InvalidArgument`.
    BucketName::materialize(raw, names)
        .map_err(|rejection| CodecError::new(rejection.bucket_error_code(), "The specified bucket is not valid").about("Bucket"))
}

/// Percent-decodes one query component, borrowing when there is nothing to decode.
///
/// A byte sequence that is not UTF-8 after decoding is returned lossily rather than refused: S3
/// query values carry object keys, and a key is bytes. The refusal, when there is one, belongs to
/// the type the value is parsed into.
fn decode_component(raw: &str) -> Cow<'_, str> {
    percent_encoding::percent_decode_str(raw).decode_utf8_lossy()
}

/// The four shapes a request body reaches a decoder in.
///
/// Which one an operation gets is the IR's `payload.request.buffering`, not a decoder's choice: an
/// operation whose body is `Streaming` never sees `Buffered`, so no generated decoder can
/// accidentally aggregate an unbounded upload into memory — the shape it is handed cannot express
/// that.
#[derive(Debug, Default)]
pub enum RequestBody {
    /// The operation takes no body.
    #[default]
    None,
    /// A complete body, already bounded by the operation's declared cap.
    Buffered(Bytes),
    /// A live producer, handed straight to the handler.
    Stream(ByteStream),
    /// An authenticated browser form whose live file part is ready for the POST Object handler.
    PostObject(Box<PostObjectInput>),
}

/// How much of a request body must exist before its decoder runs.
///
/// Generated codecs publish this from the lowered protocol IR so an assembly can choose the body
/// shape before moving the sole live producer into the decoder. Third-party codecs default to
/// [`Self::Full`], the conservative mode that preserves the complete-body handoff.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RequestBodyMode {
    /// The operation has no request payload.
    None,
    /// The complete bounded body is available before decoding.
    #[default]
    Full,
    /// The decoder receives a live producer before the body is complete.
    Streaming,
    /// A multipart form whose bounded text prelude is authenticated before its file is opened.
    PostObject,
    /// The response head is committed before the request-side outcome is known.
    Deferred,
}

impl RequestBody {
    /// The buffered bytes, or the error a decoder raises when the body was not buffered.
    ///
    /// # Errors
    ///
    /// [`CodecError::internal`]: an operation whose IR says `Full` was handed something else, which
    /// is a pipeline defect and not a caller mistake.
    pub fn into_buffered(self) -> Result<Bytes, CodecError> {
        match self {
            Self::Buffered(bytes) => Ok(bytes),
            Self::None => Ok(Bytes::new()),
            Self::Stream(_) | Self::PostObject(_) => Err(CodecError::internal(
                "this operation declares a buffered request body and was handed a stream",
            )),
        }
    }

    /// The streaming body, when there is one.
    #[must_use]
    pub fn into_stream(self) -> Option<ByteStream> {
        match self {
            Self::Stream(stream) => Some(stream),
            _ => None,
        }
    }

    /// The live producer for a required streaming member.
    ///
    /// # Errors
    ///
    /// [`CodecError::internal`] when the pipeline hands a required-streaming codec no stream. The
    /// mismatch is a gateway defect, not an omitted optional value, so this path fails closed.
    pub fn into_required_stream(self) -> Result<ByteStream, CodecError> {
        match self {
            Self::Stream(stream) => Ok(stream),
            Self::None => Err(CodecError::internal(
                "this operation requires a streaming request body and was handed none",
            )),
            Self::Buffered(_) => Err(CodecError::internal(
                "this operation requires a streaming request body and was handed buffered bytes",
            )),
            Self::PostObject(_) => Err(CodecError::internal(
                "this operation requires a streaming request body and was handed a POST form",
            )),
        }
    }

    /// The prepared POST Object input, or an internal error when the assembly handed this codec
    /// another body shape.
    pub fn into_post_object(self) -> Result<PostObjectInput, CodecError> {
        match self {
            Self::PostObject(input) => Ok(*input),
            _ => Err(CodecError::internal("PostObject requires an authenticated multipart form body")),
        }
    }
}

/// `value` with every `aws-chunked` coding removed; `None` when nothing else was named.
///
/// Codings are compared case-insensitively as RFC 9110 §8.4 says, and the survivors keep their
/// spelling and order: `gzip, aws-chunked` is `gzip`, `aws-chunked` alone is absent.
fn without_aws_chunked(value: &str) -> Option<Cow<'static, str>> {
    let kept: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    (!kept.is_empty()).then(|| Cow::Owned(kept.join(", ")))
}

#[cfg(test)]
mod content_encoding_tests {
    use super::without_aws_chunked;

    /// Negative — the framing token is removed wherever it stands and however it is cased, the
    /// other codings keep their spelling and order, and a token-only value is absent
    /// (rustfs/gateway#813).
    #[test]
    fn n_aws_chunked_is_removed_and_nothing_else_is() {
        assert_eq!(without_aws_chunked("gzip, aws-chunked").as_deref(), Some("gzip"));
        assert_eq!(without_aws_chunked("aws-chunked,gzip").as_deref(), Some("gzip"));
        assert_eq!(without_aws_chunked("br, AWS-Chunked, gzip").as_deref(), Some("br, gzip"));
        assert_eq!(without_aws_chunked("aws-chunked").as_deref(), None);
        assert_eq!(without_aws_chunked(" aws-chunked , ").as_deref(), None);
        assert_eq!(without_aws_chunked("gzip").as_deref(), Some("gzip"));
        assert_eq!(without_aws_chunked("x-aws-chunked").as_deref(), Some("x-aws-chunked"));
    }
}

#[cfg(test)]
mod request_body_tests {
    use super::*;

    #[test]
    fn required_stream_returns_the_live_producer() {
        let stream = ByteStream::from_bytes(Bytes::from_static(b"annotation"));
        assert!(RequestBody::Stream(stream).into_required_stream().is_ok());
    }

    #[test]
    fn n_required_stream_refuses_an_absent_body() {
        let result = RequestBody::None.into_required_stream();
        assert!(result.is_err(), "an absent body cannot satisfy a required streaming member");
        let Err(error) = result else {
            return;
        };
        assert_eq!(*error.code(), rustfs_gateway_types::ErrorCode::INTERNAL_ERROR);
    }

    #[test]
    fn n_required_stream_refuses_a_buffered_body() {
        let result = RequestBody::Buffered(Bytes::from_static(b"annotation")).into_required_stream();
        assert!(result.is_err(), "a buffered body cannot masquerade as the live producer");
        let Err(error) = result else {
            return;
        };
        assert_eq!(*error.code(), rustfs_gateway_types::ErrorCode::INTERNAL_ERROR);
    }
}
