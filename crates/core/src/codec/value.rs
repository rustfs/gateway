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

//! One function per scalar the IR can bind, shared by every generated codec.
//!
//! Responsible for: turning a wire string into a typed value and back, with the same refusal every
//! time.
//! NOT responsible for: knowing which field is bound where. Every call site is generated from the
//! IR, and every function here takes the member name so the failure can name it.
//! Upstream: `rustfs-gateway-types`. Downstream: every generated codec.
//!
//! # Why this is hand-written and the call sites are generated
//!
//! A rule that is generated seventy-three times is a rule that can be fixed in seventy-two places.
//! "More than one checksum header is an error, not a merge" is one sentence, and it belongs in one
//! function; what codegen contributes is that every operation accepting checksum headers *calls*
//! it, which is the half a human forgets.

use std::borrow::Cow;
use std::collections::BTreeMap;

use rustfs_gateway_http::decode_metadata_value;
use rustfs_gateway_types::{
    BucketName, ChecksumError, ChecksumSpec, ContentMd5, ETag, ErrorCode, EtagRender, NamePolicy, ObjectKey, OpaqueString,
    RangeSpec, Timestamp, TimestampFormat, is_xml_representable,
};

use crate::codec::error::CodecError;
use crate::codec::response::{ResponseOverride, override_header_value};
use crate::codec::view::MetaView;

/// The error a decoder raises for a required member the wire did not carry.
///
/// The code is IR data — `PutObject.ContentLength` names `MissingContentLength` and nothing else
/// does — so the generated call site names the constant rather than this function choosing one.
/// It arrives resolved, not as a string: a wire spelling would have to be looked up here, in the
/// request path, where a code the error-status authority does not declare has no status to be
/// given. Codegen refuses to emit such a code at all, which turns that into a build failure.
#[must_use]
pub fn missing(code: ErrorCode, member: &'static str) -> CodecError {
    CodecError::new(code, "the request omits a member the wire contract requires").about(member)
}

/// The error a decoder raises for a member that is present and unusable.
#[must_use]
pub fn unusable(member: &'static str) -> CodecError {
    CodecError::invalid_argument("the request carries a value this member cannot hold").about(member)
}

/// The decode-path exit check, as the error a codec raises.
///
/// Every generated `decode` ends with this. A placeholder reaching it is never a client mistake —
/// a request that omits a required member is refused by the binding that looked for it — so it
/// means the decoder failed to fill the member in, and a wire-invalid `BucketName` reaching a
/// handler is a value both authorization and storage would accept and neither would recognise.
///
/// # Errors
///
/// [`CodecError::internal`], because the fault is on this side.
pub fn exit(outcome: Result<(), rustfs_gateway_types::PlaceholderDefault>) -> Result<(), CodecError> {
    outcome.map_err(|_| CodecError::internal("a required member left the decoder still holding its placeholder default"))
}

/// Parses a 32-bit integer.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn integer(value: &str, member: &'static str) -> Result<i32, CodecError> {
    value.trim().parse::<i32>().map_err(|_| unusable(member))
}

/// Parses a 32-bit integer and refuses one outside the range its binding declares.
///
/// Out of range is the same refusal as unparseable, and deliberately so: `partNumber=10001` and
/// `partNumber=abc` are both a parameter the caller has to fix, and a client that is told
/// `InvalidArgument` for one and something else for the other learns nothing from the difference.
/// Clamping is the alternative this function exists to refuse — a caller asking for a hundred
/// thousand keys and reading a thousand concludes the bucket is small.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn integer_in_range(value: &str, member: &'static str, min: i32, max: i32) -> Result<i32, CodecError> {
    let parsed = integer(value, member)?;
    if parsed < min || parsed > max {
        return Err(unusable(member));
    }
    Ok(parsed)
}

/// Parses a 64-bit integer.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn long(value: &str, member: &'static str) -> Result<i64, CodecError> {
    value.trim().parse::<i64>().map_err(|_| unusable(member))
}

/// Parses a boolean, case-insensitively.
///
/// `True` is accepted along with `true`: the AWS CLI sends the capitalised spelling, and a
/// case-sensitive parser refuses a request every AWS SDK considers well formed.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn boolean(value: &str, member: &'static str) -> Result<bool, CodecError> {
    if value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    Err(unusable(member))
}

/// Parses a boolean using only lower-case wire spellings.
///
/// This is the mechanically distinct alternative selected by the boolean-spelling mutation gate.
///
/// # Errors
///
/// [`CodecError`] naming the member when the value is not exactly `true` or `false`.
pub fn boolean_lowercase(value: &str, member: &'static str) -> Result<bool, CodecError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(unusable(member)),
    }
}

/// Parses a timestamp in the format the IR bound to this field.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn timestamp(value: &str, format: TimestampFormat, member: &'static str) -> Result<Timestamp, CodecError> {
    Timestamp::parse(value, format).map_err(|_| unusable(member))
}

/// What a date condition amounted to, once the header was in hand.
///
/// Two variants, and neither of them is "the header was not sent". Absence is spelled by the
/// binding — the generated `if let Some(raw) = request.header(..)` that never fires — exactly as
/// it is for [`byte_range`]. This type only exists inside that `if`, so it cannot re-introduce the
/// ambiguity it was written to prevent.
///
/// # The `if-range` defect, and why it is not repeated here
///
/// `Range` used to bind to `Option<ByteRange>`, whose `None` meant both "no header" and "a header
/// we will not honour". The second is a fact a `416` has to state, and it had been erased before
/// any handler ran. The fix was to keep the two apart in the type.
///
/// The same erasure would be available here — a decoder could map an unreadable date straight to
/// `None` and be done — and it is refused for the same reason, with one difference worth writing
/// down. For `Range` the two cases owe the client **different responses**. For a date condition
/// they owe the client **the same response**: RFC 9110 §13.1.3 and §13.1.4 say an unreadable
/// modification-date condition is ignored, and a request with no condition at all is also served
/// in full, so the two are indistinguishable on the wire *by requirement*.
///
/// That makes the collapse correct here and wrong there — which is precisely why it must be a
/// named, single-site operation rather than a `?` that never happened. [`Self::honoured`] is that
/// site: it is the only way to reach the stored `Option<Timestamp>`, its name says the condition
/// was dropped rather than absent, and a future member that does owe the client something about an
/// unreadable date has [`Self::Unreadable`] already sitting there to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateCondition {
    /// The header arrived and is a valid date in the format its binding declares.
    At(Timestamp),
    /// The header arrived and is not a valid date, so the condition is dropped.
    ///
    /// Not an error. A date header is rewritten by proxies, generated by clients with their own
    /// idea of the format, and copied out of logs; answering `400` breaks a request that carries
    /// no requirement at all once its value cannot be read, and it turns a client's formatting
    /// mistake into a denial of service against that client.
    Unreadable,
}

impl DateCondition {
    /// The condition to evaluate, which an unreadable one does not contribute.
    ///
    /// The one place [`Self::Unreadable`] becomes indistinguishable from a header that never
    /// arrived. See the type documentation for why that is the required behaviour here and was a
    /// defect for `Range`.
    #[must_use]
    pub fn honoured(self) -> Option<Timestamp> {
        match self {
            Self::At(stamp) => Some(stamp),
            Self::Unreadable => None,
        }
    }

    /// Whether the header arrived carrying something that is not a date.
    ///
    /// Nothing in the request path branches on this today — by RFC requirement, nothing may. It is
    /// public because an observer counting malformed conditional headers is the diagnostic a
    /// client with a broken date format has no other way to receive, and because a variant no
    /// caller can read is a variant the next refactor collapses.
    #[must_use]
    pub fn was_unreadable(self) -> bool {
        matches!(self, Self::Unreadable)
    }
}

/// Reads a date condition in the format the IR bound to this field, tolerantly.
///
/// Never an error, and that is the whole point: RFC 9110 §13.1.3 and §13.1.4 require a recipient
/// to **ignore** a modification-date condition whose value is not a valid HTTP-date. Refusing one
/// tells a client that its date format is unacceptable by failing every request it sends, which is
/// the one outcome the specification rules out.
///
/// Attached to a member by a `header_tolerance` quirk in the overlay, resolved by
/// `rustfs-gateway-codegen`'s `emit::codec::tolerance`. It is deliberately not the default for
/// `Type::Timestamp(HttpDate)`: `ResponseExpires` is an override the caller asks for, not a
/// condition, and silently dropping a malformed one would serve a response the caller did not ask
/// for rather than decline to filter.
#[must_use]
pub fn date_condition(value: &str, format: TimestampFormat) -> DateCondition {
    match Timestamp::parse(value, format) {
        Ok(stamp) => DateCondition::At(stamp),
        Err(_) => DateCondition::Unreadable,
    }
}

/// Renders a timestamp in the format the IR bound to this field.
///
/// # Errors
///
/// [`CodecError::internal`]: a value the gateway itself produced has no wire form in the format
/// its own IR chose, which is a defect on this side rather than anything a caller did.
pub fn render_timestamp(value: &Timestamp, format: TimestampFormat) -> Result<String, CodecError> {
    value
        .render(format)
        .map_err(|_| CodecError::internal("an output timestamp has no rendering in the format its binding declares"))
}

/// Parses an entity tag out of a header value.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn etag_header(value: &str, member: &'static str) -> Result<ETag, CodecError> {
    ETag::parse_http_header(value).map_err(|_| unusable(member))
}

/// Parses an entity tag out of an XML text node, quoted or bare.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn etag_xml(value: &str, member: &'static str) -> Result<ETag, CodecError> {
    ETag::parse_xml_text(value).map_err(|_| unusable(member))
}

/// Renders an entity tag in the context the IR bound to this field.
///
/// There is no default context on purpose: the same tag is `"d41d…"` in a header, `&quot;d41d…&quot;`
/// in most bodies, and bare in exactly one. The context is a parameter because a call site that
/// had to remember it would eventually not.
#[must_use]
pub fn render_etag(value: &ETag, context: EtagRender) -> String {
    value.render(context).into_owned()
}

/// Parses an object key out of a body element or a query value, already percent-decoded.
///
/// The safety floor runs here too. A key that arrives in a `<Delete>` body is a key a client
/// chose, and a floor that governed the request path but not the request body would be a floor
/// with a door in it — `DeleteObjects` names its keys in the body and nowhere else.
///
/// No decode happens: the XML or query reader that produced this value already performed the one
/// decode, and a second one is the `%252e%252e` trap.
///
/// The deployment policy is required rather than defaulted: body-carried keys and URI-carried keys
/// must pass the same validator, or one assembled service would have two naming authorities.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn object_key(value: &str, member: &'static str, names: &NamePolicy) -> Result<ObjectKey, CodecError> {
    ObjectKey::materialize_decoded(value, names).map_err(|_| unusable(member))
}

/// Parses a bucket name.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn bucket_name(value: &str, member: &'static str) -> Result<BucketName, CodecError> {
    BucketName::new(value.to_owned()).map_err(|_| unusable(member))
}

/// The query parameter a listing uses to ask for percent-encoded key-shaped members.
const ENCODING_TYPE: &str = "encoding-type";

/// The one value AWS defines for it.
const ENCODING_TYPE_URL: &str = "url";

/// Whether this response percent-encodes the members its operation declares as key-shaped.
///
/// One decision per response rather than one per member: a listing that encoded some of its keys
/// and not others would be undecodable, because the echo a client reads —
/// `<EncodingType>url</EncodingType>` — is a single flag covering the whole document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlEncoding {
    /// The request asked for it: every declared member is encoded.
    Requested,
    /// It did not. A member is still encoded when its value has no XML spelling at all, because
    /// the alternative is a body the client's parser rejects in full.
    Absent,
}

/// Reads the encoding the request asked for.
///
/// Generated into the `encode` of every operation whose IR declares `xml.url_encoded_fields`, and
/// nowhere else. Any value other than `url` is `Absent`: AWS defines exactly one, and treating an
/// unknown spelling as "encode anyway" would percent-encode a listing whose echo says it did not.
#[must_use]
pub fn url_encoding(request: &MetaView<'_>) -> UrlEncoding {
    match request.query(ENCODING_TYPE) {
        Some(value) if value.eq_ignore_ascii_case(ENCODING_TYPE_URL) => UrlEncoding::Requested,
        _ => UrlEncoding::Absent,
    }
}

pub(crate) fn url_encoding_for_response(request: &MetaView<'_>, forced: bool) -> UrlEncoding {
    if forced {
        UrlEncoding::Requested
    } else {
        url_encoding(request)
    }
}

/// Whether one listing member forces `encoding-type=url`, including C0 controls and DEL.
#[must_use]
pub fn needs_url_encoding(value: &str) -> bool {
    !is_xml_representable(value) || value.chars().any(|ch| ch <= '\u{1f}' || ch == '\u{7f}')
}

pub(crate) trait UrlEncodingValue {
    fn requires_url_encoding(&self) -> bool;
}

impl UrlEncodingValue for String {
    fn requires_url_encoding(&self) -> bool {
        needs_url_encoding(self)
    }
}

impl UrlEncodingValue for OpaqueString {
    fn requires_url_encoding(&self) -> bool {
        needs_url_encoding(self.as_str())
    }
}

impl UrlEncodingValue for ObjectKey {
    fn requires_url_encoding(&self) -> bool {
        self.needs_url_encoding()
    }
}

impl<T: UrlEncodingValue> UrlEncodingValue for Option<T> {
    fn requires_url_encoding(&self) -> bool {
        self.as_ref().is_some_and(UrlEncodingValue::requires_url_encoding)
    }
}

pub(crate) fn requires_url_encoding<T: UrlEncodingValue>(value: &T) -> bool {
    value.requires_url_encoding()
}

pub(crate) fn any_requires_url_encoding<T, V: UrlEncodingValue>(values: &[T], field: impl Fn(&T) -> &V) -> bool {
    values.iter().any(|value| field(value).requires_url_encoding())
}

/// The single encoding pass, shared by both renderers below.
///
/// `rustfs_gateway_sig::percent_encode` rather than a second implementation: it is already the
/// "every byte outside RFC 3986's unreserved set, uppercase hex" pass, which is the same one AWS
/// documents for `encoding-type=url`. Two copies of a percent codec in one workspace is how the
/// two come to disagree about `/`.
fn percent_encoded(value: &str) -> Cow<'_, str> {
    Cow::Owned(rustfs_gateway_sig::percent_encode(value.as_bytes()))
}

/// Renders a string member the operation declares as url-encodable.
///
/// Encoded when the request asked, and otherwise only when the value carries a character XML
/// cannot represent. The second half is not an optimisation: `<Prefix>` echoes a value the caller
/// chose, so a caller can put a byte in it that has no XML spelling.
#[must_use]
pub fn url_encoded(value: &str, encoding: UrlEncoding) -> Cow<'_, str> {
    if encoding == UrlEncoding::Requested || needs_url_encoding(value) {
        return percent_encoded(value);
    }
    Cow::Borrowed(value)
}

/// The [`ObjectKey`] twin of [`url_encoded`].
///
/// The forced half asks the key itself — [`ObjectKey::needs_url_encoding`] — so that "which keys
/// cannot be written into a body" is answered by the key type rather than by whichever encoder
/// happens to be running.
#[must_use]
pub fn url_encoded_key(value: &ObjectKey, encoding: UrlEncoding) -> Cow<'_, str> {
    if encoding == UrlEncoding::Requested || value.needs_url_encoding() {
        return percent_encoded(value.as_str());
    }
    Cow::Borrowed(value.as_str())
}

/// Reads a payload that is a text document rather than XML, refusing bytes that are not text.
///
/// The one member with this shape today is a bucket policy, whose body is JSON. What this does is
/// the whole of the decoder's contribution to it: the bytes are text or they are not, and a
/// decoder has no way to name a code more specific than that. Whether the text is *valid* JSON,
/// how deep it nests and how large it may be are the operation's questions, asked after decoding
/// by `ops::shared::bucket_policy` with the code AWS answers — `MalformedPolicy`, which no
/// generated decoder can reach.
///
/// The refusal never repeats the body. A policy document names principals, account ids and
/// resource ARNs, so an error that echoed the offending bytes would publish them to whoever can
/// provoke it — the message is a constant and the member name is a compile-time constant from the
/// IR.
///
/// # Errors
///
/// [`CodecError`] — `400 MalformedPolicy` — when the bytes are not UTF-8.
pub fn text_payload(value: &[u8], member: &'static str) -> Result<String, CodecError> {
    match core::str::from_utf8(value) {
        Ok(text) => Ok(text.to_owned()),
        Err(_) => Err(CodecError::new(ErrorCode::MALFORMED_POLICY, "the request body is not UTF-8 text").about(member)),
    }
}

/// Splits a comma-delimited list header into its elements.
///
/// RFC 9110 section 5.6.1 list syntax: elements are separated by commas with optional whitespace
/// around each, and empty elements do not count. Repeated field lines arrive here already joined
/// with a comma by the header view, so they read as one list. An element is not otherwise
/// interpreted: the caller turns each into the member type the IR declares.
pub fn header_list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(|element| element.trim_matches([' ', '\t']))
        .filter(|element| !element.is_empty())
}

/// Wraps a value that is round-tripped byte for byte and never parsed.
#[must_use]
pub fn opaque(value: &str) -> OpaqueString {
    OpaqueString::new(value.to_owned())
}

/// Reads a `Range` header into the parse **and** the bytes it was parsed from.
///
/// Never an error. RFC 9110 requires an unsatisfiable or unparseable `Range` to be ignored and the
/// whole representation served; refusing one breaks clients whose proxy rewrote the header, and
/// S3 answers a multi-range request with the whole object rather than a multipart body.
///
/// # Why this returns a value and not an `Option`
///
/// Because it used to return one, and that `None` meant two different things: "no `Range` header
/// arrived" and "a `Range` header arrived that this server will not honour". The second is a fact
/// a `416` has to be able to state — `<RangeRequested>` is the header as the client wrote it — and
/// it was erased, along with the text, before any handler ran. `Option<RangeSpec>` now spells
/// absence once, in the binding, and the header's own bytes survive whatever it parsed to.
#[must_use]
pub fn byte_range(value: &str) -> RangeSpec {
    RangeSpec::new(value)
}

/// Collects every header under a prefix into a map.
///
/// Used for `x-amz-meta-*`. Keys arrive lowercased, which is the form AWS returns them in; the
/// value bytes have already been through this workspace's metadata validation at acceptance.
#[must_use]
pub fn prefixed_map(request: &MetaView<'_>, prefix: &'static str) -> BTreeMap<String, String> {
    request
        .headers_with_prefix(prefix)
        .map(|(suffix, value)| (suffix.to_owned(), value.to_owned()))
        .collect()
}

/// Collects and RFC 2047-decodes every user-metadata header before storage sees the map.
///
/// # Errors
/// [`CodecError`] when an accepted value cannot be decoded.
pub fn metadata_map(
    request: &MetaView<'_>,
    prefix: &'static str,
    member: &'static str,
) -> Result<BTreeMap<String, String>, CodecError> {
    request
        .headers_with_prefix(prefix)
        .map(|(suffix, value)| {
            decode_metadata_value(value)
                .map(|decoded| (suffix.to_owned(), decoded.into_owned()))
                .map_err(|_| unusable(member))
        })
        .collect()
}

/// Reads the one `x-amz-checksum-*` header a request is allowed to carry.
///
/// Three rules in one place, and they are the reason this is not inlined into each codec:
///
/// * a request carrying two *different* checksum headers is refused rather than merged — picking
///   one would mean verifying an integrity claim the caller did not make;
/// * an algorithm this build does not implement is refused, not ignored;
/// * a value that is not the right length for its algorithm is refused here, before any body byte
///   has been read, so an oversized upload is not consumed before the rejection.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn checksum_spec(
    request: &MetaView<'_>,
    prefix: &'static str,
    member: &'static str,
) -> Result<Option<ChecksumSpec>, CodecError> {
    checksum_spec_of_fields(request.headers_with_prefix(prefix), prefix, member)
}

/// [`checksum_spec`]'s rule over any `(suffix, value)` fields that share `prefix`.
///
/// The header decoder and the trailer reader
/// ([`crate::ops::shared::trailer_checksum::request_checksum`]) both call this, so a checksum field
/// is judged by one rule whichever section of the message carried it.
pub(crate) fn checksum_spec_of_fields<'a>(
    fields: impl Iterator<Item = (&'a str, &'a str)>,
    prefix: &'static str,
    member: &'static str,
) -> Result<Option<ChecksumSpec>, CodecError> {
    let mut found: Option<ChecksumSpec> = None;
    for (suffix, value) in fields {
        // Three headers share the prefix and declare no digest. They are named rather than
        // pattern-matched away, for the same reason `parse_request_checksum` names them: the
        // prefix is otherwise a closed set of algorithms, and a member of it this build does not
        // know must be refused rather than waved through.
        if matches!(suffix, "algorithm" | "type" | "mode") {
            continue;
        }
        let mut name = String::with_capacity(prefix.len().saturating_add(suffix.len()));
        name.push_str(prefix);
        name.push_str(suffix);
        // Refused, never skipped. Skipping a value this binder cannot read means the input reaches
        // the handler with no checksum at all, so the caller's claim is dropped on the floor and
        // the object is stored as though none had been made. The head-level arbitration in
        // `rustfs-gateway-http` has already applied the identical rule above the body read; this
        // agreeing with it is what makes the two one decision instead of two.
        let Ok(spec) = ChecksumSpec::parse_header(&name, value) else {
            return Err(CodecError::invalid_request(
                "the request carries a checksum value that is not valid for the algorithm its header names",
            )
            .about(member));
        };
        if let Some(existing) = &found
            && existing.algorithm() != spec.algorithm()
        {
            return Err(CodecError::invalid_request(
                "the request carries more than one checksum algorithm, which is a contradiction rather than a choice",
            )
            .about(member));
        }
        found = Some(spec);
    }
    Ok(found)
}

/// The header prefix every per-algorithm request checksum is spelled with.
pub(crate) const CHECKSUM_PREFIX: &str = "x-amz-checksum-";

/// The header a chunked upload uses to announce the checksum it will send as a trailer.
const TRAILER_HEADER: &str = "x-amz-trailer";

/// The header carrying the legacy whole-body digest.
const CONTENT_MD5: &str = "content-md5";

/// Refuses a request body that carries no integrity claim at all.
///
/// Generated into the decoder of every operation whose IR says `checksum.http_checksum_required`,
/// and called before a single body byte is read. That order is the point: for `DeleteObjects` the
/// body is a list of keys to destroy, so a server that buffers a megabyte of them and only then
/// refuses has already paid for the attack, and one corrupted in transit deletes keys nobody can
/// identify afterwards.
///
/// Three spellings satisfy it, and the third is why this is not a plain header lookup: a chunked
/// upload sends its digest in a trailer and announces it in `x-amz-trailer`, so demanding a header
/// value would refuse traffic the AWS SDKs consider well formed.
///
/// A view the deployment built [`MetaView::with_integrity_optional`] for is admitted without one:
/// that is the reviewed client waiver, decided per operation by the assembly, not here.
///
/// `x-amz-sdk-checksum-algorithm` deliberately does not satisfy it. It names an algorithm and
/// carries no digest, so treating it as an integrity check would accept exactly the request this
/// function exists to refuse.
///
/// # Errors
///
/// [`CodecError::invalid_request`] naming the header a caller can supply.
pub fn require_integrity(request: &MetaView<'_>) -> Result<(), CodecError> {
    if request.integrity_optional() || request.header(CONTENT_MD5).is_some() {
        return Ok(());
    }
    if request.headers_with_prefix(CHECKSUM_PREFIX).next().is_some() {
        return Ok(());
    }
    if request
        .header(TRAILER_HEADER)
        .is_some_and(|value| value.to_ascii_lowercase().contains(CHECKSUM_PREFIX))
    {
        return Ok(());
    }
    Err(CodecError::invalid_request(
        "this operation requires an integrity check on the request body: send Content-MD5 or an x-amz-checksum-* header",
    ))
}

/// Verifies a buffered request body against the `Content-MD5` the request declared.
///
/// Generated into every decoder at the point the body is buffered, and at no other point. The
/// header is optional; a request that sends none is not checked, because `Content-MD5` is a claim
/// the client chooses to make and its absence is answered by [`require_integrity`] where an
/// operation demands one.
///
/// The split between the two codes is the one clients branch on. A value that is not base64 of
/// sixteen bytes is `InvalidDigest`: the client's claim is unreadable, and no body could satisfy
/// it. A readable value that does not match is `BadDigest`: the claim was well formed and the
/// bytes are not the bytes it names. Collapsing them would tell an uploader with a broken SDK the
/// same thing as an uploader with a corrupted wire.
///
/// # What this does not cover, and what covers it instead
///
/// **Only `Content-MD5`, and only a buffered body.** The two gaps have different owners and it
/// matters which is which:
///
/// * A **streaming** body. `PutObject` and `UploadPart` hand their payload onward without
///   aggregating it here, so nothing at this layer ever sees their bytes. An assembly that reads
///   the body itself covers them at the read — `rustfs_gateway_http::BodyIntegrity` is that check
///   and it is the same comparison, run over the bytes as they arrive.
/// * The **`x-amz-checksum-*` family**. It is arbitrated and compared by
///   `rustfs_gateway_http::BodyIntegrity`, above this layer, because the ambiguities it has to
///   refuse — two claims, a claim that names an algorithm no value carried — are decidable from
///   the head and must be refused *before* the transfer rather than after it. Restating that
///   decision here would be a second copy of it.
///
/// What this function does own is the guarantee that a decoder buffering a body **cannot** be
/// composed into an assembly that forgot to check the digest: it is generated at the buffering
/// site itself, from one string, so acquiring the body and checking its digest are the same edit.
/// The digest itself is [`ContentMd5::digester`], the same one every other caller uses; nothing
/// here computes MD5 a second way.
///
/// # It is redundant in the assembly this repository ships, on purpose
///
/// `rustfs-gateway`'s body read refuses the same request earlier, so deleting the comparison below
/// leaves that assembly's test suite and the whole conformance corpus green. That is stated here
/// rather than left to be discovered: this crate is a library, an assembly that reads the body
/// some other way is exactly what it exists to support, and a decoder that trusted its caller to
/// have checked would be a decoder whose safety depends on a caller it cannot see. The redundancy
/// is defence in depth and not an oversight — but it does mean a regression here is invisible to
/// this repository's own suite, so treat this function as covered by
/// `crates/codegen`'s structural control over the emission and by nothing else.
///
/// # Errors
///
/// [`CodecError`] carrying `InvalidDigest` or `BadDigest`.
pub fn verify_body_digest(request: &MetaView<'_>, body: &[u8]) -> Result<(), CodecError> {
    let Some(declared) = request.header(CONTENT_MD5) else {
        return Ok(());
    };
    let refuse = |error: ChecksumError| CodecError::new(error.error_code(), error.message());
    let expected = ContentMd5::parse(declared.as_ref()).map_err(refuse)?;
    let mut digest = ContentMd5::digester();
    digest.update(body);
    expected.verify(&digest.finish()).map_err(refuse)
}

/// Refuses a request whose `response-*` override carries a value no response header can hold.
///
/// Generated as the first statement of every decoder whose operation declares such a parameter,
/// and nowhere else. It is first on purpose: the value is head data, the refusal is about the
/// response this request would produce rather than about anything a backend knows, and a request
/// that would have to be answered by splitting its own response head must not reach a handler at
/// all. Answering it later — or, as this gateway did until rustfs/backlog#1701, dropping the
/// header and answering `200` with the object — hands the caller a success for a request the
/// service could not carry out, and leaves the only evidence of the attempt in a header that is
/// not there.
///
/// The reading is [`crate::codec::response::override_header_value`], the same function the encoder
/// writes the value with. One predicate, two call sites: the set refused here and the set the
/// encoder would have had to drop are the same set, so neither can silently widen.
///
/// # Errors
///
/// [`CodecError::invalid_argument`] naming the model member the parameter binds. `InvalidArgument`
/// rather than a code of this rule's own: AWS answers a `response-*` value it cannot put in a
/// header with `InvalidArgument`, and the status that code carries is
/// `model/overlays/error-status.toml`'s to state, not this function's.
pub fn verify_response_overrides(request: &MetaView<'_>, table: &[ResponseOverride]) -> Result<(), CodecError> {
    for entry in table {
        let Some(value) = request.query(entry.query) else {
            continue;
        };
        if override_header_value(value.as_ref()).is_none() {
            return Err(
                CodecError::invalid_argument("a response-* override carries a value the response header cannot hold")
                    .about(entry.member),
            );
        }
    }
    Ok(())
}

/// Renders a checksum back into its `x-amz-checksum-<algorithm>` header name and value.
#[must_use]
pub fn checksum_header(spec: &ChecksumSpec) -> (&'static str, &str) {
    (spec.algorithm().header_name(), spec.render_base64())
}
