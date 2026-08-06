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

use rustfs_gateway_types::{
    BucketName, ChecksumSpec, ETag, EtagRender, ObjectKey, OpaqueString, RangeSpec, Timestamp, TimestampFormat,
    is_xml_representable,
};

use crate::codec::error::CodecError;
use crate::codec::view::MetaView;

/// The error a decoder raises for a required member the wire did not carry.
///
/// The code is IR data — `PutObject.ContentLength` names `MissingContentLength` and nothing else
/// does — so it arrives as a string from the overlay rather than being chosen here.
#[must_use]
pub fn missing(code: &'static str, member: &'static str) -> CodecError {
    CodecError::new(
        rustfs_gateway_types::ErrorCode::custom(code),
        "the request omits a member the wire contract requires",
    )
    .about(member)
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

/// Parses a timestamp in the format the IR bound to this field.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn timestamp(value: &str, format: TimestampFormat, member: &'static str) -> Result<Timestamp, CodecError> {
    Timestamp::parse(value, format).map_err(|_| unusable(member))
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
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn object_key(value: &str, member: &'static str) -> Result<ObjectKey, CodecError> {
    ObjectKey::new(value.to_owned()).map_err(|_| unusable(member))
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
    if encoding == UrlEncoding::Requested || !is_xml_representable(value) {
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

/// Wraps a value that is round-tripped byte for byte and never parsed.
#[must_use]
pub fn opaque(value: &str) -> OpaqueString {
    OpaqueString::new(value.to_owned())
}

/// Checks that a value the wire spells as an entity tag actually is one, and hands it back
/// unchanged.
///
/// The member keeps its string type: what the IR declares here is the *wire form*, not the stored
/// shape, so this refuses `"5d41…` — an opening quote with no closing one — without moving the
/// value into [`ETag`] and changing what every reader of that member is handed. `*`, a bare tag, a
/// quoted tag and a `W/` validator all parse, which is the whole set a conditional header may
/// carry.
///
/// It is also what makes a repeated conditional header a refusal rather than a coin flip: two
/// field lines reach here joined by a comma, and the joined value carries an embedded quote, which
/// no entity tag may.
///
/// # Errors
///
/// [`CodecError`] naming the member.
pub fn etag_form<'a>(value: &'a str, member: &'static str) -> Result<&'a str, CodecError> {
    ETag::parse_http_header(value).map_err(|_| unusable(member))?;
    Ok(value)
}

/// The longest token this service could have minted, in bytes.
///
/// Deliberately the same number as `crate::ops::shared::pagination::MAX_CURSOR_BYTES`, which is
/// the ceiling the listing operations read a cursor under once they have one. It is written twice
/// rather than shared because the two live on opposite sides of the codec/handler boundary and
/// `codec` does not depend on `ops`; the copy collapses into the shared one the day a cursor has a
/// type the IR can name. Until then the two must move together, and this sentence is the only
/// thing saying so.
///
/// The ceiling is checked before anything else for the reason the case that pins it gives: a
/// decoder that parses first has already done the work the ceiling exists to prevent.
const MAX_TOKEN_LEN: usize = 2048;

/// Checks that a value the wire spells as a server-minted opaque token could have been minted
/// here, and hands it back unchanged.
///
/// Four refusals, and every one of them is about a value the caller did not get from a previous
/// response:
///
/// * longer than anything this service mints — an unbounded allocation an unauthenticated caller
///   controls, once per request;
/// * carrying the replacement character — the single percent-decode is deliberately lossy because
///   S3 query values carry keys and a key is bytes, so a replacement character in the decoded form
///   means the wire bytes were not text, and no token this service minted is not text;
/// * carrying a control character, for the same reason and with the same conclusion;
/// * spelling a parent traversal — a `..` segment or a backslash. A cursor is the one
///   attacker-controlled value in the listing families that an implementation is tempted to give
///   structure to, and the moment it is joined onto a path it is a traversal performed on request.
///   Refusing the spelling here is what makes that impossible rather than merely unintended.
///
/// A `/` is *not* refused: a cursor derived from a key contains them, and a token drawn from the
/// standard base64 alphabet does too.
///
/// The last refusal is the one that distinguishes this from
/// `crate::ops::shared::pagination::CursorSpec::accept`, which shares the first three and
/// deliberately treats a traversal spelling as inert data. The two are not in conflict: that
/// function reads *every* cursor including `marker` and `key-marker`, which are object keys the
/// client is entitled to compose, and a key may spell whatever a key may spell. This one is
/// attached only to the cursors the overlay marks as server-minted, where a spelling the server
/// could not have produced is by definition not a cursor it produced.
///
/// # Errors
///
/// [`CodecError`] naming the member.
/// The value is returned rather than wrapped so that the one grammar serves both spellings a
/// cursor has in this surface: an `OpaqueString` member wraps the result, and the members the
/// model left as plain strings own it. A second function per storage type would be two places for
/// the rule to drift apart.
pub fn token_form<'a>(value: &'a str, member: &'static str) -> Result<&'a str, CodecError> {
    if value.len() > MAX_TOKEN_LEN {
        return Err(unusable(member));
    }
    if value
        .chars()
        .any(|c| c == char::REPLACEMENT_CHARACTER || c.is_control() || c == '\\')
    {
        return Err(unusable(member));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Err(unusable(member));
    }
    Ok(value)
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
    let mut found: Option<ChecksumSpec> = None;
    for (suffix, value) in request.headers_with_prefix(prefix) {
        // `algorithm` is one of a closed set; anything else is not a checksum header this gateway
        // recognises and is left to the signature layer to ignore.
        let mut name = String::with_capacity(prefix.len().saturating_add(suffix.len()));
        name.push_str(prefix);
        name.push_str(suffix);
        let Ok(spec) = ChecksumSpec::parse_header(&name, value) else {
            continue;
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
const CHECKSUM_PREFIX: &str = "x-amz-checksum-";

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
/// `x-amz-sdk-checksum-algorithm` deliberately does not satisfy it. It names an algorithm and
/// carries no digest, so treating it as an integrity check would accept exactly the request this
/// function exists to refuse.
///
/// # Errors
///
/// [`CodecError::invalid_request`] naming the header a caller can supply.
pub fn require_integrity(request: &MetaView<'_>) -> Result<(), CodecError> {
    if request.header(CONTENT_MD5).is_some() {
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

/// Renders a checksum back into its `x-amz-checksum-<algorithm>` header name and value.
#[must_use]
pub fn checksum_header(spec: &ChecksumSpec) -> (&'static str, &str) {
    (spec.algorithm().header_name(), spec.render_base64())
}
