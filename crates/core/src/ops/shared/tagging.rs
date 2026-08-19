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

//! Shares: tagging
//! Members: DeleteBucketTagging, DeleteObjectTagging, GetBucketTagging, GetObjectTagging,
//!          PutBucketTagging, PutObjectTagging
//!
//! Responsible for: what a tag set is allowed to be, in one place for its two request channels —
//! the `<Tagging>` document of the `?tagging` subresource and the packed `x-amz-tagging` header
//! that `PutObject`, `CopyObject` and `CreateMultipartUpload` carry. [`parse_tagging_header`] is
//! the only sanctioned reading of the header; [`validate_tag_set`] is the one copy of the
//! per-scope count ceiling, the character-set rule, the length ceilings and the duplicate-key
//! refusal, shared by both channels.
//! NOT responsible for: the XML wire form itself — `<TagSet><Tag>` is wrapped, and that fact
//! lives in the model plus `model/overlays/ops/*`, rendered by the generated codecs — nor for
//! storing a tag set, minting `x-amz-tagging-count`, or evaluating `s3:ExistingObjectTag/*`
//! conditions, all of which belong to a backend.
//! Upstream: `rustfs_gateway_types::ErrorCode`. Downstream: the six operations named above, and —
//! through the facade re-export — any backend reading the header channel, the conformance fixture
//! included.
//!
//! # Why one validator serves two channels
//!
//! `x-amz-tagging: a=1&b=2` and `<Tagging><TagSet><Tag>...` express the same value, and a rule
//! implemented once per channel is the s3s#499-versus-#632 shape: two copies of one rule, fixed in
//! different directions. The *syntax* of the two channels differs — only the header is
//! form-urlencoded, so only the header has escapes to refuse — but every semantic rule (how many
//! tags, how long a key, which characters, no repeated key) is [`validate_tag_set`], called by
//! whoever read either channel.
//!
//! # The limits, and where they come from
//!
//! AWS documents the same tag shape at both scopes and different count ceilings per scope:
//!
//! * key at most 128 Unicode characters, value at most 256, characters drawn from letters,
//!   numbers, whitespace and `+ - = . _ : / @`, keys unique — see
//!   <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html> (the character
//!   and length rules for object tags) and
//!   <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html> (`InvalidTag` as
//!   the code a rejected tag answers with);
//! * at most **10** tags on an object, at most **50** on a bucket — the object ceiling from the
//!   user guide above, the bucket ceiling from AWS's cost-allocation tag restrictions,
//!   <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/allocation-tag-restrictions.html>.
//!
//! The ceilings are counted in **UTF-16 code units**, which is the counting AWS's own user guide
//! names: it says object tags are represented internally in UTF-16 and that a character there
//! occupies one or two positions. A supplementary-plane character therefore spends two of a key's
//! 128 and two of a value's 256, and the two countings differ on nothing else — every BMP
//! character is one unit and one scalar value alike. Counting scalar values instead accepted a key
//! of 128 astral characters that AWS refuses, which is the divergence that only shows up in
//! production, so `char`s are not the unit here even though `char`s are what Rust reaches for.
//! See <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html>.
//!
//! # What a rejection may say
//!
//! A [`TaggingRejection`]'s reason is a `&'static str`, never assembled from the request: a tag
//! key is caller-chosen text, and echoing it into an error body is how a stored-XSS or a
//! log-injection payload gets a second life. The header's malformed-spelling refusals all share
//! one sentence — AWS's own — because a caller who could tell "no `=`" from "broken escape" apart
//! by the message would be learning the parser's shape rather than the rule.

use rustfs_gateway_types::ErrorCode;

/// The largest number of tags one object may carry.
pub const MAX_OBJECT_TAGS: usize = 10;

/// The largest number of tags one bucket may carry.
pub const MAX_BUCKET_TAGS: usize = 50;

/// The longest tag key, in UTF-16 code units.
pub const MAX_TAG_KEY_UNITS: usize = 128;

/// The longest tag value, in UTF-16 code units.
pub const MAX_TAG_VALUE_UNITS: usize = 256;

/// AWS's own wording for an `x-amz-tagging` header that is not a tag set.
///
/// One constant rather than a message per failure: AWS answers every malformed spelling of this
/// header with the same sentence.
const MALFORMED_TAGGING_HEADER: &str = "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query \
     parameters without tag name duplicates.";

/// Which resource a tag set labels. The two scopes share every rule but the count ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagScope {
    /// A bucket's tag set: at most [`MAX_BUCKET_TAGS`] entries.
    Bucket,
    /// An object's tag set: at most [`MAX_OBJECT_TAGS`] entries.
    Object,
}

impl TagScope {
    /// The count ceiling this scope enforces.
    #[must_use]
    pub const fn max_tags(self) -> usize {
        match self {
            TagScope::Bucket => MAX_BUCKET_TAGS,
            TagScope::Object => MAX_OBJECT_TAGS,
        }
    }
}

/// Why a tag set was refused: the S3 code to render and a constant explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaggingRejection {
    code: ErrorCode,
    reason: &'static str,
}

impl TaggingRejection {
    const fn new(code: ErrorCode, reason: &'static str) -> Self {
        TaggingRejection { code, reason }
    }

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
}

/// The header's own refusal: every malformed spelling shares AWS's one sentence.
fn malformed_header() -> TaggingRejection {
    TaggingRejection::new(ErrorCode::INVALID_ARGUMENT, MALFORMED_TAGGING_HEADER)
}

/// Reads the packed `x-amz-tagging` header — `a=1&b=2`, form-urlencoded — into ordered pairs.
///
/// This is the header channel of the tag set: the same value the `?tagging` subresource carries as
/// a `<Tagging>` document, packed into one header on `PutObject`, `CopyObject` and
/// `CreateMultipartUpload`. Decoding is `application/x-www-form-urlencoded`, which is not the same
/// alphabet as a path segment: `+` is a space, and `%` begins exactly two hex digits.
///
/// Syntax only, plus the two rules AWS's own header sentence names — no duplicate key, no empty
/// key. The semantic ceilings (count, length, character set) are [`validate_tag_set`]'s, so a
/// caller reads the header and then validates the pairs under its scope, exactly as the XML
/// channel does.
///
/// # Errors
///
/// `InvalidArgument` with AWS's one sentence for a segment with no `=`, a broken or non-UTF-8
/// escape, and a repeated key; `InvalidTag` for an empty key, which has no legal representation in
/// either channel.
pub fn parse_tagging_header(header: Option<&str>) -> Result<Vec<(String, String)>, TaggingRejection> {
    let Some(raw) = header else { return Ok(Vec::new()) };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for segment in raw.split('&') {
        if segment.is_empty() {
            continue;
        }
        let (key, value) = segment.split_once('=').ok_or_else(malformed_header)?;
        let key = form_decode(key)?;
        let value = form_decode(value)?;
        if key.is_empty() {
            return Err(TaggingRejection::new(ErrorCode::INVALID_TAG, INVALID_KEY));
        }
        if pairs.iter().any(|(existing, _)| existing == &key) {
            return Err(malformed_header());
        }
        pairs.push((key, value));
    }
    Ok(pairs)
}

/// One form-urlencoded field, decoded.
///
/// # Errors
///
/// `InvalidArgument` when an escape is truncated, is not hex, or decodes to bytes that are not
/// UTF-8. The header's own wording says "encoded as UTF-8 **then** URLEncoded", so a sequence that
/// survives the second step and fails the first is exactly what it describes.
fn form_decode(text: &str) -> Result<String, TaggingRejection> {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes.get(index) {
            Some(b'+') => out.push(b' '),
            Some(b'%') => {
                let hex = text.get(index + 1..index + 3).ok_or_else(malformed_header)?;
                let byte = u8::from_str_radix(hex, 16).map_err(|_| malformed_header())?;
                out.push(byte);
                index += 2;
            }
            Some(byte) => out.push(*byte),
            None => break,
        }
        index += 1;
    }
    String::from_utf8(out).map_err(|_| malformed_header())
}

/// The refusal a key outside the documented shape answers with.
const INVALID_KEY: &str = "The TagKey you have provided is invalid";

/// The refusal a value outside the documented shape answers with.
const INVALID_VALUE: &str = "The TagValue you have provided is invalid";

/// The refusal a repeated key in a tagging document answers with.
const DUPLICATE_KEY: &str = "There are duplicate keys in your request. Please check and try again.";

/// The refusal an object tag set over its ceiling answers with.
const TOO_MANY_OBJECT_TAGS: &str = "Object tags cannot be greater than 10";

/// The refusal a bucket tag set over its ceiling answers with.
const TOO_MANY_BUCKET_TAGS: &str = "Bucket tag count cannot be greater than 50";

/// The one copy of every semantic tag-set rule, for both channels and both scopes.
///
/// Checks, in order: the scope's count ceiling, then per tag the key (non-empty, at most
/// [`MAX_TAG_KEY_UNITS`] UTF-16 code units, documented character set), the value (at most
/// [`MAX_TAG_VALUE_UNITS`] units, same character set), and finally that no key repeats. The
/// order is observable only through which reason a set violating several rules gets, and it is
/// fixed here so that it cannot differ between the header and the XML channel.
///
/// # Errors
///
/// `InvalidTag` for every violation — the code AWS's `PutBucketTagging` page documents for a tag
/// that fails validation — with a constant reason naming the rule, never the tag.
pub fn validate_tag_set(pairs: &[(String, String)], scope: TagScope) -> Result<(), TaggingRejection> {
    if pairs.len() > scope.max_tags() {
        let reason = match scope {
            TagScope::Bucket => TOO_MANY_BUCKET_TAGS,
            TagScope::Object => TOO_MANY_OBJECT_TAGS,
        };
        return Err(TaggingRejection::new(ErrorCode::INVALID_TAG, reason));
    }
    for (index, (key, value)) in pairs.iter().enumerate() {
        if key.is_empty() || utf16_units(key) > MAX_TAG_KEY_UNITS || !is_legal_tag_text(key) {
            return Err(TaggingRejection::new(ErrorCode::INVALID_TAG, INVALID_KEY));
        }
        if utf16_units(value) > MAX_TAG_VALUE_UNITS || !is_legal_tag_text(value) {
            return Err(TaggingRejection::new(ErrorCode::INVALID_TAG, INVALID_VALUE));
        }
        if pairs.iter().take(index).any(|(existing, _)| existing == key) {
            return Err(TaggingRejection::new(ErrorCode::INVALID_TAG, DUPLICATE_KEY));
        }
    }
    Ok(())
}

/// The length of one label in the units AWS measures it in.
///
/// `str::chars().count()` is the tempting spelling and it is wrong above the basic multilingual
/// plane: a supplementary-plane character is one scalar value and two UTF-16 code units, and AWS
/// documents the second counting. `encode_utf16().count()` walks the string once and allocates
/// nothing, so the honest unit costs nothing over the convenient one.
fn utf16_units(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The documented tag alphabet: letters and numbers in any script, the space, and `+ - = . _ : / @`.
///
/// Deliberately *not* "anything printable". `<` would nest into the XML rendering of the set,
/// `&`, `#` and `?` would corrupt its header rendering, and a control character in a label is a
/// log-injection payload wherever the label is printed. AWS documents the allowed set positively,
/// so this follows the same shape: a character is legal because the list says so.
fn is_legal_tag_text(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || matches!(c, '+' | '-' | '=' | '.' | '_' | ':' | '/' | '@'))
}
