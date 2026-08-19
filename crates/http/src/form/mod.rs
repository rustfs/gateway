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

//! The POST Object form, read so that the file's ceiling is known before the file is.
//!
//! Responsible for: `multipart/form-data` framing for browser POST uploads — the boundary, the
//! per-part headers, the bounded text fields that precede the file, and a file reader that cannot
//! be constructed without a byte ceiling.
//! NOT responsible for: what a policy *means*. Base64, JSON, expiry, conditions, `${filename}`
//! substitution and the signature comparison all live in `rustfs-gateway-sig`'s post-policy module,
//! which sits above this crate and consumes the fields produced here.
//! Upstream: nothing — this module is sans-io and holds no transport. Downstream:
//! `rustfs-gateway-sig` (policy proof) and the POST Object operation.
//!
//! # The ordering is the security property
//!
//! POST Object is the one S3 face where the credential, the policy and the signature arrive
//! *inside the body*, after the head has already been accepted. The policy carries
//! `content-length-range`, which is the only statement anyone has made about how large the upload
//! is allowed to be — there is no `Content-Length` for the file part, and the `Content-Length` of
//! the whole request is chosen by the same peer whose authority has not yet been established.
//!
//! So a limit found *after* the file has been read is not a limit. It is a report about a buffer
//! that already exists. The types here are arranged so that the mistake cannot be written:
//! [`FormReader`] reads text fields and stops dead at the `file` part header, and the only way to
//! obtain a [`FileReader`] is [`FormReader::into_file`], which takes the ceiling as an argument.
//! There is no `FileReader::new`, no `Default`, and no setter that installs a ceiling afterwards.
//! Whoever reads a file byte has already named a bound, because the compiler made them.
//!
//! # And the reader never owns the file
//!
//! A ceiling enforced inside a parser whose caller has already collected the whole body into a
//! buffer is decorative — rustfs/gateway#229 records that exact shape one layer down. This reader
//! therefore hands file bytes to a [`FileSink`] as subslices of the caller's own buffer and keeps
//! only a delimiter-sized carry between calls, so its resident cost is a function of the boundary
//! length and not of the upload. `crates/http/tests/form_allocations.rs` measures that rather than
//! asserting it.
//!
//! # Why the framing is written here rather than taken from a crate
//!
//! The obvious candidate is `multer`. It supplies the framing and not the property above: its
//! `SizeLimit` is fixed when the parser is constructed, and the file ceiling is
//! `min(content-length-range, deployment maximum)` — a value that does not exist until the policy
//! field has been read. Wiring it up would mean constructing with the deployment maximum and then
//! counting the file's bytes separately, which is this module with an async dependency added to a
//! crate that has none.

mod file;
mod reader;

pub use self::file::{FileReader, FileSink, FileStep};
pub use self::reader::{FormReader, FormStep};

/// The form field carrying the base64 POST policy.
///
/// Named here because its ceiling is not the ordinary field ceiling: AWS documents the policy
/// document as bounded at 20 KiB, and [`FormLimits::HARD_MAX_POLICY_BYTES`] is that number.
pub const FORM_POLICY_FIELD: &str = "policy";

/// The form field carrying the object content, which S3 requires to be last.
pub const FORM_FILE_FIELD: &str = "file";

/// The media type a POST Object body must carry.
const MULTIPART_FORM_DATA: &str = "multipart/form-data";

/// The longest boundary RFC 2046 permits, in bytes.
const MAX_BOUNDARY_BYTES: usize = 70;

/// Which ceiling, or which rule, the form crossed.
///
/// Separate from [`crate::LimitKind`] on purpose. `LimitKind` names the ceilings
/// [`crate::WireRequest::accept`] decides from the request head alone, before a body byte is read;
/// everything here is decided *while* reading a body, and folding the two together would put
/// variants into the head's vocabulary that the head can never produce.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormReject {
    /// The `Content-Type` was not `multipart/form-data`, or carried no usable `boundary`.
    MalformedContentType,
    /// A part header block, a delimiter, or a `Content-Disposition` was not well formed.
    MalformedPart,
    /// A field value was not UTF-8, or carried a control character.
    ///
    /// A form field reaches a policy comparison, a log line and an object key. Bytes that are not
    /// text have no business in any of the three, and a value carrying CR or LF is the
    /// header-injection primitive one layer further out.
    MalformedFieldValue,
    /// A part's header block exceeded [`FormLimits::max_part_header_bytes`].
    PartHeaderTooLarge,
    /// A text field exceeded [`FormLimits::max_field_bytes`].
    FieldTooLarge,
    /// The `policy` field exceeded [`FormLimits::max_policy_bytes`].
    PolicyTooLarge,
    /// The form carried more than [`FormLimits::max_field_count`] text fields.
    TooManyFields,
    /// One field name appeared twice.
    ///
    /// Refused rather than resolved, for the reason the crate documentation gives: a first-wins or
    /// last-wins choice lets the signer and the enforcer read different values.
    DuplicateField,
    /// The whole form exceeded [`FormLimits::max_whole_stream_bytes`].
    WholeStreamTooLarge,
    /// The file part exceeded the ceiling named at [`FormReader::into_file`].
    FileTooLarge,
    /// A part arrived after the `file` part.
    ///
    /// S3 requires `file` to be last precisely so that everything needed to authorise the upload
    /// has arrived before the upload does. A form that puts it earlier is refused rather than
    /// buffered, because accepting it means reading bytes whose policy has not been read.
    FieldAfterFile,
    /// The form ended without a `file` part.
    MissingFile,
    /// The form ended in the middle of a part.
    IncompleteStream,
}

impl FormReject {
    /// A short, stable label for logs and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedContentType => "malformed-content-type",
            Self::MalformedPart => "malformed-part",
            Self::MalformedFieldValue => "malformed-field-value",
            Self::PartHeaderTooLarge => "part-header-too-large",
            Self::FieldTooLarge => "field-too-large",
            Self::PolicyTooLarge => "policy-too-large",
            Self::TooManyFields => "too-many-fields",
            Self::DuplicateField => "duplicate-field",
            Self::WholeStreamTooLarge => "whole-stream-too-large",
            Self::FileTooLarge => "file-too-large",
            Self::FieldAfterFile => "field-after-file",
            Self::MissingFile => "missing-file",
            Self::IncompleteStream => "incomplete-stream",
        }
    }
}

impl core::fmt::Display for FormReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for FormReject {}

/// The ceilings a POST Object form is read under.
///
/// Every field is private, for the reason [`crate::ChunkLimits`] gives: the invariants — a policy
/// ceiling that no configuration may raise above the number AWS documents, a whole-stream budget
/// derived from everything it contains — are enforced by the setters, and public fields would let
/// a caller construct exactly the states the setters refuse.
///
/// There is deliberately no unlimited constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormLimits {
    max_field_bytes: usize,
    max_policy_bytes: usize,
    max_field_count: usize,
    max_part_header_bytes: usize,
    max_whole_stream_bytes: u64,
    max_file_bytes: u64,
}

impl FormLimits {
    /// The most text fields a form may carry.
    ///
    /// A POST form's five required fields plus `key`, `bucket`, an ACL, a redirect, a cache
    /// header, a content type, and the `x-amz-meta-*` set a browser upload realistically carries.
    pub const DEFAULT_MAX_FIELD_COUNT: usize = 64;

    /// The default ceiling on one ordinary text field: 8 KiB.
    ///
    /// The largest legitimate non-policy field is `key`, an object key at its 1024-byte ceiling,
    /// alongside a `success_action_redirect` URL. Eight kibibytes is comfortably above both and
    /// far below anything worth buffering.
    pub const DEFAULT_MAX_FIELD_BYTES: usize = 8 * 1024;

    /// The largest `policy` field any configuration may permit: 20 KiB.
    ///
    /// A ceiling on the ceiling, and the number AWS documents for the POST policy document. A
    /// deployment may lower it; nothing may raise it, because a policy above this size is one no
    /// AWS-compatible client can have produced.
    pub const HARD_MAX_POLICY_BYTES: usize = 20 * 1024;

    /// The default ceiling on the `policy` field, which is also the hard ceiling.
    pub const DEFAULT_MAX_POLICY_BYTES: usize = Self::HARD_MAX_POLICY_BYTES;

    /// The default ceiling on one part's header block: 4 KiB.
    ///
    /// A `Content-Disposition` naming a field and a filename, plus a `Content-Type`, is a few
    /// hundred bytes. The remainder is slack so that a malformed block is diagnosed as malformed
    /// rather than as truncated.
    pub const DEFAULT_MAX_PART_HEADER_BYTES: usize = 4 * 1024;

    /// The default deployment ceiling on the file part: 5 GiB.
    ///
    /// The largest object a single S3 PUT or POST can carry. It is the *upper* half of the
    /// `min(policy, deployment)` pair — a policy's `content-length-range` almost always tightens
    /// it, and [`FormReader::into_file`] takes the smaller of the two.
    pub const DEFAULT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

    /// The default ceiling on the whole form, derived rather than chosen.
    ///
    /// It is the sum of everything a form at every other ceiling can legitimately contain: the
    /// file at its ceiling, every text field at its ceiling, the policy at its own larger one, and
    /// one header block per part. Picking a round number instead would eventually put this budget
    /// *underneath* one of the ceilings it contains, and then the specific refusal — "your policy
    /// is too large", which a client can act on — would be replaced by the vague one. That is the
    /// shadowing defect `limits.rs` documents at the query layer, in a second place.
    pub const DEFAULT_MAX_WHOLE_STREAM_BYTES: u64 = Self::DEFAULT_MAX_FILE_BYTES
        + (Self::DEFAULT_MAX_FIELD_COUNT * Self::DEFAULT_MAX_FIELD_BYTES) as u64
        + Self::DEFAULT_MAX_POLICY_BYTES as u64
        + ((Self::DEFAULT_MAX_FIELD_COUNT + 1) * Self::DEFAULT_MAX_PART_HEADER_BYTES) as u64;

    /// The ceiling on one ordinary text field, in bytes.
    #[must_use]
    pub const fn max_field_bytes(&self) -> usize {
        self.max_field_bytes
    }

    /// The ceiling on the `policy` field, in bytes.
    #[must_use]
    pub const fn max_policy_bytes(&self) -> usize {
        self.max_policy_bytes
    }

    /// The most text fields the form may carry.
    #[must_use]
    pub const fn max_field_count(&self) -> usize {
        self.max_field_count
    }

    /// The ceiling on one part's header block, in bytes.
    #[must_use]
    pub const fn max_part_header_bytes(&self) -> usize {
        self.max_part_header_bytes
    }

    /// The ceiling on the whole form, in bytes.
    #[must_use]
    pub const fn max_whole_stream_bytes(&self) -> u64 {
        self.max_whole_stream_bytes
    }

    /// The deployment ceiling on the file part, in bytes.
    #[must_use]
    pub const fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }

    /// Sets the ordinary text-field ceiling, never below one byte.
    #[must_use]
    pub const fn with_max_field_bytes(mut self, bytes: usize) -> Self {
        self.max_field_bytes = if bytes == 0 { 1 } else { bytes };
        self
    }

    /// Sets the `policy` ceiling, never above [`FormLimits::HARD_MAX_POLICY_BYTES`].
    #[must_use]
    pub const fn with_max_policy_bytes(mut self, bytes: usize) -> Self {
        let bytes = if bytes == 0 { 1 } else { bytes };
        self.max_policy_bytes = if bytes > Self::HARD_MAX_POLICY_BYTES {
            Self::HARD_MAX_POLICY_BYTES
        } else {
            bytes
        };
        self
    }

    /// Sets the field-count ceiling, never below one.
    #[must_use]
    pub const fn with_max_field_count(mut self, count: usize) -> Self {
        self.max_field_count = if count == 0 { 1 } else { count };
        self
    }

    /// Sets the part-header ceiling, never below what one `Content-Disposition` needs.
    #[must_use]
    pub const fn with_max_part_header_bytes(mut self, bytes: usize) -> Self {
        self.max_part_header_bytes = if bytes < 128 { 128 } else { bytes };
        self
    }

    /// Sets the whole-form ceiling, never below one byte.
    #[must_use]
    pub const fn with_max_whole_stream_bytes(mut self, bytes: u64) -> Self {
        self.max_whole_stream_bytes = if bytes == 0 { 1 } else { bytes };
        self
    }

    /// Sets the deployment file ceiling, never below one byte.
    #[must_use]
    pub const fn with_max_file_bytes(mut self, bytes: u64) -> Self {
        self.max_file_bytes = if bytes == 0 { 1 } else { bytes };
        self
    }
}

impl Default for FormLimits {
    fn default() -> Self {
        Self {
            max_field_bytes: Self::DEFAULT_MAX_FIELD_BYTES,
            max_policy_bytes: Self::DEFAULT_MAX_POLICY_BYTES,
            max_field_count: Self::DEFAULT_MAX_FIELD_COUNT,
            max_part_header_bytes: Self::DEFAULT_MAX_PART_HEADER_BYTES,
            max_whole_stream_bytes: Self::DEFAULT_MAX_WHOLE_STREAM_BYTES,
            max_file_bytes: Self::DEFAULT_MAX_FILE_BYTES,
        }
    }
}

/// One text field read from the form, in the order it arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormField {
    name: String,
    value: String,
}

impl FormField {
    /// Builds one field. Crate-private: fields are produced by the reader, never by a caller.
    pub(super) fn new(name: String, value: String) -> Self {
        Self { name, value }
    }

    /// The field name, lowercased because the POST policy vocabulary is case-insensitive.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The field value, exactly as it arrived.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Extracts the boundary from a `multipart/form-data` content type.
fn parse_boundary(content_type: &str) -> Result<String, FormReject> {
    let mut parts = content_type.split(';');
    let Some(media) = parts.next() else {
        return Err(FormReject::MalformedContentType);
    };
    if !media.trim().eq_ignore_ascii_case(MULTIPART_FORM_DATA) {
        return Err(FormReject::MalformedContentType);
    }
    let mut found: Option<String> = None;
    for parameter in parts {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        // Two `boundary` parameters is the same ambiguity the header layer refuses: one component
        // would frame the body one way and another the other way.
        if found.is_some() {
            return Err(FormReject::MalformedContentType);
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(value);
        found = Some(value.to_owned());
    }
    let boundary = found.ok_or(FormReject::MalformedContentType)?;
    if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_BYTES {
        return Err(FormReject::MalformedContentType);
    }
    if !boundary.bytes().all(|byte| byte.is_ascii_graphic() || byte == b' ') {
        return Err(FormReject::MalformedContentType);
    }
    Ok(boundary)
}

/// Reads `name` and `filename` out of one part's header block.
fn parse_disposition(block: &[u8]) -> Result<(String, Option<String>), FormReject> {
    let Ok(text) = core::str::from_utf8(block) else {
        return Err(FormReject::MalformedPart);
    };
    let mut disposition = None;
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(FormReject::MalformedPart);
        };
        if name.trim().eq_ignore_ascii_case("content-disposition") {
            if disposition.is_some() {
                return Err(FormReject::MalformedPart);
            }
            disposition = Some(value.trim().to_owned());
        }
    }
    let Some(disposition) = disposition else {
        return Err(FormReject::MalformedPart);
    };
    let mut parameters = disposition.split(';');
    let Some(kind) = parameters.next() else {
        return Err(FormReject::MalformedPart);
    };
    if !kind.trim().eq_ignore_ascii_case("form-data") {
        return Err(FormReject::MalformedPart);
    }
    let mut field = None;
    let mut filename = None;
    for parameter in parameters {
        let Some((key, value)) = parameter.trim().split_once('=') else {
            return Err(FormReject::MalformedPart);
        };
        let Some(value) = value.trim().strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) else {
            return Err(FormReject::MalformedPart);
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "name" => {
                if field.is_some() {
                    return Err(FormReject::MalformedPart);
                }
                field = Some(value.to_ascii_lowercase());
            }
            "filename" => {
                if filename.is_some() {
                    return Err(FormReject::MalformedPart);
                }
                filename = Some(value.to_owned());
            }
            _ => {}
        }
    }
    let Some(field) = field else {
        return Err(FormReject::MalformedPart);
    };
    if field.is_empty() || crate::text::contains_forbidden_control(field.as_bytes()) {
        return Err(FormReject::MalformedPart);
    }
    Ok((field, filename))
}

/// The first position at which `needle` occurs in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let last = haystack.len().saturating_sub(needle.len());
    let first = *needle.first()?;
    for start in 0..=last {
        if haystack.get(start) != Some(&first) {
            continue;
        }
        if haystack.get(start..start.saturating_add(needle.len())) == Some(needle) {
            return Some(start);
        }
    }
    None
}
