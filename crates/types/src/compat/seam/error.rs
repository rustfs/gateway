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

//! The handler-error migration seam: what the gateway must answer for an `s3s::S3Error` a RustFS
//! app body returned, for the s3s revision this file is compiled against (`super::s3s`).
//!
//! Responsible for: turning the error into a [`Refusal`] — the code, status and message the s3s
//! service would have written, or the typed context the gateway renders a contextual code from,
//! including the facts a GetObject/HeadObject body states in the error's own headers (the entity
//! tag of a `304`, the complete length of a `416`, the identity of a delete marker) — and refusing,
//! by member name, an error the gateway cannot answer the way s3s would: a contextual code with no
//! typed context, a fact header that is missing, repeated or malformed, a status that is not a
//! refusal, a code that is not an identifier, text that XML 1.0 cannot carry, or a response header
//! the verdict has no member for.
//! NOT responsible for: building the gateway `HandlerError` (ring-1 `rustfs-gateway-core`, which
//! this ring-0 crate may not name; the ring-2 adapter matches on [`Refusal`] and calls the one
//! constructor each variant names), rendering the document, or supplying what only the request
//! holds — the key, and the `Range` a `416` names (the adapter holds the request).
//! And, for the RustFS profile, reading the same error as the legacy stack writes it
//! ([`refusal_from_legacy`]): its status, code, message and fact headers exactly, with nothing the
//! typed verdicts would add, refusing by name only what the gateway cannot write the same way.
//! Upstream: the s3s error of the bound revision. Downstream: the goldens error-parity diff under
//! every seam revision, and the RustFS ring-2 adapter through the revision RustFS links
//! (rustfs/backlog#1752, rustfs/backlog#1762, rustfs/gateway#1148).
//!
//! # Why a verdict and not a code
//!
//! The gateway resolves ten codes only from typed facts (`is_contextual` in
//! `rustfs-gateway-core`'s `error_resolution`) and answers `500 InternalError` for a bare
//! `HandlerError` carrying one. The first RustFS bridge mapped `NoSuchBucket` by hand and left the
//! other nine to that `500`. Naming the context here, once, keeps the list next to the conversion
//! and lets the goldens diff hold it to the gateway's own.

use super::s3s;
use http::StatusCode;

use crate::compat::ConversionError;
use crate::{ETag, ErrorCode, EtagRender, Timestamp, TimestampFormat};

/// The longest message the gateway's error resolution admits; a longer one would be a `500`.
pub const MAX_MESSAGE_BYTES: usize = 1024;

/// The longest code the gateway's error resolution admits.
pub const MAX_CODE_BYTES: usize = 128;

/// The codes the gateway renders only from typed context, in its `is_contextual` order. The
/// goldens diff proves every one is refused as a bare `HandlerError` and no other known code is.
pub const CONTEXTUAL_CODES: [&str; 10] = [
    "NoSuchKey",
    "NoSuchVersion",
    "NoSuchBucket",
    "PermanentRedirect",
    "TemporaryRedirect",
    "NotModified",
    "AuthorizationHeaderMalformed",
    "MethodNotAllowed",
    "BucketAlreadyOwnedByYou",
    "AccessForbidden",
];

/// Codes the gateway renders only with facts beyond the code: `416 InvalidRange` must state the
/// object's complete length in `Content-Range` and `<ActualObjectSize>`, and the gateway answers
/// `500` for one without them. The goldens diff proves that too. The seam reads the length from the
/// error's `Content-Range: bytes */<length>`, as it reads a `304`'s entity tag from `ETag`.
pub const NEEDS_FACTS_CODES: [&str; 1] = ["InvalidRange"];

/// What the gateway answers for one s3s handler error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `HandlerError::new(code, message)`: a code and a message with no context.
    Ordinary {
        /// The declared code when s3s renders it with the declared status, otherwise a custom code
        /// carrying the status s3s would have written.
        code: ErrorCode,
        /// The s3s message, else the revision's default sentence for the code, else empty.
        message: String,
    },
    /// `HandlerErrorContext::missing_bucket()`: `404 NoSuchBucket`.
    MissingBucket,
    /// `HandlerErrorContext::missing_object_for(key, MissingObject::Key, ResourceVisibility::Visible)`:
    /// `404 NoSuchKey`. Visible, because a RustFS body answers `NoSuchKey` only after its own access
    /// check passed; the adapter supplies the key it holds.
    MissingKey,
    /// The same with `MissingObject::Version`: `404 NoSuchVersion`.
    MissingVersion,
    /// `HandlerErrorContext::not_modified(etag)`: `304` carrying the entity tag the error's `ETag`
    /// header states.
    NotModified {
        /// The representation's entity tag.
        etag: ETag,
    },
    /// `HandlerError::unsatisfiable_range(requested, complete_length)`: `416 InvalidRange` with
    /// `Content-Range: bytes */<complete_length>`. The adapter supplies `requested`, the request's
    /// own `Range` value, as it supplies the key: the s3s error does not carry it.
    UnsatisfiableRange {
        /// The complete length the error's `Content-Range: bytes */<length>` states.
        complete_length: u64,
    },
    /// `HandlerErrorContext::current_delete_marker(ResourceVisibility::Visible, key, last_modified)`:
    /// `404 NoSuchKey` with the marker header. Visible for the reason [`Self::MissingKey`] is.
    CurrentDeleteMarker {
        /// The marker's version id, from `x-amz-version-id`.
        version_id: String,
        /// When the marker was written, in Unix seconds, from `Last-Modified`.
        last_modified: i64,
    },
    /// `HandlerErrorContext::versioned_delete_marker(&version_id, last_modified)`:
    /// `405 MethodNotAllowed` with the marker header.
    VersionedDeleteMarker {
        /// The marker's version id, from `x-amz-version-id`.
        version_id: String,
        /// When the marker was written, in Unix seconds, from `Last-Modified`.
        last_modified: i64,
    },
}

/// Why the legacy decoder refused a request whose member only it reads: a query parameter it saw
/// twice. The member's [`ConversionError::field`] names the parameter.
pub const LEGACY_DUPLICATE_QUERY: &str = "a query parameter the legacy decoder refuses to see twice";

/// As [`LEGACY_DUPLICATE_QUERY`], for a header line it saw twice.
pub const LEGACY_DUPLICATE_HEADER: &str = "a header the legacy decoder refuses to see twice";

/// As [`LEGACY_DUPLICATE_QUERY`], for a header value outside its boolean grammar.
pub const LEGACY_INVALID_BOOLEAN: &str = "not a boolean the legacy decoder accepts";

/// As [`LEGACY_DUPLICATE_QUERY`], for a header value the legacy decoder cannot read: text it cannot
/// decode, or an `x-amz-trailer` declaration naming two checksum headers.
pub const LEGACY_INVALID_HEADER: &str = "a header value the legacy decoder refuses";

/// What the gateway answers for a conversion the legacy decoder would have refused before any
/// RustFS body ran: the member only the legacy decoder reads (`leaf::legacy_query`,
/// `leaf::legacy_bool_header`) held a value it rejects. The code and status are the legacy
/// decoder's (`InvalidRequest` for a repeated parameter or header, `InvalidArgument` for a value
/// it cannot parse); the message names the parameter or header, not its value. `None` for any
/// other conversion error, which the adapter answers as an internal error.
#[must_use]
pub fn refusal_from_conversion(error: &ConversionError) -> Option<Refusal> {
    let (code, message) = match error.reason {
        LEGACY_DUPLICATE_QUERY => (ErrorCode::INVALID_REQUEST, format!("duplicate query: {}", error.field)),
        LEGACY_DUPLICATE_HEADER => (ErrorCode::INVALID_REQUEST, format!("duplicate header: {}", error.field)),
        LEGACY_INVALID_BOOLEAN | LEGACY_INVALID_HEADER => {
            (ErrorCode::INVALID_ARGUMENT, format!("invalid header: {}", error.field))
        }
        _ => return None,
    };
    Some(Refusal::Ordinary { code, message })
}

/// The one header an s3s error may carry that the gateway writes itself: s3s replaces the
/// response head with the error's header map, so RustFS re-adds the XML type there.
const WRITTEN_BY_THE_GATEWAY: [&str; 1] = ["content-type"];

const ETAG: &str = "etag";
const CONTENT_RANGE: &str = "content-range";
const DELETE_MARKER: &str = "x-amz-delete-marker";
const VERSION_ID: &str = "x-amz-version-id";
const LAST_MODIFIED: &str = "last-modified";

/// The headers a delete-marker read states its marker with (RustFS `with_delete_marker_read_headers`).
const MARKER_FACTS: [&str; 3] = [DELETE_MARKER, VERSION_ID, LAST_MODIFIED];

/// Maps an s3s handler error to what the gateway answers for it.
///
/// A `NotModified` carrying `ETag`, an `InvalidRange` carrying `Content-Range: bytes */<length>`,
/// and a `NoSuchKey` or `MethodNotAllowed` carrying `x-amz-delete-marker: true`, `x-amz-version-id`
/// and `Last-Modified` become the typed verdicts that state those facts. Every other error may
/// carry no header but `Content-Type`.
///
/// # Errors
///
/// [`ConversionError`] naming `code` for a contextual code this seam has no typed context for, or
/// a code that is not an identifier of at most [`MAX_CODE_BYTES`]; the header's own name for a fact
/// header that is missing, repeated or malformed; `headers` for a response header the verdict has
/// no member for; `status_code` for a status outside 4xx and 5xx; `message` for text XML 1.0
/// cannot carry.
pub fn refusal_from_s3s(error: &s3s::S3Error) -> Result<Refusal, ConversionError> {
    let facts = Facts(error.headers());
    let name = error.code().as_str();
    let marker = facts.states(DELETE_MARKER);
    let refusal = match name {
        "NotModified" => {
            facts.only(&[ETAG])?;
            Refusal::NotModified { etag: facts.etag()? }
        }
        "InvalidRange" => {
            facts.only(&[CONTENT_RANGE])?;
            Refusal::UnsatisfiableRange {
                complete_length: facts.complete_length()?,
            }
        }
        "NoSuchKey" if marker => {
            let (version_id, last_modified) = facts.marker()?;
            Refusal::CurrentDeleteMarker {
                version_id,
                last_modified,
            }
        }
        "MethodNotAllowed" if marker => {
            let (version_id, last_modified) = facts.marker()?;
            Refusal::VersionedDeleteMarker {
                version_id,
                last_modified,
            }
        }
        _ => {
            facts.only(&[])?;
            match name {
                "NoSuchBucket" => Refusal::MissingBucket,
                "NoSuchKey" => Refusal::MissingKey,
                "NoSuchVersion" => Refusal::MissingVersion,
                _ if CONTEXTUAL_CODES.contains(&name) || NEEDS_FACTS_CODES.contains(&name) => {
                    return Err(ConversionError {
                        field: "code",
                        reason: "the gateway renders this code from typed facts the s3s error does not carry",
                    });
                }
                _ => ordinary(error)?,
            }
        }
    };
    Ok(refusal)
}

/// A code the gateway admits bare, with the status and message s3s would write.
fn ordinary(error: &s3s::S3Error) -> Result<Refusal, ConversionError> {
    let name = error.code().as_str();
    if !is_identifier(name) {
        return Err(ConversionError {
            field: "code",
            reason: "not an ASCII identifier of at most 128 bytes",
        });
    }
    let status = error
        .status_code()
        .or_else(|| error.code().status_code())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if !(status.is_client_error() || status.is_server_error()) {
        return Err(ConversionError {
            field: "status_code",
            reason: "an error document is written only for a 4xx or 5xx status",
        });
    }
    let code = match ErrorCode::known(name) {
        Some(known) if known.default_status() == status => known,
        _ => ErrorCode::custom(name.to_owned(), status),
    };
    let text = error
        .message()
        .or_else(|| super::default_message(error.code()))
        .unwrap_or_default();
    if !text.chars().all(is_xml_char) {
        return Err(ConversionError {
            field: "message",
            reason: "holds a character XML 1.0 cannot carry",
        });
    }
    Ok(Refusal::Ordinary {
        code,
        message: truncated(text).to_owned(),
    })
}

/// One error a RustFS app body returned, read as the legacy stack writes it: what the RustFS
/// profile answers (`HandlerErrorContext::legacy_rustfs` in `rustfs-gateway-core`, built member for
/// member from this value by the ring-2 adapter).
///
/// Every member is exactly what the legacy stack puts on the wire for the error, so an answer built
/// from it is legacy RustFS's answer: the status the code carries, the `<Message>` text or none,
/// and each fact header only when the error carried it. The request id and host id the gateway
/// stamps are not the error's (rd-err-0001).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyRefusal {
    /// The code, answered at its own status: the declared code when the legacy stack writes it at
    /// the declared status, otherwise a custom code carrying the status the legacy stack writes.
    pub code: ErrorCode,
    /// The `<Message>` text, or `None` when the legacy document has no `<Message>`.
    pub message: Option<String>,
    /// The `ETag` of a `304`, when the error states one.
    pub etag: Option<ETag>,
    /// The `Last-Modified` of a `304` or a delete-marker read, in Unix seconds, when stated.
    pub last_modified: Option<i64>,
    /// The version id of the delete marker a `NoSuchKey` or `MethodNotAllowed` read found, when the
    /// error states `x-amz-delete-marker: true`.
    pub delete_marker: Option<String>,
    /// The complete length of a `416`, when the error states `Content-Range: bytes */<length>`.
    pub complete_length: Option<u64>,
}

/// Reads a RustFS body's handler error as the legacy stack writes it, for the RustFS profile.
///
/// The legacy stack answers with the error's status (its own, else the code's), writes `<Code>` and
/// the error's `<Message>` when it has one, and, when the error carries a header map, sends that
/// map in place of its own head — dropping `Content-Type` and `Content-Length` from a bodyless
/// `304`. Legacy RustFS attaches four facts that way: `ETag` and `Last-Modified` on a `304`
/// (`rustfs/src/storage/ecfs_extend.rs:557-604` on rustfs/rustfs `e870a6d25b`), none on the `304` of
/// a conditional `HEAD` (`rustfs/src/app/object/head.rs:423,431`), and the delete-marker flag,
/// version id and, on a versioned read only, `Last-Modified` with the `Content-Type` it re-adds
/// (`rustfs/src/app/object/shared.rs:60-100`); its `416` carries none
/// (`rustfs/src/app/object/shared.rs:159-174`). Each is read here only when present, and every
/// value must be spelled exactly as the gateway will write it again, so the answer is the same
/// bytes.
///
/// Unlike [`refusal_from_s3s`], nothing is resolved from typed context and nothing is cut: a
/// contextual code crosses as the legacy answer, and a message crosses whole.
///
/// # Errors
///
/// [`ConversionError`] naming what the gateway cannot write as the legacy stack writes it:
/// - `code`: not an identifier of at most [`MAX_CODE_BYTES`];
/// - `status_code`: a status that is neither 4xx nor 5xx nor the `304` of `NotModified`, or a
///   `NotModified` at another status;
/// - `message`: text XML 1.0 cannot carry;
/// - `request_id`: a request id the app body set, which the legacy document would carry and the
///   gateway, writing its own, cannot;
/// - `headers`: a header its code does not state (only `Content-Type` accompanies every code);
/// - `content-type`: a header map without `Content-Type: application/xml` on an answer with a
///   document, which the legacy stack would send untyped or typed otherwise;
/// - the fact header's own name: a fact repeated, or spelled other than the gateway writes it (a
///   quoted entity tag, an IMF-fixdate, the flag `true`, a non-empty version id, `bytes */<length>`
///   in shortest decimal).
pub fn refusal_from_legacy(error: &s3s::S3Error) -> Result<LegacyRefusal, ConversionError> {
    let name = error.code().as_str();
    if !is_identifier(name) {
        return Err(ConversionError {
            field: "code",
            reason: "not an ASCII identifier of at most 128 bytes",
        });
    }
    let status = error
        .status_code()
        .or_else(|| error.code().status_code())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let not_modified = name == "NotModified";
    let bodyless = status == StatusCode::NOT_MODIFIED;
    if not_modified != bodyless || !(bodyless || status.is_client_error() || status.is_server_error()) {
        return Err(ConversionError {
            field: "status_code",
            reason: "the legacy answer is a 4xx or 5xx refusal, or the 304 of NotModified",
        });
    }
    let message = error.message();
    if message.is_some_and(|text| !text.chars().all(is_xml_char)) {
        return Err(ConversionError {
            field: "message",
            reason: "holds a character XML 1.0 cannot carry",
        });
    }
    // The legacy document carries a request id only when the app body set one, which legacy RustFS
    // never does; the gateway writes its own (rd-err-0001), so a body that set one is refused.
    if error.request_id().is_some() {
        return Err(ConversionError {
            field: "request_id",
            reason: "the gateway writes its own request id in the document",
        });
    }
    let facts = Facts(error.headers());
    let marker = facts.states(DELETE_MARKER);
    let marker_code = matches!(
        (name, status),
        ("NoSuchKey", StatusCode::NOT_FOUND) | ("MethodNotAllowed", StatusCode::METHOD_NOT_ALLOWED)
    );
    match (name, marker && marker_code) {
        ("NotModified", _) => facts.only(&[ETAG, LAST_MODIFIED])?,
        ("InvalidRange", _) => facts.only(&[CONTENT_RANGE])?,
        (_, true) => facts.only(&MARKER_FACTS)?,
        _ => facts.only(&[])?,
    }
    if !bodyless && error.headers().is_some() && facts.optional(CONTENT_TYPE)? != Some(XML_CONTENT_TYPE) {
        return Err(ConversionError {
            field: CONTENT_TYPE,
            reason: "a legacy error document is sent with the error's own header map, which must type it application/xml",
        });
    }
    let delete_marker = match marker && marker_code {
        true => Some(facts.legacy_marker()?),
        false => None,
    };
    let last_modified = match not_modified || delete_marker.is_some() {
        true => facts.optional(LAST_MODIFIED)?.map(canonical_http_date).transpose()?,
        false => None,
    };
    let etag = match not_modified {
        true => facts.optional(ETAG)?.map(canonical_etag).transpose()?,
        false => None,
    };
    let complete_length = match name {
        "InvalidRange" => facts.optional(CONTENT_RANGE)?.map(canonical_complete_length).transpose()?,
        _ => None,
    };
    let code = match ErrorCode::known(name) {
        Some(known) if known.default_status() == status => known,
        _ => ErrorCode::custom(name.to_owned(), status),
    };
    Ok(LegacyRefusal {
        code,
        message: message.map(str::to_owned),
        etag,
        last_modified,
        delete_marker,
        complete_length,
    })
}

const CONTENT_TYPE: &str = "content-type";
const XML_CONTENT_TYPE: &str = "application/xml";

/// An entity tag the gateway writes back as the same header value.
fn canonical_etag(value: &str) -> Result<ETag, ConversionError> {
    match ETag::parse_http_header(value) {
        Ok(etag) if !etag.is_any() && etag.render(EtagRender::HeaderQuoted) == value => Ok(etag),
        _ => Err(ConversionError {
            field: ETAG,
            reason: "not one entity tag spelled as the gateway writes it",
        }),
    }
}

/// An IMF-fixdate the gateway writes back as the same header value.
fn canonical_http_date(value: &str) -> Result<i64, ConversionError> {
    let refused = || ConversionError {
        field: LAST_MODIFIED,
        reason: "not an IMF-fixdate spelled as the gateway writes it",
    };
    let seconds = Timestamp::parse(value, TimestampFormat::HttpDate)
        .map_err(|_| refused())?
        .secs();
    match Timestamp::from_secs(seconds).render(TimestampFormat::HttpDate) {
        Ok(rendered) if rendered == value => Ok(seconds),
        _ => Err(refused()),
    }
}

/// `bytes */<length>` with the length in shortest decimal, as the gateway writes it.
fn canonical_complete_length(value: &str) -> Result<u64, ConversionError> {
    let refused = || ConversionError {
        field: CONTENT_RANGE,
        reason: "not the unsatisfied form bytes */<complete-length> spelled as the gateway writes it",
    };
    let digits = value.strip_prefix("bytes */").ok_or_else(refused)?;
    let length: u64 = match digits.bytes().all(|byte| byte.is_ascii_digit()) {
        true => digits.parse().map_err(|_| refused())?,
        false => return Err(refused()),
    };
    match length.to_string() == digits {
        true => Ok(length),
        false => Err(refused()),
    }
}

/// The response headers of one s3s error, read as the facts a verdict states.
struct Facts<'a>(Option<&'a http::HeaderMap>);

impl Facts<'_> {
    fn states(&self, name: &str) -> bool {
        self.0.is_some_and(|headers| headers.contains_key(name))
    }

    /// Refuses a header that is neither `Content-Type` nor one of `admitted`: dropping it would
    /// answer differently from s3s, which writes every one.
    fn only(&self, admitted: &[&str]) -> Result<(), ConversionError> {
        let beyond = |name: &http::HeaderName| {
            let name = name.as_str();
            !WRITTEN_BY_THE_GATEWAY.contains(&name) && !admitted.contains(&name)
        };
        if self.0.is_some_and(|headers| headers.keys().any(beyond)) {
            return Err(ConversionError {
                field: "headers",
                reason: "the gateway refusal carries only its closed header set",
            });
        }
        Ok(())
    }

    /// The one visible-ASCII value of `name`; absent, repeated or other text is refused by `name`.
    fn single(&self, name: &'static str) -> Result<&str, ConversionError> {
        let refused = || ConversionError {
            field: name,
            reason: "the fact must be stated exactly once, as visible ASCII",
        };
        let headers = self.0.ok_or_else(refused)?;
        let mut values = headers.get_all(name).iter();
        match (values.next(), values.next()) {
            (Some(value), None) => value.to_str().map_err(|_| refused()),
            _ => Err(refused()),
        }
    }

    fn etag(&self) -> Result<ETag, ConversionError> {
        match ETag::parse_http_header(self.single(ETAG)?) {
            Ok(etag) if !etag.is_any() => Ok(etag),
            _ => Err(ConversionError {
                field: ETAG,
                reason: "not one entity tag",
            }),
        }
    }

    /// The length in the unsatisfied form `bytes */<length>`, RFC 9110 §14.4.
    fn complete_length(&self) -> Result<u64, ConversionError> {
        let refused = || ConversionError {
            field: CONTENT_RANGE,
            reason: "not the unsatisfied form bytes */<complete-length>",
        };
        let length = self.single(CONTENT_RANGE)?.strip_prefix("bytes */").ok_or_else(refused)?;
        if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(refused());
        }
        length.parse().map_err(|_| refused())
    }

    /// The one visible-ASCII value of `name`, or `None` when the error does not state it; a
    /// repeated or unreadable value is refused by `name`.
    fn optional(&self, name: &'static str) -> Result<Option<&str>, ConversionError> {
        match self.0.is_some_and(|headers| headers.contains_key(name)) {
            true => self.single(name).map(Some),
            false => Ok(None),
        }
    }

    /// The marker's version id, with the flag stating `true`; the instant is optional here, as
    /// legacy RustFS states it on a versioned read only.
    fn legacy_marker(&self) -> Result<String, ConversionError> {
        if self.single(DELETE_MARKER)? != "true" {
            return Err(ConversionError {
                field: DELETE_MARKER,
                reason: "a delete-marker read states the flag as true",
            });
        }
        match self.single(VERSION_ID)? {
            "" => Err(ConversionError {
                field: VERSION_ID,
                reason: "a delete marker has a version id",
            }),
            version_id => Ok(version_id.to_owned()),
        }
    }

    /// The marker's version id and write instant, with the flag stating `true`.
    fn marker(&self) -> Result<(String, i64), ConversionError> {
        self.only(&MARKER_FACTS)?;
        if self.single(DELETE_MARKER)? != "true" {
            return Err(ConversionError {
                field: DELETE_MARKER,
                reason: "a delete-marker read states the flag as true",
            });
        }
        let version_id = self.single(VERSION_ID)?;
        if version_id.is_empty() {
            return Err(ConversionError {
                field: VERSION_ID,
                reason: "a delete marker has a version id",
            });
        }
        let last_modified = Timestamp::parse(self.single(LAST_MODIFIED)?, TimestampFormat::HttpDate)
            .map_err(|_| ConversionError {
                field: LAST_MODIFIED,
                reason: "not an HTTP date",
            })?
            .secs();
        Ok((version_id.to_owned(), last_modified))
    }
}

/// `text` cut to at most [`MAX_MESSAGE_BYTES`] on a character boundary. Cut rather than refused:
/// the code and status are what a client branches on, and a RustFS `InvalidArgument` names its
/// reason at whatever length it has.
fn truncated(text: &str) -> &str {
    if text.len() <= MAX_MESSAGE_BYTES {
        return text;
    }
    let mut end = MAX_MESSAGE_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The gateway's code grammar: an ASCII letter, then ASCII letters and digits.
fn is_identifier(code: &str) -> bool {
    let mut bytes = code.bytes();
    code.len() <= MAX_CODE_BYTES
        && bytes.next().is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric())
}

/// XML 1.0 `Char`, which a Rust `char` already confines to scalar values.
const fn is_xml_char(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}
