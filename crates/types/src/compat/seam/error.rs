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
//! Upstream: the s3s error of the bound revision. Downstream: the goldens error-parity diff under
//! every seam revision, and the RustFS ring-2 adapter through the revision RustFS links
//! (rustfs/backlog#1752, rustfs/backlog#1762).
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
use crate::{ETag, ErrorCode, Timestamp, TimestampFormat};

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
        LEGACY_INVALID_BOOLEAN => (ErrorCode::INVALID_ARGUMENT, format!("invalid header: {}", error.field)),
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
