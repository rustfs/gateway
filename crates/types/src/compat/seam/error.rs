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
//! service would have written, or the typed context the gateway renders a contextual code from —
//! and refusing, by member name, an error the gateway cannot answer the way s3s would: a
//! contextual code with no typed context, a status that is not a refusal, a code that is not an
//! identifier, text that XML 1.0 cannot carry, or response headers the gateway's closed header set
//! has no member for.
//! NOT responsible for: building the gateway `HandlerError` (ring-1 `rustfs-gateway-core`, which
//! this ring-0 crate may not name; the ring-2 adapter matches on [`Refusal`] and calls the one
//! constructor each variant names), rendering the document, or choosing which request fields a
//! context carries (the adapter holds the request).
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

use crate::ErrorCode;
use crate::compat::ConversionError;

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

/// Codes the gateway renders only with facts the s3s error does not carry: `416 InvalidRange` must
/// state the object's complete length in `Content-Range` and `<ActualObjectSize>`, and the gateway
/// answers `500` for one without them. The goldens diff proves that too.
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
}

/// The one header an s3s error may carry that the gateway writes itself: s3s replaces the
/// response head with the error's header map, so RustFS re-adds the XML type there.
const WRITTEN_BY_THE_GATEWAY: [&str; 1] = ["content-type"];

/// Maps an s3s handler error to what the gateway answers for it.
///
/// # Errors
///
/// [`ConversionError`] naming `code` for a contextual code this seam has no typed context for, or
/// a code that is not an identifier of at most [`MAX_CODE_BYTES`]; `status_code` for a status
/// outside 4xx and 5xx; `message` for text XML 1.0 cannot carry; `headers` for a response header
/// other than `Content-Type`.
pub fn refusal_from_s3s(error: &s3s::S3Error) -> Result<Refusal, ConversionError> {
    if let Some(headers) = error.headers()
        && headers.keys().any(|name| !WRITTEN_BY_THE_GATEWAY.contains(&name.as_str()))
    {
        return Err(ConversionError {
            field: "headers",
            reason: "the gateway refusal carries only its closed header set",
        });
    }
    let name = error.code().as_str();
    match name {
        "NoSuchBucket" => return Ok(Refusal::MissingBucket),
        "NoSuchKey" => return Ok(Refusal::MissingKey),
        "NoSuchVersion" => return Ok(Refusal::MissingVersion),
        _ if CONTEXTUAL_CODES.contains(&name) || NEEDS_FACTS_CODES.contains(&name) => {
            return Err(ConversionError {
                field: "code",
                reason: "the gateway renders this code from typed facts the s3s error does not carry",
            });
        }
        _ => {}
    }
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
