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

//! The admission checks an ordinary refusal passes before it enters resolution.
//!
//! Responsible for: bounding a code, a message and a detail's text, naming the codes that need a
//! context, and refusing a header or detail a code may not carry or that only resolution may state.
//! NOT responsible for: choosing any response shape (the parent's `resolve`), or validating the
//! facts a named context carries (its constructor in the parent).
//! Upstream: the parent's `ErrorContext` constructors. Downstream: the parent.

use rustfs_gateway_types::{ErrorCode, is_xml_representable};

use super::{InvalidErrorContext, MAX_BUCKET_BYTES, MAX_CODE_BYTES, MAX_KEY_BYTES, MAX_MESSAGE_BYTES, MAX_RANGE_BYTES};
use crate::{ErrorDetail, ErrorHeader, HandlerError};

pub(super) fn validate_code(code: &ErrorCode) -> Result<(), InvalidErrorContext> {
    if code.is_known() || valid_identifier(code.as_str(), MAX_CODE_BYTES, None) {
        Ok(())
    } else {
        Err(InvalidErrorContext::InvalidCode)
    }
}

/// A letter, then letters, digits and `also`: an error code admits nothing more, and a codec
/// refusal's member also admits `_`, because it may name a claimed row's path parameter
/// (`target_type`, ADR-0024 and ADR-0027).
pub(super) fn valid_identifier(value: &str, max: usize, also: Option<u8>) -> bool {
    if value.is_empty() || value.len() > max || !is_xml_representable(value) {
        return false;
    }
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || Some(byte) == also)
}

pub(super) fn validate_message(message: &str) -> Result<(), InvalidErrorContext> {
    if message.len() <= MAX_MESSAGE_BYTES && is_xml_representable(message) {
        Ok(())
    } else {
        Err(InvalidErrorContext::InvalidMessage)
    }
}

pub(super) fn is_contextual(code: &ErrorCode) -> bool {
    code == &ErrorCode::NO_SUCH_KEY
        || code == &ErrorCode::NO_SUCH_VERSION
        || code == &ErrorCode::NO_SUCH_BUCKET
        || code == &ErrorCode::PERMANENT_REDIRECT
        || code == &ErrorCode::TEMPORARY_REDIRECT
        || code == &ErrorCode::NOT_MODIFIED
        || code == &ErrorCode::AUTHORIZATION_HEADER_MALFORMED
        || code == &ErrorCode::METHOD_NOT_ALLOWED
        || code == &ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU
        || code == &ErrorCode::ACCESS_FORBIDDEN
}

pub(super) fn validate_extras(error: &HandlerError) -> Result<(), InvalidErrorContext> {
    let code = error.code();
    let mut range_header = None;
    let mut range_text = false;
    let mut actual_size = None;

    for header in error.headers() {
        match header {
            ErrorHeader::UnsatisfiedRange { complete_length } => {
                if code != &ErrorCode::INVALID_RANGE {
                    return Err(InvalidErrorContext::InvalidDetail);
                }
                range_header = Some(*complete_length);
            }
            ErrorHeader::RetryAfter { .. } => {
                if code != &ErrorCode::SLOW_DOWN && code != &ErrorCode::SERVICE_UNAVAILABLE {
                    return Err(InvalidErrorContext::InvalidDetail);
                }
            }
            // Five facts only resolution may state. A backend that could attach them could
            // announce a bucket lives elsewhere, or announce a deletion, on any refusal it liked.
            ErrorHeader::BucketRegion { .. }
            | ErrorHeader::RedirectLocation { .. }
            | ErrorHeader::DeleteMarker
            | ErrorHeader::VersionId { .. }
            | ErrorHeader::LastModified { .. } => {
                return Err(InvalidErrorContext::ReservedExtra);
            }
        }
    }

    for detail in error.details() {
        match detail {
            ErrorDetail::Key(text) => {
                validate_detail_text(text, MAX_KEY_BYTES)?;
                if code != &ErrorCode::INVALID_OBJECT_STATE {
                    return Err(InvalidErrorContext::InvalidDetail);
                }
            }
            ErrorDetail::BucketName(text) => {
                validate_detail_text(text, MAX_BUCKET_BYTES)?;
                return Err(InvalidErrorContext::ReservedExtra);
            }
            ErrorDetail::Condition(text) => {
                validate_detail_text(text, 32)?;
                if code != &ErrorCode::PRECONDITION_FAILED
                    || !matches!(text.as_ref(), "If-Match" | "If-None-Match" | "If-Modified-Since" | "If-Unmodified-Since")
                {
                    return Err(InvalidErrorContext::InvalidDetail);
                }
            }
            ErrorDetail::RangeRequested(text) => {
                validate_detail_text(text, MAX_RANGE_BYTES)?;
                if code != &ErrorCode::INVALID_RANGE {
                    return Err(InvalidErrorContext::InvalidDetail);
                }
                range_text = true;
            }
            ErrorDetail::ActualObjectSize(size) => {
                if code != &ErrorCode::INVALID_RANGE {
                    return Err(InvalidErrorContext::InvalidDetail);
                }
                actual_size = Some(*size);
            }
            ErrorDetail::Region(_) => return Err(InvalidErrorContext::ReservedExtra),
        }
    }

    if code == &ErrorCode::INVALID_RANGE {
        match (range_header, range_text, actual_size) {
            (Some(header), true, Some(size)) if header == size => {}
            _ => return Err(InvalidErrorContext::InvalidDetail),
        }
    }
    Ok(())
}

pub(super) fn validate_detail_text(text: &str, max: usize) -> Result<(), InvalidErrorContext> {
    if text.len() <= max && is_xml_representable(text) {
        Ok(())
    } else {
        Err(InvalidErrorContext::InvalidDetail)
    }
}
