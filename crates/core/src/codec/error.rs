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

//! What a codec failed with.
//!
//! Responsible for: [`CodecError`] — an S3 error code, a static message, and the model member the
//! failure is about.
//! NOT responsible for: rendering the error document, or the code-to-status table
//! (`rustfs-gateway-types::ErrorCode`).
//! Upstream: `rustfs-gateway-types`. Downstream: every generated codec.
//!
//! # Why every part of it is `&'static str`
//!
//! Decoding runs before authorisation. An error raised here is an error an unidentified caller can
//! produce at will, so anything derived from the request would make the response a mirror of the
//! request — the reflection surface `crate::PreAuthError` exists to close. The rule is the same and
//! it is a type, not a review item: `format!` does not typecheck into this struct.
//!
//! It is a separate type from [`crate::PreAuthError`] for one measured reason: that type's status
//! set is `{400, 403, 501}`, and `MissingContentLength` is a `411`. A decode failure is not a
//! pre-authentication statement about the caller, it is a statement about bytes the caller sent,
//! so it may carry any 4xx the IR names.

use std::fmt;

use http::StatusCode;
use rustfs_gateway_types::{ErrorCode, ErrorContext, status_of};

/// Why a request could not be decoded, or a response could not be encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecError {
    code: ErrorCode,
    message: &'static str,
    member: Option<&'static str>,
}

impl CodecError {
    /// An error with a code and a message.
    #[must_use]
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            member: None,
        }
    }

    /// `400 InvalidArgument` — a value is present and unusable.
    #[must_use]
    pub const fn invalid_argument(message: &'static str) -> Self {
        Self::new(ErrorCode::INVALID_ARGUMENT, message)
    }

    /// `400 InvalidRequest` — the request is unusable for a reason with no better code.
    #[must_use]
    pub const fn invalid_request(message: &'static str) -> Self {
        Self::new(ErrorCode::INVALID_REQUEST, message)
    }

    /// `400 MalformedXML` — the body is not the XML this operation accepts.
    #[must_use]
    pub const fn malformed_xml(message: &'static str) -> Self {
        Self::new(ErrorCode::MALFORMED_XML, message)
    }

    /// `500 InternalError` — the gateway produced an output it cannot serialise.
    ///
    /// Reachable only from `encode`, and only for a defect on this side: a handler that returned
    /// a value with no wire form. It is the one variant that is not about the caller.
    #[must_use]
    pub const fn internal(message: &'static str) -> Self {
        Self::new(ErrorCode::INTERNAL_ERROR, message)
    }

    /// Names the model member this error is about.
    ///
    /// A member name is a compile-time constant from the IR, never a value from the request, which
    /// is why naming one is allowed here at all.
    #[must_use]
    pub const fn about(mut self, member: &'static str) -> Self {
        self.member = Some(member);
        self
    }

    /// The error code.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The message. Always a compile-time constant.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// The model member this error is about, when it is about one.
    #[must_use]
    pub const fn member(&self) -> Option<&'static str> {
        self.member
    }

    /// The status this error goes out with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        status_of(&self.code, &ErrorContext::default())
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(member) = self.member {
            write!(f, " (member: {member})")?;
        }
        Ok(())
    }
}

impl std::error::Error for CodecError {}
