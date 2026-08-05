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

//! The errors that can be produced before the caller has been authenticated.
//!
//! Responsible for: [`PreAuthError`] — a code, a static message, and optionally a static operation
//! name — and the closed set of statuses it is allowed to carry.
//! NOT responsible for: the code-to-status table (`rustfs-gateway-types::ErrorCode`), the
//! context-sensitive status rules (`rustfs-gateway-types::status_of`), rendering XML, or any error
//! raised after authentication, which may say as much as it likes.
//! Upstream: `rustfs-gateway-types`. Downstream: `crate::registry`, `crate::dispatch`.
//!
//! # Why the message is a `&'static str`
//!
//! An error produced before authentication is an error an unauthenticated caller can produce at
//! will. If any part of it is derived from the request, the error response is a mirror: it will
//! echo whatever was sent, to whoever sent it, as many times as they like. That is a reflection
//! surface and, when the echoed value is a bucket or key name, an enumeration oracle.
//!
//! The rule is therefore structural rather than a review item: [`PreAuthError`] holds
//! `&'static str`, so a message built with `format!` does not typecheck. The one place this bites
//! is the useful case — "the required parameter 'id' is missing" — and the answer is that the
//! parameter name is a constant from the operation's spec, not a value from the request.
//! `crates/core/tests/purity_guard.rs` additionally refuses `Box::leak` in this crate, which is
//! the only way to launder a `String` into the type.
//!
//! # Why the status set is closed
//!
//! Three statuses are reachable before authentication: `400`, `403` and `501`. Anything else is a
//! statement about a request the gateway has not yet been given permission to look at. In
//! particular nothing here is a `5xx`: a client that receives one retries and trips its circuit
//! breaker over what was its own mistake, and several SDKs discard the body of a `5xx` entirely,
//! so the code chosen with care never reaches the operator reading the logs.

use http::StatusCode;
use rustfs_gateway_types::{ErrorCode, ErrorContext, status_of};

/// The statuses an error raised before authentication may carry.
pub const PRE_AUTH_STATUSES: [StatusCode; 3] = [StatusCode::BAD_REQUEST, StatusCode::FORBIDDEN, StatusCode::NOT_IMPLEMENTED];

/// A code whose status is outside [`PRE_AUTH_STATUSES`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisallowedPreAuthCode {
    /// The code that was offered.
    pub code: ErrorCode,
    /// The status it maps to.
    pub status: StatusCode,
}

impl std::fmt::Display for DisallowedPreAuthCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} maps to {}, which is not one of the statuses reachable before authentication (400, 403, 501)",
            self.code, self.status
        )
    }
}

impl std::error::Error for DisallowedPreAuthCode {}

/// An error the gateway can produce before it knows who is asking.
///
/// Deliberately not `From<std::io::Error>`, `From<String>` or anything else that could carry
/// request-derived text into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreAuthError {
    code: ErrorCode,
    message: &'static str,
    operation: Option<&'static str>,
}

impl PreAuthError {
    /// `400 InvalidArgument` — a parameter is missing or unusable.
    #[must_use]
    pub const fn invalid_argument(message: &'static str) -> Self {
        Self::of(ErrorCode::INVALID_ARGUMENT, message)
    }

    /// `400 InvalidRequest` — the request is not usable for a reason with no better code.
    #[must_use]
    pub const fn invalid_request(message: &'static str) -> Self {
        Self::of(ErrorCode::INVALID_REQUEST, message)
    }

    /// `403 AccessDenied`.
    #[must_use]
    pub const fn access_denied(message: &'static str) -> Self {
        Self::of(ErrorCode::ACCESS_DENIED, message)
    }

    /// `501 NotImplemented` — no route, or a route this backend does not handle.
    #[must_use]
    pub const fn not_implemented(message: &'static str) -> Self {
        Self::of(ErrorCode::NOT_IMPLEMENTED, message)
    }

    const fn of(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            operation: None,
        }
    }

    /// An error carrying an operation-specific code.
    ///
    /// # Errors
    ///
    /// [`DisallowedPreAuthCode`] when the code's status is outside [`PRE_AUTH_STATUSES`]. Callers
    /// that build a table of codes should call this at build time, not per request — see
    /// [`crate::registry::Registry::register`], which does exactly that.
    pub fn with_code(code: ErrorCode, message: &'static str) -> Result<Self, DisallowedPreAuthCode> {
        let status = status_of(&code, &ErrorContext::default());
        if !PRE_AUTH_STATUSES.contains(&status) {
            return Err(DisallowedPreAuthCode { code, status });
        }
        Ok(Self {
            code,
            message,
            operation: None,
        })
    }

    /// Names the operation this error is about.
    ///
    /// The name comes from the route table, so it is one of a closed set of compile-time strings
    /// and cannot carry anything the caller sent — which is why it is allowed here at all. It is
    /// what turns "not implemented" into something an operator can act on.
    #[must_use]
    pub const fn about(mut self, operation: &'static str) -> Self {
        self.operation = Some(operation);
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

    /// The operation this error is about, when it is about one.
    #[must_use]
    pub const fn operation(&self) -> Option<&'static str> {
        self.operation
    }

    /// The status this error goes out with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        status_of(&self.code, &ErrorContext::default())
    }
}

impl std::fmt::Display for PreAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(operation) = self.operation {
            write!(f, " (operation: {operation})")?;
        }
        Ok(())
    }
}

impl std::error::Error for PreAuthError {}
