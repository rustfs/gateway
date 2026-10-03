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

//! An authentication refusal worded as legacy RustFS words it, for the RustFS profile's legacy
//! readings of a signature (rustfs/gateway#1130).
//!
//! Responsible for: [`LegacyRefusal`] — the code and the sentence legacy RustFS answers a refused
//! signature with — and rendering it with the connection verdict every authentication failure
//! owes.
//! NOT responsible for: deciding when a request is refused (the RustFS-profile switches of the
//! built-in authenticator, `super::authenticator_switches`), or the status (the code's own, from
//! the error-status authority).
//! Upstream: `super::authenticator`, which attaches one to an outcome only the built-in
//! authenticator can build. Downstream: `crate::service`, which renders it in place of the
//! verdict's own sentence.
//!
//! # Why a sentence may name what the request said
//!
//! Every [`AuthError`] sentence is a constant, so nothing a request carries reaches a refusal.
//! Legacy RustFS names what it refused in a few of its sentences — the scope service it does not
//! verify, for one — and a RustFS client may read them. Only the RustFS profile's legacy readings
//! build one of these, only from the refused request's own credential text, and never from a
//! secret, a signature or anything derived from one.

use std::borrow::Cow;

use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_sig::AuthError;
use rustfs_gateway_types::ErrorCode;

use crate::render::{S3Error, from_handler};

/// A refused signature, answered with legacy RustFS's code and sentence.
pub(crate) struct LegacyRefusal {
    code: ErrorCode,
    sentence: Cow<'static, str>,
}

impl LegacyRefusal {
    /// Legacy RustFS's answer: `code`, at that code's status, with `sentence`.
    pub(crate) fn new(code: ErrorCode, sentence: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            sentence: sentence.into(),
        }
    }

    /// The refusal of a request whose authentication failed with `error`: legacy RustFS's code and
    /// sentence, with the connection verdict `error` owes when `body_owed`.
    pub(crate) fn render(self, error: &AuthError, response: ResponseKind, body_owed: bool) -> S3Error {
        from_handler(
            HandlerError::new(self.code, self.sentence),
            response,
            crate::close::after_auth_failure(error, body_owed),
        )
    }
}
