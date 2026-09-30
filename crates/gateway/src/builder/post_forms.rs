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

//! The assembly's choice of POST Object form grammar.
//!
//! Responsible for: the RustFS-profile switch that reads browser upload forms with the legacy
//! RustFS grammar, and turning the switch and a request's framing into the
//! [`FormGrammar`] that request is read with.
//! NOT responsible for: the grammars themselves (`rustfs-gateway-http`'s form module) or the POST
//! Object bridge that uses them (`crate::post_object`).
//! Upstream: the assembler; the switch is held in `super::ViewPolicy` beside the assembly's other
//! RustFS-profile switches. Downstream: `crate::service`'s POST Object prelude.

use http::HeaderMap;
use rustfs_gateway_http::{FormGrammar, FormLimits};

use crate::ServiceBuilder;

/// How one request's POST Object form is read: its ceilings and its grammar.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PostFormRead {
    pub(crate) limits: FormLimits,
    pub(crate) grammar: FormGrammar,
}

/// Which grammar this assembly reads POST Object forms with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PostFormGrammar {
    legacy_rustfs: bool,
}

impl PostFormGrammar {
    /// How the form of a request with `headers` is read.
    ///
    /// The legacy grammar's closing rule turns on whether the request carried a `Content-Length`:
    /// that is what legacy RustFS derives the file's exact length from, leaving no room for
    /// padding after the closing delimiter.
    pub(crate) fn read(self, headers: &HeaderMap) -> PostFormRead {
        let grammar = if self.legacy_rustfs {
            FormGrammar::LegacyRustfs {
                declared_length: headers.contains_key(http::header::CONTENT_LENGTH),
            }
        } else {
            FormGrammar::Gateway
        };
        PostFormRead {
            limits: FormLimits::default(),
            grammar,
        }
    }
}

impl ServiceBuilder {
    /// Reads POST Object forms exactly as legacy RustFS reads them ([`FormGrammar::LegacyRustfs`]),
    /// in both directions (ruling R8 of rustfs/backlog#1677).
    ///
    /// Off by default: every other deployment reads forms with [`FormGrammar::Gateway`]. The
    /// RustFS profile turns it on, so a browser upload the legacy stack stores — a preamble, a `;`
    /// inside a quoted filename, `filename*`, bare parameter values — is stored the same way here,
    /// with the key `${filename}` names the legacy way; and one it refuses — an epilogue after the
    /// closing boundary, a boundary outside RFC 2046's characters — is refused here too. The
    /// ceilings, the refusal of a repeated field and of a control byte in a field value, and the
    /// policy-before-file order are unchanged by it.
    ///
    /// It also hands the registered `PostObject` handler every other `PutObject` member legacy
    /// RustFS reads from the form, in `PostObjectInput::fields` (rustfs/gateway#1129). The handler
    /// must give each the effect its store gives that field, or refuse the upload: one it ignored
    /// would store another object than legacy RustFS stores from the same form. The members this
    /// profile cannot carry yet — Object Lock, SSE-C, `redirect` — are refused before any handler
    /// runs.
    #[must_use]
    pub fn legacy_rustfs_post_forms(mut self) -> Self {
        self.view_policy.post_forms.legacy_rustfs = true;
        self
    }
}
