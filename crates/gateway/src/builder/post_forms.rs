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
//! Responsible for: the RustFS-profile switches that read browser upload forms with the legacy
//! RustFS grammar and enforce a policy no signature covers, and turning them and a request's
//! framing into the [`FormGrammar`] and policy reading that request is read with.
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
    /// Whether a policy the form does not sign is enforced as legacy RustFS enforces it.
    pub(crate) unsigned_policies: bool,
}

/// Which grammar this assembly reads POST Object forms with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PostFormGrammar {
    legacy_rustfs: bool,
    unsigned_policies: bool,
}

impl PostFormGrammar {
    /// Whether forms are read with legacy RustFS's grammar.
    pub(crate) const fn is_legacy_rustfs(self) -> bool {
        self.legacy_rustfs
    }

    /// Whether a policy no signature covers is enforced as legacy RustFS enforces it.
    pub(crate) const fn enforces_unsigned_policies(self) -> bool {
        self.unsigned_policies
    }

    /// How the form of a request with `headers` is read.
    ///
    /// The legacy grammar's closing rule turns on whether the request carried a `Content-Length`:
    /// that is what legacy RustFS derives the file's exact length from, leaving no room for
    /// padding after the closing delimiter.
    pub(crate) fn read(self, headers: &HeaderMap) -> PostFormRead {
        if self.legacy_rustfs {
            return PostFormRead {
                limits: FormLimits::legacy_rustfs(),
                grammar: FormGrammar::LegacyRustfs {
                    declared_length: headers.contains_key(http::header::CONTENT_LENGTH),
                },
                unsigned_policies: self.unsigned_policies,
            };
        }
        PostFormRead {
            limits: FormLimits::default(),
            grammar: FormGrammar::Gateway,
            unsigned_policies: self.unsigned_policies,
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
    /// closing boundary, a boundary outside RFC 2046's characters — is refused here too. The form
    /// is read under legacy RustFS's ceilings ([`FormLimits::legacy_rustfs`]: 1 MiB per field and
    /// per part header block, 20 MiB of field values, 1000 parts; rustfs/gateway#1173). The refusal
    /// of a repeated field and of a control byte in a field value, and the policy-before-file
    /// order, are unchanged by it.
    ///
    /// It also hands the registered `PostObject` handler every other `PutObject` member legacy
    /// RustFS reads from the form, in `PostObjectInput::fields` (rustfs/gateway#1129). The handler
    /// must give each the effect its store gives that field, or refuse the upload: one it ignored
    /// would store another object than legacy RustFS stores from the same form. The Object Lock
    /// and customer-key fields are read under either grammar (rustfs/gateway#1167): a form naming
    /// a lock is asked the lock actions, and a form's customer key passes the gate a header key
    /// passes.
    #[must_use]
    pub fn legacy_rustfs_post_forms(mut self) -> Self {
        self.view_policy.post_forms.legacy_rustfs = true;
        self
    }

    /// Parses and enforces the POST policy of a browser form that carries no signature, as legacy
    /// RustFS does (rustfs/backlog#2734), instead of refusing it.
    ///
    /// Off by default: a form with a `policy` and neither `x-amz-signature` nor `signature` is
    /// `400 MalformedPOSTRequest`, since no signature binds the policy to anyone. Under this switch
    /// the policy is read with the legacy SigV2-form reading
    /// ([`rustfs_gateway_sig::UnsignedPostPolicy`]) and every condition is enforced; the request
    /// stays anonymous whatever credential fields the form names, so the authorizer decides it as
    /// any anonymous request. A failed `eq` or `starts-with` condition, and a form `bucket` other
    /// than the routed one, are `400 InvalidPolicyDocument`; a field no condition names `403
    /// AccessDenied`; a file outside `content-length-range` `400 EntityTooLarge` or
    /// `EntityTooSmall`; an expired policy `403 AccessDenied`; an unreadable one `400
    /// InvalidPolicyDocument`; a repeated `key` or `bucket` field `400 InvalidPolicyDocument`.
    ///
    /// Legacy-compat: those answers carry legacy RustFS's sentences, naming the failed field and,
    /// for a bucket mismatch, the form's own `bucket` value — a deliberate exception to the
    /// no-echo rule of rustfs/gateway#1444, limited to names and values the same form sent and
    /// never a policy value, credential or signature. The intended future behaviour is the
    /// default's: a policy nobody signs is refused.
    #[must_use]
    pub fn enforce_unsigned_post_policies_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.post_forms.unsigned_policies = true;
        self
    }
}
