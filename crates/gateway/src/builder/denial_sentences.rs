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

//! The RustFS-profile switch that answers an authorization denial with the sentence legacy RustFS
//! writes for it (rustfs/gateway#1349).
//!
//! Responsible for: [`ServiceBuilder::answer_denials_with_legacy_rustfs_sentence`], the sentence,
//! and [`DenialSentences::sentence`], which `crate::render::from_denial` writes into every
//! authorization refusal.
//! NOT responsible for: deciding a denial (the [`crate::ext::Authorizer`]), its code, status or
//! connection verdict (`crate::render::from_denial`), or any refusal that is not an authorization
//! denial — a security-floor refusal, an expired presigned URL and a backend's hidden-resource
//! answer keep their own sentences.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, which hands
//! [`super::view_policy::ViewPolicy::denial_sentences`] to every `from_denial`.
//!
//! # What legacy RustFS writes
//!
//! Every exit of RustFS's per-operation authorization that refuses a caller builds the same error:
//! `403 AccessDenied` with the sentence [`RUSTFS_ACCESS_DENIED`], no full stop, for an anonymous
//! caller and a signed one alike (rustfs/rustfs `95268a3b9`, `rustfs/src/storage/access.rs:1161-1164`
//! `DenialContext::deny`, reached from every refusing branch of `authorize_request` at `:1280`,
//! `:1322`, `:1436`, `:1478`, `:1482` and `:1490`; `rustfs/src/error.rs:266-271` writes the same
//! text). The gateway's own sentence names no condition either; the RustFS profile keeps RustFS's
//! wording and changes nothing else.

use super::ServiceBuilder;

/// Legacy RustFS's sentence for an authorization denial.
pub(crate) const RUSTFS_ACCESS_DENIED: &str = "Access Denied";

/// The gateway's sentence for an authorization denial.
pub(crate) const GATEWAY_ACCESS_DENIED: &str = "the request is not allowed";

/// Which sentence an assembly answers an authorization denial with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DenialSentences {
    /// This gateway's sentence.
    #[default]
    Gateway,
    /// Legacy RustFS's sentence.
    LegacyRustfs,
}

impl DenialSentences {
    /// The sentence an authorization denial carries under this choice.
    pub(crate) const fn sentence(self) -> &'static str {
        match self {
            Self::Gateway => GATEWAY_ACCESS_DENIED,
            Self::LegacyRustfs => RUSTFS_ACCESS_DENIED,
        }
    }
}

impl ServiceBuilder {
    /// Answers an authorization denial — an anonymous caller or a signed one the authorizer
    /// refuses — with the sentence legacy RustFS writes for it, `Access Denied`, as RustFS does
    /// today (rustfs/gateway#1349).
    ///
    /// Off by default: the gateway answers with its own sentence. Either way the sentence names no
    /// condition of the policy, so a caller cannot map the policy one request at a time. Only the
    /// `<Message>` changes — the code, the status, the connection verdict and the point the request
    /// is refused at stay the authorizer's — and no refusal other than an authorization denial is
    /// touched.
    #[must_use]
    pub fn answer_denials_with_legacy_rustfs_sentence(mut self) -> Self {
        self.view_policy.denial_sentences = DenialSentences::LegacyRustfs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::render::from_denial;
    use rustfs_gateway_core::{Denied, ResponseKind};
    use rustfs_gateway_types::ErrorCode;

    /// Positive — under the legacy choice, a denial and a fail-closed indeterminate decision both
    /// carry legacy RustFS's sentence; the code stays `AccessDenied`.
    #[test]
    fn the_legacy_choice_words_every_denial_as_legacy_rustfs() {
        for denial in [Denied::access_denied(), Denied::indeterminate()] {
            for response in [ResponseKind::Other, ResponseKind::Head] {
                let refusal = from_denial(denial, response, DenialSentences::LegacyRustfs);
                assert_eq!(refusal.message(), Some(RUSTFS_ACCESS_DENIED), "{denial:?} {response:?}");
                assert_eq!(refusal.code(), Some(&ErrorCode::ACCESS_DENIED), "{denial:?} {response:?}");
            }
        }
    }

    /// Negative — the default keeps the gateway's sentence, so the switch alone moves the wording.
    #[test]
    fn n_the_default_keeps_the_gateway_sentence() {
        assert_eq!(DenialSentences::default(), DenialSentences::Gateway);
        let refusal = from_denial(Denied::access_denied(), ResponseKind::Other, DenialSentences::default());
        assert_eq!(refusal.message(), Some(GATEWAY_ACCESS_DENIED));
    }

    /// Negative — the two choices render the same refusal apart from the message: status, code and
    /// connection verdict do not move.
    #[test]
    fn n_only_the_message_differs_between_the_two_choices() {
        let gateway = from_denial(Denied::access_denied(), ResponseKind::Other, DenialSentences::Gateway);
        let legacy = from_denial(Denied::access_denied(), ResponseKind::Other, DenialSentences::LegacyRustfs);
        assert_ne!(gateway.message(), legacy.message());
        assert_eq!(gateway.status(), legacy.status());
        assert_eq!(gateway.code(), legacy.code());
        assert_eq!(gateway.must_close_connection(), legacy.must_close_connection());
    }
}
