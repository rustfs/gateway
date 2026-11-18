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

//! A value refusal of the SSE headers handed to the handler instead of answered before it.
//!
//! Responsible for: [`DeferredSseRefusal`] and [`SseRejection::defer`], the one way a refusal
//! becomes a proof the handler receives, and the rule that the cleartext refusal never does.
//! NOT responsible for: judging the headers ([`super::enforce`]), the words of the refusal (the
//! facade renders them before deferring), or deciding to defer (the facade's assembly switch).
//! Upstream: [`super::enforce`]'s verdict. Downstream: a handler, through
//! [`super::SseEnforced::deferred_refusal`].
//!
//! # Why a handler may be handed a refusal at all
//!
//! A host that authorizes inside its handler (legacy RustFS asks its bucket policy there) answers a
//! policy denial before it judges an SSE header; a gate before the handler answers the same
//! request `400` instead of `403`. Deferring moves the answer, not the verdict: the rules ran, the
//! refusal is carried whole, and a proof that carries one carries no fingerprint and no managed
//! algorithm, so nothing read from it can be mistaken for an accepted key. The cleartext refusal is
//! never deferred: by the time it is known the key has crossed the wire, and no authorization
//! decision changes that.

use crate::HandlerError;

use super::{Managed, SseEnforced, SseRejection};

/// A refusal the shared gate reached and the assembly handed to the handler: the rule, and the
/// error the assembly answers it with.
#[derive(Clone, Debug)]
pub struct DeferredSseRefusal {
    rejection: SseRejection,
    error: HandlerError,
}

impl DeferredSseRefusal {
    /// The rule the request broke.
    #[must_use]
    pub const fn rejection(&self) -> &SseRejection {
        &self.rejection
    }

    /// The error the assembly answers the refusal with, in its words: what a handler returns once
    /// it has authorized the request.
    #[must_use]
    pub const fn error(&self) -> &HandlerError {
        &self.error
    }
}

impl SseRejection {
    /// Hands this refusal to the handler as a proof carrying it and nothing else, answered by
    /// `error` once the handler returns it.
    ///
    /// # Errors
    ///
    /// The refusal itself when it is [`SseRejection::PlaintextCustomerKey`], which is never
    /// deferred.
    pub fn defer(self, error: HandlerError) -> Result<SseEnforced, Self> {
        if self == Self::PlaintextCustomerKey {
            return Err(self);
        }
        Ok(SseEnforced {
            customer: None,
            copy_source: None,
            managed: Managed::Deferred(Box::new(DeferredSseRefusal { rejection: self, error })),
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use rustfs_gateway_types::ErrorCode;

    use super::*;
    use crate::sse::{KeyRejection, KeySide, ManagedRejection};

    fn error() -> HandlerError {
        HandlerError::new(ErrorCode::INVALID_REQUEST, "deferred")
    }

    /// Negative — the cleartext refusal is never deferred, whatever error it would be answered with.
    #[test]
    fn n_the_cleartext_refusal_is_never_deferred() {
        assert!(matches!(
            SseRejection::PlaintextCustomerKey.defer(error()),
            Err(SseRejection::PlaintextCustomerKey)
        ));
    }

    /// Negative — every value refusal is deferred whole, with its error, and the proof carrying it
    /// carries no fingerprint and no managed algorithm.
    #[test]
    fn n_a_deferred_refusal_carries_nothing_that_reads_as_accepted() {
        for rejection in [
            SseRejection::ChannelsContradict,
            SseRejection::CustomerTrioIncomplete(KeySide::Target),
            SseRejection::CustomerAlgorithmUnknown(KeySide::CopySource),
            SseRejection::CustomerKeyMalformed(KeySide::Target, KeyRejection::KeyWidth(5)),
            SseRejection::ManagedChannelInvalid(ManagedRejection::BucketKeyNotABoolean),
        ] {
            let Ok(proof) = rejection.clone().defer(error()) else {
                panic!("{rejection:?} was not deferred");
            };
            let Some(deferred) = proof.deferred_refusal() else {
                panic!("{rejection:?} lost its refusal");
            };
            assert_eq!(deferred.rejection(), &rejection);
            assert_eq!(deferred.error(), &error());
            assert!(proof.customer_key_fingerprint().is_none(), "{rejection:?}");
            assert!(proof.copy_source_key_fingerprint().is_none(), "{rejection:?}");
            assert!(proof.managed_algorithm().is_none(), "{rejection:?}");
        }
    }

    /// Positive — a proof the gate accepted carries no deferred refusal.
    #[test]
    fn an_accepted_request_carries_no_deferred_refusal() {
        assert!(SseEnforced::empty_for_unit_test().deferred_refusal().is_none());
    }
}
