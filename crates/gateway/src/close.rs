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

//! Whether a refusal ends the connection, declared once as a table instead of decided per call
//! site.
//!
//! Responsible for: [`ConnectionIntent`], the per-stage entry points that produce one, and the
//! statement of which rows are RFC-derived and which are this service's judgement.
//! NOT responsible for: touching a socket. Nothing in this crate owns one — the service is a
//! value, not a peer. What this module produces is carried on [`crate::S3Error`], written into the
//! response as `Connection: close`, and read by whatever transport is serving. A transport that
//! reads it and does not close is a transport defect, and `conformance`'s socket target exists to
//! observe that difference rather than trust it.
//! Upstream: `rustfs-gateway-http`, `rustfs-gateway-sig`. Downstream: `crate::render`,
//! `crate::gate`, `crate::service`.
//!
//! # The rule, and the one sentence it comes from
//!
//! RFC 9112 §9.3:
//!
//! > A server MUST read the entire request message body or close the connection after sending its
//! > response; otherwise, the remaining data on a persistent connection would be misinterpreted as
//! > the next request.
//!
//! That is the whole of it. This service never *chooses* to close; it chooses whether it is
//! willing and able to drain what the peer still owes, and §9.3 turns that choice into the
//! connection verdict. Stating it this way is what makes the table below checkable: every row is
//! either "cannot drain" (a fact about the framing, with an RFC section) or "will not drain" (a
//! decision, with the reason and the case that shows it).
//!
//! # The table
//!
//! | Refusal | Verdict | Basis |
//! | --- | --- | --- |
//! | a framing verdict from `WireReject` | close | **RFC 9112 §6.1, §6.3** — the body's extent is undecidable, so there is nothing well-defined to drain |
//! | `WireReject::LimitExceeded(BodyBytes)` | close | **policy** — refused *for* the size; draining performs the transfer the refusal avoids. §9.3 then forces the close |
//! | every other `WireReject` | may keep | **RFC 9112 §9.3** — framing intact, remainder bounded; drain and the connection survives |
//! | `ChunkReject`, per [`rustfs_gateway_http::ChunkReject::must_close_connection`] | both | `aws-chunked` is a content encoding inside a wire body whose extent §6.3 already fixed |
//! | an authentication failure | close | **policy** — see [`after_auth_failure`] |
//! | an authorisation denial | may keep | **the corpus** — `c-copy-0019`, `c-copy-0020`, `c-copy-0021` all assert `connection_after = "open"` for a `403 AccessDenied` |
//! | a body past the operation's cap or the assembly's ceiling | close | **policy**, the same shape as `BodyBytes`; `c-object-0015` |
//! | a decode, condition or handler refusal | may keep | **RFC 9112 §9.3** — the body was read to its end before the refusal could be reached |
//!
//! # What is guessed, said plainly
//!
//! Three rows are not derivable from RFC 9112 and are marked as such wherever they are
//! implemented:
//!
//! 1. **"An unauthenticated peer's body is not drained."** [`after_auth_failure`]. The RFC has
//!    nothing to say about who the peer is; the close is only §9.3's consequence of the refusal to
//!    drain, and the refusal to drain is ours.
//! 2. **"A body refused for its size is not drained."** [`after_body_ceiling`], and
//!    `WireReject::LimitExceeded(BodyBytes)`.
//! 3. **The drain budget itself.** [`rustfs_gateway_http::MAX_LINGER_DRAIN_BYTES`] — RFC 9112 §9.6
//!    describes the lingering read and puts no number on it.
//!
//! # One row the corpus and this table disagree on
//!
//! `c-mpu-0045` sends a `PUT` with neither `Content-Length` nor `Transfer-Encoding`, expects
//! `411 MissingContentLength`, and asserts `connection_after = "closed"`. RFC 9112 §6.3 item 7
//! says a request with no framing headers *has* a zero-length body, so by §9.3 the entire body has
//! been read and the connection is in sync — this table would say "may keep". The case is
//! presumably reasoning about what the client evidently *intended* to send, whose octets would
//! then be parsed as a request line. That is a real hazard and it is not a rule §9.3 states, so it
//! is left as a disagreement rather than encoded: nothing here returns [`ConnectionIntent::Close`]
//! for a missing length. `c-mpu-0045` is skipped by the in-process target for an unrelated reason
//! (it needs a raw request head), so this disagreement is not currently visible as a verdict.

use rustfs_gateway_http::{ChunkReject, WireReject};
use rustfs_gateway_sig::AuthError;

/// What a refusal says about the connection it was produced on.
///
/// Two states rather than a `bool` so that a call site cannot read `true` as either answer, and so
/// that [`ConnectionIntent::MayKeepAlive`] can carry its condition in its documentation rather
/// than in a comment beside every use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectionIntent {
    /// The connection survives **if the remainder of the request body is drained**.
    ///
    /// It is not a promise that the connection stays up. A transport that declines to drain — the
    /// remainder is past [`rustfs_gateway_http::MAX_LINGER_DRAIN_BYTES`], the peer stopped
    /// sending, the deployment is shedding load — must still close, and is right to. This variant
    /// says only that *this refusal* does not force the close.
    #[default]
    MayKeepAlive,
    /// The connection ends after the response, whatever the transport would prefer.
    Close,
}

impl ConnectionIntent {
    /// Whether this intent forces the close.
    #[must_use]
    pub const fn must_close(self) -> bool {
        matches!(self, Self::Close)
    }

    /// The stricter of two intents.
    ///
    /// Used where one response is assembled from more than one verdict: a stage that says "close"
    /// is never overruled by a later stage that says "may keep", because the reason for the close
    /// — undrained octets, or an unauthenticated peer — does not stop being true.
    #[must_use]
    pub const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::MayKeepAlive, Self::MayKeepAlive) => Self::MayKeepAlive,
            _ => Self::Close,
        }
    }
}

/// The acceptance layer's verdict, read off the reject rather than restated here.
///
/// A second spelling of the rule in this crate is a second place it can be wrong, so this is a
/// forwarding function and deliberately has no `match` of its own.
#[must_use]
pub fn after_wire_reject(reject: &WireReject) -> ConnectionIntent {
    if reject.must_close_connection() {
        ConnectionIntent::Close
    } else {
        ConnectionIntent::MayKeepAlive
    }
}

/// The `aws-chunked` layer's verdict, likewise forwarded.
#[must_use]
pub fn after_chunk_reject(reject: &ChunkReject) -> ConnectionIntent {
    if reject.must_close_connection() {
        ConnectionIntent::Close
    } else {
        ConnectionIntent::MayKeepAlive
    }
}

/// The third leg: an authentication failure ends the connection.
///
/// **This row is a policy decision, not an RFC one, and it is the one this module most wants a
/// maintainer to look at.** RFC 9112 §9.3 forces the close only once the server has decided not to
/// read the rest of the body; it says nothing about who the peer is. The decision not to read is
/// made here, for one reason:
///
/// A request whose signature did not verify has not established who sent it. Draining its body is
/// this server spending its own read time, and the socket buffer behind it, on behalf of a caller
/// it could not identify — which is the work `c-sig-0001` exists to prove is not done ("the
/// rejection must happen before the server reads the payload — otherwise an unauthenticated client
/// can make the server buffer gigabytes by sending a request it was always going to refuse", and
/// s3s#367 is the same defect found upstream). Having refused to read it, §9.3 leaves no choice
/// about the connection.
///
/// Every [`AuthError`] answers the same way, and the uniformity is deliberate rather than
/// unexamined: a skewed clock, an unknown access key and a wrong signature are all "not
/// established as anyone", and a table that closed for some and not others would let a peer
/// distinguish them by connection state without reading the body at all.
///
/// Note what this is *not*: an authorisation **denial** is a different stage and answers
/// [`ConnectionIntent::MayKeepAlive`] — see [`after_denial`]. The corpus agrees: `c-copy-0019`,
/// `c-copy-0020` and `c-copy-0021` are `403 AccessDenied` with `connection_after = "open"`, while
/// `c-sig-0001` is `403 SignatureDoesNotMatch` with `connection_after = "closed"`. Two `403`s, two
/// connection verdicts, and identity is what separates them.
#[must_use]
pub const fn after_auth_failure(_error: &AuthError) -> ConnectionIntent {
    ConnectionIntent::Close
}

/// An authorisation denial keeps the connection.
///
/// The caller is known — the signature verified — so none of [`after_auth_failure`]'s reasoning
/// applies. What is left is RFC 9112 §9.3 on its own: drain the remainder and keep the connection.
/// A denied request is the ordinary outcome of a correctly configured policy, and closing on it
/// would make every policy-shaped `403` cost the client a fresh connection.
#[must_use]
pub const fn after_denial() -> ConnectionIntent {
    ConnectionIntent::MayKeepAlive
}

/// A body refused for its size ends the connection.
///
/// **Policy, in the same sense as [`after_auth_failure`].** The RFC does not say a large body must
/// not be drained; this service says so, because draining a body it refused *because of its size*
/// is performing the transfer the refusal exists to avoid, and under concurrency that is the
/// out-of-memory condition `c-object-0015` names. §9.3 then supplies the close.
///
/// Applies to both ceilings — the operation's declared cap and the assembly's buffered ceiling —
/// because the reasoning does not distinguish them.
#[must_use]
pub const fn after_body_ceiling() -> ConnectionIntent {
    ConnectionIntent::Close
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_http::{LimitKind, ModeConfusion};

    /// Negative — the two `403`s the corpus distinguishes are distinguished here. If this ever
    /// collapses to one answer, `c-sig-0001` and `c-copy-0019` become the same assertion and one
    /// of them stops testing anything.
    #[test]
    fn the_two_forbidden_outcomes_do_not_share_a_connection_verdict() {
        assert_eq!(after_auth_failure(&AuthError::SignatureDoesNotMatch), ConnectionIntent::Close);
        assert_eq!(after_denial(), ConnectionIntent::MayKeepAlive);
    }

    /// Negative — every authentication failure closes, including the ones that are about the clock
    /// rather than the credential. A table with holes in it is a table a peer can probe.
    #[test]
    fn no_authentication_failure_keeps_the_connection() {
        for error in [
            AuthError::SignatureDoesNotMatch,
            AuthError::InvalidAccessKeyId,
            AuthError::RequestTimeTooSkewed,
            AuthError::AccessDenied,
            AuthError::AuthorizationHeaderMalformed,
        ] {
            assert!(after_auth_failure(&error).must_close(), "{error:?}");
        }
    }

    /// Negative — the acceptance layer's verdict actually branches. Before this change both
    /// families answered `close`, so an assertion that read `must_close_connection()` could not
    /// fail; this is the assertion that would go red if the constant came back.
    #[test]
    fn the_acceptance_verdict_branches_on_which_refusal_fired() {
        assert_eq!(
            after_wire_reject(&WireReject::ContentLengthTransferEncodingConflict),
            ConnectionIntent::Close
        );
        assert_eq!(
            after_wire_reject(&WireReject::LimitExceeded(LimitKind::BodyBytes)),
            ConnectionIntent::Close
        );
        assert_eq!(
            after_wire_reject(&WireReject::Host(rustfs_gateway_http::HostError::Missing)),
            ConnectionIntent::MayKeepAlive
        );
        assert_eq!(
            after_wire_reject(&WireReject::DuplicateSingleValuedHeader("x-amz-copy-source")),
            ConnectionIntent::MayKeepAlive
        );
    }

    /// Negative — the chunk layer branches too, and on the axis its documentation claims: the wire
    /// body's extent, not the chunk syntax.
    #[test]
    fn the_chunk_verdict_branches_on_the_wire_bodys_extent() {
        assert_eq!(after_chunk_reject(&ChunkReject::TruncatedStream), ConnectionIntent::Close);
        assert_eq!(
            after_chunk_reject(&ChunkReject::SignatureChainBroken { chunk_index: 0 }),
            ConnectionIntent::Close
        );
        assert_eq!(
            after_chunk_reject(&ChunkReject::ModeConfusion(ModeConfusion::WireLengthMissing)),
            ConnectionIntent::Close
        );
        assert_eq!(after_chunk_reject(&ChunkReject::LeadingZeros), ConnectionIntent::MayKeepAlive);
        assert_eq!(after_chunk_reject(&ChunkReject::BadLineTerminator), ConnectionIntent::MayKeepAlive);
    }

    /// Negative — combining verdicts never weakens one. A stage that closed cannot be talked out
    /// of it by a later stage with nothing to say.
    #[test]
    fn a_close_survives_being_combined_with_a_keep() {
        assert_eq!(ConnectionIntent::Close.and(ConnectionIntent::MayKeepAlive), ConnectionIntent::Close);
        assert_eq!(ConnectionIntent::MayKeepAlive.and(ConnectionIntent::Close), ConnectionIntent::Close);
        assert_eq!(
            ConnectionIntent::MayKeepAlive.and(ConnectionIntent::MayKeepAlive),
            ConnectionIntent::MayKeepAlive
        );
    }

    /// Positive — the default is the permissive one, so a refusal that says nothing about the
    /// connection does not close it. The closing rows are the ones that had to be argued for.
    #[test]
    fn the_default_intent_keeps_the_connection() {
        assert_eq!(ConnectionIntent::default(), ConnectionIntent::MayKeepAlive);
    }
}
