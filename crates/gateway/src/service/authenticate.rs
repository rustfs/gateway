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

//! The authentication stage helpers for `S3Service`, including T6 `FailureFloor` enforcement and
//! optional presigned-URL single-use replay protection.
//!
//! Responsible for: enforcing pre-lookup legacy signature guards, driving the configured
//! authenticator / token verifiers from a `SecurityFloor::admit` result, enforcing an optional
//! `ReplayNonceStore` after signature verification succeeds, and holding `FailureFloor` on every
//! authentication failure exit path.
//! NOT responsible for: sealing the request body, calling `SecurityFloor::admit` itself, minting
//! `MetadataAdmission`, authorization, or body decoding (`super`).
//! Upstream: `super::S3Service::run` after `.governed()`. Downstream: `super::S3Service::run` before `.meta_auth()`.

use http::{HeaderMap, Response};
use rustfs_gateway_core::{HandlerError, RequestBodyMode, ResponseKind};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_sig::{
    Admission, AuthError, CredentialPresence, OperationFloor, PayloadMode, PostPolicyLimits, QueryBearerClaim, RequestNow,
    SealedAws, SecurityFloor, Verdict, WireView,
};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::ErrorCode;

use super::{Outcome, S3Service, UNAUTHENTICATED, host_tokens};
use crate::builder::view_policy::header_signatures::SignedHead;
use crate::clock::MonotonicNow;
use crate::config::ConfigSnapshot;
use crate::ext::{Authentication, AuthenticationOutcome, ChunkSink, SigV2Authentication};
use crate::gate::{BodyDigestObligation, StsBodyReader};
use crate::logging::{Extension, Refused};
use crate::render::{S3Error, from_auth, from_auth_with_detail};
use crate::request_deadline::hold_failure_floor;

/// Settled payload-mode inputs extracted from `Admission::Sealed` before running verification.
pub(super) struct PreparedSealedPayload {
    payload: PayloadMode,
    trailer_refusal: Option<S3Error>,
    signed_length: crate::builder::buffered_lengths::SignedLength,
    body_digest: BodyDigestObligation,
    replay_fingerprint: Option<rustfs_gateway_sig::ReplayFingerprint>,
}

/// Inputs passed from `S3Service::run` into [`S3Service::complete_auth_stage`].
pub(super) struct AuthStageInput<'a> {
    pub(super) auth_started: MonotonicNow,
    pub(super) operation: &'static str,
    pub(super) operation_floor: &'a OperationFloor,
    pub(super) request_body_mode: RequestBodyMode,
    pub(super) declared_length: Option<u64>,
    pub(super) external_bound: bool,
    pub(super) claimed: bool,
    pub(super) bearer_verified_claim: Option<QueryBearerClaim>,
    pub(super) secret_scope: crate::routed_facts::CallerKeyOptIn,
    pub(super) vhost_bucket: Option<&'a str>,
    pub(super) now: RequestNow,
    pub(super) response_kind: ResponseKind,
    pub(super) headers: &'a HeaderMap,
    pub(super) wire: &'a WireRequest<()>,
    pub(super) view: WireView<'a>,
    pub(super) presence: CredentialPresence,
    pub(super) prepared_sealed: Option<PreparedSealedPayload>,
    pub(super) replacement_verdict: Option<Verdict>,
    pub(super) post_policy_limits: Option<PostPolicyLimits>,
    pub(super) post_filename: Option<&'a str>,
    pub(super) sts_body_reader: Option<&'a dyn StsBodyReader>,
    pub(super) config: &'a ConfigSnapshot,
}

/// Settled outputs handed back to `S3Service::run` once authentication succeeds.
pub(super) struct AuthStageOutput {
    pub(super) verdict: Verdict,
    pub(super) caller_secret: Option<rustfs_gateway_sig::SecretBytes>,
    pub(super) chunk_sink: ChunkSink,
    pub(super) framing_mode: Option<PayloadMode>,
    pub(super) trailer_refusal: Option<S3Error>,
    pub(super) signed_length: crate::builder::buffered_lengths::SignedLength,
    pub(super) body_digest: BodyDigestObligation,
    pub(super) signed_bearer: Option<rustfs_gateway_sig::BearerReceipt>,
}

impl S3Service {
    /// Holds the configured security failure floor from `started` before returning an
    /// authentication refusal (row `T6` of `rustfs_gateway_sig::timing::SIDE_CHANNELS`).
    pub(super) async fn hold_auth_failure_floor(&self, started: MonotonicNow) {
        hold_failure_floor(self.inner.floor.failure_floor(), self.inner.authz_clock.as_ref(), started).await;
    }

    /// Evaluates legacy pre-lookup header-signature and presigned-URL refusals, holding
    /// [`Self::hold_auth_failure_floor`] when one fires.
    pub(super) async fn pre_lookup_auth_refusal(
        &self,
        signed_head: &SignedHead<'_>,
        by_header_token: bool,
        response_kind: ResponseKind,
        body_owed: bool,
        auth_started: MonotonicNow,
        outcome: &mut Outcome<'_>,
    ) -> Option<Response<Body>> {
        let policy = &self.inner.view_policy;
        let legacy_refusal = policy
            .header_signatures
            .refusal(signed_head, response_kind, body_owed)
            .or_else(|| policy.presigned_urls.refusal(signed_head, response_kind, body_owed));
        let refusal = legacy_refusal.filter(|_| !by_header_token)?;
        self.hold_auth_failure_floor(auth_started).await;
        Some(outcome.refuse(refusal))
    }

    /// Extracts and validates the signed payload mode from `Admission::Sealed` before running
    /// signature verification, holding [`Self::hold_auth_failure_floor`] on rejection.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prepare_sealed_payload(
        &self,
        sealed: &SealedAws<'_>,
        signed_head: &SignedHead<'_>,
        operation: &'static str,
        request_body_mode: RequestBodyMode,
        response_kind: ResponseKind,
        body_owed: bool,
        auth_started: MonotonicNow,
        outcome: &mut Outcome<'_>,
    ) -> Result<PreparedSealedPayload, Response<Body>> {
        let location = sealed.marker().location();
        let replay_fingerprint = sealed.replay_fingerprint();
        let mut trailer_refusal = None;
        let (payload, obligation) =
            match self
                .inner
                .view_policy
                .signed_payload(signed_head, operation, location, &mut trailer_refusal)
            {
                Ok(declared) => declared,
                Err(refusal) => {
                    self.hold_auth_failure_floor(auth_started).await;
                    return Err(outcome.refuse_at(Refused::Authentication, refusal.render(response_kind, body_owed)));
                }
            };
        let signed_length = crate::builder::buffered_lengths::SignedLength::of(location, &payload, obligation);
        let body_digest = self.inner.view_policy.bodyless_digest.apply(request_body_mode, obligation);
        let payload = self.inner.view_policy.signed_payload_mode(payload);
        Ok(PreparedSealedPayload {
            payload,
            trailer_refusal,
            signed_length,
            body_digest,
            replay_fingerprint,
        })
    }

    /// Completes authentication from the result of `SecurityFloor::admit`, holding
    /// [`Self::hold_auth_failure_floor`] on every authentication failure exit path.
    pub(super) async fn complete_auth_stage<'a>(
        &self,
        admission: Result<Admission<'a>, AuthError>,
        input: AuthStageInput<'a>,
        outcome: &mut Outcome<'_>,
    ) -> Result<AuthStageOutput, Response<Body>> {
        let AuthStageInput {
            auth_started,
            operation,
            operation_floor,
            request_body_mode,
            declared_length,
            external_bound,
            claimed,
            bearer_verified_claim,
            secret_scope,
            vhost_bucket,
            now,
            response_kind,
            headers,
            wire,
            view,
            presence,
            prepared_sealed,
            replacement_verdict,
            post_policy_limits,
            post_filename,
            sts_body_reader,
            config,
        } = input;

        let body_owed = wire.framing().has_body();
        let chunk_sink = ChunkSink::new();
        // Kept out of the `match` so the read at the bottom can consult it. A custom admission has no
        // payload mode; an anonymous one has only the unsigned streaming mode its head declares.
        let mut framing_mode: Option<PayloadMode> = None;
        let mut trailer_refusal = None;
        let mut signed_length = crate::builder::buffered_lengths::SignedLength::default();
        let mut body_digest = BodyDigestObligation::None;
        let mut signed_body = false; // Whether a SigV4 header signature covers the body (rustfs/gateway#1587).
        // Legacy RustFS's words for a RustFS-profile refusal, when the authenticator published them.
        let mut legacy = None;
        // Presigned single-use fingerprint, recorded only after signature verification succeeds.
        let mut replay_fingerprint = None;
        // Whether this request's own admission was a bearer or header-token one; such a verdict from any other path is refused below.
        let (mut bearer_admitted, mut header_token_admitted) = (false, false);
        let (authentication, signature_mismatch) = match admission {
            Ok(Admission::Sealed(sealed)) => {
                let Some(prepared) = prepared_sealed else {
                    return Err(outcome.refuse_handler(HandlerError::internal_error(
                        "sealed admission arrived without prepared payload metadata",
                    )));
                };
                replay_fingerprint = prepared.replay_fingerprint;
                trailer_refusal = prepared.trailer_refusal;
                signed_length = prepared.signed_length;
                body_digest = prepared.body_digest;
                let payload = prepared.payload;
                framing_mode = Some(payload.clone());
                if let Some(verdict) = replacement_verdict {
                    (AuthenticationOutcome::ordinary(verdict), None)
                } else {
                    let question = Authentication::new(
                        &sealed,
                        wire.method(),
                        wire.raw_path().as_str(),
                        wire.host().raw_for_signing(),
                        &payload,
                        if external_bound { Some(0) } else { declared_length },
                    )
                    .with_post_form(post_policy_limits, post_filename)
                    .with_claimed_route(claimed)
                    // Offered before the verdict and read long after it. An `aws-chunked` body's chunk
                    // chain is verified with the same key and seed the request signature was, and
                    // neither survives `Verdict` — see `crate::ext::ChunkVerification`.
                    .with_chunk_sink(&chunk_sink)
                    .with_sts_body_reader(sts_body_reader, operation, config);
                    let auth = self.inner.authenticator.as_ref();
                    let result =
                        match super::extension_guards::authenticate_safely(auth, &question, outcome.trace, operation).await {
                            Ok(result) => result,
                            Err(error) => return Err(outcome.refuse_handler(error)),
                        };
                    signed_body = question.signs_its_body();
                    body_digest = self.settle_body_digest(request_body_mode, body_digest, &question);
                    let (signature_mismatch, published_legacy, body_refusal) = question.into_published();
                    legacy = published_legacy;
                    if let Some(refusal) = body_refusal {
                        self.hold_auth_failure_floor(auth_started).await;
                        return Err(outcome.refuse_at(Refused::Authentication, refusal));
                    }
                    match result {
                        Ok(authentication) => (authentication, signature_mismatch),
                        Err(_) => {
                            self.hold_auth_failure_floor(auth_started).await;
                            return Err(outcome.refuse_unavailable(UNAUTHENTICATED, body_owed));
                        }
                    }
                }
            }
            // Unsigned: anonymous, or admitted by the header token claim (ADR-0054). One framing rule serves both.
            Ok(unsigned @ (Admission::Anonymous(_) | Admission::HeaderToken(_))) => {
                framing_mode = match crate::payload_header::anonymous_framing(headers, self.inner.decode_anonymous_framing) {
                    Ok(mode) => mode,
                    Err(error) => return Err(outcome.refuse_at(Refused::Decode, error)),
                };
                let verdict = match unsigned {
                    Admission::Anonymous(evidence) => Verdict::anonymous(evidence),
                    Admission::HeaderToken(admission) => {
                        header_token_admitted = true;
                        self.header_token_verdict(admission, wire.transport_extensions(), outcome.trace, operation)
                    }
                    _ => Verdict::reject(AuthError::AccessDenied), // not reachable: the pattern admits only those two
                };
                (AuthenticationOutcome::ordinary(verdict), None)
            }
            // No payload mode and no framed body: SigV2 has neither, so `framing_mode` stays
            // `None` and the body read at the bottom is a plain one.
            Ok(Admission::SealedSigV2(sealed)) => {
                let question = SigV2Authentication::new(&sealed, wire.method(), wire.raw_path().as_str(), vhost_bucket)
                    .with_post_policy_limits(post_policy_limits);
                let auth = self.inner.authenticator.as_ref();
                match super::extension_guards::authenticate_sigv2_safely(auth, &question, outcome.trace, operation).await {
                    Ok(Ok(authentication)) => (authentication, None),
                    Ok(Err(_)) => {
                        self.hold_auth_failure_floor(auth_started).await;
                        return Err(outcome.refuse_unavailable(UNAUTHENTICATED, body_owed));
                    }
                    Err(error) => return Err(outcome.refuse_handler(error)),
                }
            }
            Ok(Admission::Custom(request)) => match &self.inner.custom_signature_verifier {
                Some(verifier) => {
                    let verdict = match super::extension_guards::verify_custom_signature_safely(
                        verifier.as_ref(),
                        &request,
                        outcome.trace,
                        operation,
                    ) {
                        Ok(verdict) => verdict,
                        Err(error) => return Err(outcome.refuse_handler(error)),
                    };
                    let verdict = if verdict.is_anonymous() {
                        Verdict::reject(AuthError::AuthorizationHeaderMalformed)
                    } else {
                        verdict
                    };
                    (AuthenticationOutcome::ordinary(verdict), None)
                }
                None => {
                    self.hold_auth_failure_floor(auth_started).await;
                    return Err(outcome.refuse_handler_at(
                        Refused::Authentication,
                        HandlerError::new(
                            ErrorCode::NOT_IMPLEMENTED,
                            "this deployment registered a custom authentication scheme and installed no verifier for it",
                        ),
                    ));
                }
            },
            // ADR-0042: only the installed host verifier makes a bearer admission a verdict; else it is refused.
            Ok(Admission::Bearer(admission)) => {
                bearer_admitted = true;
                let verdict = self.bearer_verdict(admission, wire.raw_path().as_str(), outcome.trace, operation);
                (AuthenticationOutcome::ordinary(verdict), None)
            }
            // `Admission` is `#[non_exhaustive]`: a variant added later must not be answered by a
            // wildcard that falls through to "authenticated". Refused, loudly.
            Ok(_) => {
                self.hold_auth_failure_floor(auth_started).await;
                return Err(outcome.refuse_handler_at(
                    Refused::Authentication,
                    HandlerError::new(
                        ErrorCode::NOT_IMPLEMENTED,
                        "the security floor admitted this request in a way this assembly does not handle",
                    ),
                ));
            }
            // The floor rejects malformed credential surfaces before a verifier can recover a scope. Keep that fail-closed
            // response distinct from a verifier's well-formed but unserved scope, which is `400 AuthorizationHeaderMalformed`.
            Err(error) => {
                self.hold_auth_failure_floor(auth_started).await;
                return Err(outcome.refuse_at(Refused::Authentication, from_auth(error, response_kind, body_owed)));
            }
        };

        // H4's run-time half: a receipt minted for another request cannot be attached to this one.
        let (verdict, scope_rejection, caller_secret) = authentication.into_parts();
        let caller_secret = caller_secret.filter(|_| secret_scope.admits(signed_body, self.inner.caller_secret_every_operation));
        let verdict = SecurityFloor::seal_verdict(verdict, presence);
        let verdict = host_tokens::from_own_admission(verdict, bearer_admitted, header_token_admitted);
        if let Some(error) = verdict.rejection() {
            self.hold_auth_failure_floor(auth_started).await;
            // A RustFS-profile reading's refusal, in legacy RustFS's words (rustfs/gateway#1130).
            if let Some(legacy) = legacy {
                return Err(outcome.refuse(legacy.render(&error, response_kind, body_owed)));
            }
            if error == AuthError::AuthorizationHeaderMalformed {
                return Err(Self::refuse_scope_rejection(error, scope_rejection, response_kind, body_owed, outcome));
            }
            return Err(outcome.refuse_at(
                Refused::Authentication,
                from_auth_with_detail(
                    error,
                    signature_mismatch.as_ref(),
                    config.verbose_signature_errors(),
                    response_kind,
                    body_owed,
                ),
            ));
        }

        // H7: optional single-use presigned-URL replay protection. Runs strictly AFTER the
        // signature verified so unauthenticated/forged requests can never poison the nonce store.
        if verdict.is_authenticated()
            && let (Some(store), Some(fingerprint)) = (self.inner.replay_nonce_store.as_ref(), replay_fingerprint)
        {
            let allowed = match crate::panic_boundary::contain_decision(|| store.record_first_use(fingerprint)) {
                Ok(rustfs_gateway_sig::ReplayDecision::FirstUse) => true,
                Ok(_) => false,
                Err(()) => {
                    crate::logging::extension_panicked(Extension::ReplayNonceStore, outcome.trace.request_id(), operation);
                    false
                }
            };
            if !allowed {
                self.hold_auth_failure_floor(auth_started).await;
                return Err(
                    outcome.refuse_at(Refused::Authentication, from_auth(AuthError::AccessDenied, response_kind, body_owed))
                );
            }
        }

        // ADR-0042: with the host verifier installed, a signed request on a bearer-claimed operation
        // must also carry a token the verifier accepts for this download and for the signed
        // principal. The signature verdict stays as it is; the receipt only carries host state.
        let signed_bearer = match (bearer_verified_claim, &self.inner.bearer_token_verifier, verdict.identity()) {
            (Some(_), Some(verifier), Some(signed)) if verdict.is_authenticated() => {
                let verified = self
                    .inner
                    .floor
                    .bearer_alongside_signature(&view, operation_floor, now)
                    .and_then(|admission| {
                        admission.map_or(Err(AuthError::AccessDenied), |admission| {
                            crate::panic_boundary::contain_decision(|| {
                                admission.verify_alongside(verifier.as_ref(), wire.raw_path().as_str(), signed)
                            })
                            .unwrap_or_else(|()| {
                                crate::logging::extension_panicked(
                                    Extension::BearerVerifier,
                                    outcome.trace.request_id(),
                                    operation,
                                );
                                Err(AuthError::AccessDenied)
                            })
                        })
                    });
                match verified {
                    Ok(receipt) => Some(receipt),
                    Err(error) => {
                        self.hold_auth_failure_floor(auth_started).await;
                        return Err(outcome.refuse_at(Refused::Authentication, from_auth(error, response_kind, body_owed)));
                    }
                }
            }
            _ => None,
        };

        Ok(AuthStageOutput {
            verdict,
            caller_secret,
            chunk_sink,
            framing_mode,
            trailer_refusal,
            signed_length,
            body_digest,
            signed_bearer,
        })
    }
}
