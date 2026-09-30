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

//! The two stacks of the seam decode diff, each recording the pinned legacy input its handler
//! ends up with.
//!
//! Responsible for: the assembled gateway (the assembly of `gateway.rs` — SigV4 authenticator,
//! allow-every-stage authorizer, anonymous requests delegated to it, a fixed bucket owner,
//! admission that never refuses for load — with the RustFS profile's decode options, since the
//! seam is only reached behind that profile) with one recording handler per covered
//! operation, which converts through the production seam and records the result; the pinned
//! legacy service with an access hook naming the operation it routed to and a backend recording
//! the input it was handed; and draining a body on either side once, as a storing handler would.
//! NOT responsible for: which operations are covered or how each converts (`table.rs`), or
//! comparing (`mod.rs`).
//! Upstream: `rustfs-gateway`, the compat seam. Downstream: `mod.rs`.

use std::any::Any;
use std::sync::{Arc, Mutex};

use http_body_util::BodyExt;
use rustfs_gateway::{
    Credentials, GovernorRates, Handler, HandlerError, HandlerResult, PlaintextCustomerKeyAck, Rate, Req, Resp, S3Service,
    ServiceBuilder, SigV4Authenticator, SlashPolicy, SseConfig, StaticCredentials, Unlimited,
};
use rustfs_gateway_sig::{PresignedExpiryRule, RegionSet, SecurityFloor};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::compat::ConversionError;

use super::table::{self, SeamConverted, Stored};
use super::trailers::{TrailerView, gateway_view};
use crate::decode::{Answer, BodySeen, S3ErrorView};
use crate::encode::WireAnswer;
use crate::gateway::{AllowEveryStage, FixtureOwner, RouteObserver, Routed};
use crate::oracle::{RecordOperation, drain};
use crate::probe::{ProbeBody, block_on};
use crate::request::RawRequest;
use crate::resolver::Resolver;
use crate::s3s;
use crate::sign::{ACCESS_KEY, REGION, SECRET_KEY};

/// What one handler ended up with.
pub(crate) struct Recorded {
    /// The operation the handler serves.
    pub(crate) operation: &'static str,
    /// The pinned legacy input, or the member the gateway conversion refused.
    pub(crate) input: Result<Box<dyn Any + Send>, ConversionError>,
    /// The body the handler drained, when the input carries one.
    pub(crate) body: Option<BodySeen>,
    /// The configuration bytes this side would store, for a configuration write.
    pub(crate) stored: Stored,
    /// The trailer handle the handler was handed, read once the body was drained.
    pub(crate) trailers: TrailerView,
}

pub(crate) type Slot = Arc<Mutex<Option<Recorded>>>;

/// A RustFS app body's whole answer: its output and the response headers it set beside it.
pub(crate) struct LegacyAnswer<T> {
    pub(crate) output: T,
    pub(crate) headers: http::HeaderMap,
}

/// The answer the next handler call gives instead of refusing, boxed as a [`LegacyAnswer`] of the
/// operation's legacy output.
pub(crate) type Queued = Arc<Mutex<Option<Box<dyn Any + Send>>>>;

pub(crate) fn take(queued: &Queued) -> Option<Box<dyn Any + Send>> {
    queued.lock().ok().and_then(|mut held| held.take())
}

/// Records `recorded` in `slot`, draining the body first and reading the trailer handle after, as
/// a RustFS body reads it.
pub(crate) async fn record(
    slot: &Slot,
    operation: &'static str,
    input: Result<Box<dyn Any + Send>, ConversionError>,
    body: Option<s3s::dto::StreamingBlob>,
    stored: Stored,
    trailers: impl FnOnce() -> TrailerView,
) {
    let body = match body {
        None => None,
        Some(blob) => Some(drain(blob).await),
    };
    let trailers = trailers();
    if let Ok(mut held) = slot.lock() {
        *held = Some(Recorded {
            operation,
            input,
            body,
            stored,
            trailers,
        });
    }
}

/// The gateway backend: every covered operation converts through the seam and records, then
/// answers with a queued legacy answer converted through the seam, or refuses.
pub(crate) struct SeamRecorder {
    pub(crate) slot: Slot,
    pub(crate) answer: Queued,
}

impl<O: SeamConverted> Handler<O> for SeamRecorder {
    async fn call(&self, request: Req<O>) -> HandlerResult<O> {
        let stored = O::stored(request.input());
        let (input, body, trailers) = O::convert(request);
        record(&self.slot, O::NAME, input, body, stored, || gateway_view(trailers.as_ref())).await;
        match take(&self.answer).map(O::answer) {
            Some(Ok((output, headers))) => Ok(Resp::new(output).with_extra_headers(headers)),
            Some(Err(error)) => Err(HandlerError::internal_error(format!("the seam cannot hand the answer over: {error}"))),
            None => Err(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "recorded by the seam diff")),
        }
    }
}

/// The assembled gateway with the seam recorder behind every covered operation.
pub(crate) struct GatewaySeam {
    service: S3Service,
    slot: Slot,
    routed: Routed,
    answer: Queued,
}

impl GatewaySeam {
    pub(crate) fn new() -> Result<Self, String> {
        let credentials =
            Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credential: {error:?}"))?;
        let regions = RegionSet::new([REGION]).map_err(|error| format!("regions: {error:?}"))?;
        // The RustFS profile's scope handling, as `compat/sut` assembles it.
        let authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions)
            .accept_any_signing_region()
            .accept_empty_signing_region()
            .refuse_unreadable_signing_regions_after_verification()
            .accept_signing_regions_of_any_length()
            .verify_raw_paths_only_with_unencoded_bytes()
            .accept_legacy_rustfs_signing_services()
            .answer_credential_scope_refusals_as_legacy_rustfs()
            .read_signed_headers_as_legacy_rustfs();
        let slot: Slot = Arc::new(Mutex::new(None));
        let routed: Routed = Arc::new(Mutex::new(None));
        let answer: Queued = Arc::new(Mutex::new(None));
        let recorder = Arc::new(SeamRecorder {
            slot: Arc::clone(&slot),
            answer: Arc::clone(&answer),
        });
        let unbounded = Rate::new(u32::MAX, u32::MAX);
        let builder = ServiceBuilder::new()
            .framework_governor_rates(GovernorRates {
                aggregate: unbounded,
                per_ip: unbounded,
                credential_lookup: unbounded,
                cors_preflight: unbounded,
                unauthenticated: unbounded,
                tracked_clients: 1,
            })
            .governor(Unlimited)
            .authenticator(authenticator)
            .authorizer(AllowEveryStage)
            .security_floor(
                SecurityFloor::new()
                    .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
                    .enable_sigv2_presigned_compatibility()
                    .with_presigned_expiry_rule(PresignedExpiryRule::LegacyRustfs)
                    .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
                    .recognize_signatures_as_legacy_rustfs(),
            )
            .bucket_owner_source(FixtureOwner)
            // The RustFS profile: the seam is only ever reached behind it, so its decode choices
            // are what the RustFS app layer is handed (`compat/sut` turns on the same ones).
            .accept_all_checksum_omissions()
            .clamp_oversized_max_keys()
            .accept_minio_body_literals()
            .refuse_unsigned_amz_headers_before_routing()
            .leave_anonymous_streaming_payloads_undecoded()
            .sign_presigned_payloads_as_unsigned()
            .answer_head_refusals_without_content_length()
            .answer_not_modified_with_legacy_rustfs_headers()
            .sign_base64_payload_digests_as_hex()
            .answer_header_signatures_as_legacy_rustfs()
            .answer_presigned_urls_as_legacy_rustfs()
            .answer_checksum_failures_with_bad_digest()
            .ignore_unknown_checksum_algorithms()
            .accept_mismatched_payload_digests_without_a_body()
            .bound_buffered_bodies_as_legacy_rustfs()
            .answer_body_refusals_with_legacy_rustfs_sentences()
            .answer_credential_refusals_with_legacy_rustfs_sentences()
            .slash_policy(SlashPolicy::RustfsLegacy)
            .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
            .address_paths_as_legacy_rustfs()
            .select_operations_as_legacy_rustfs()
            .accept_empty_uploads_without_content_length()
            .refuse_unreadable_date_conditions()
            .url_encode_listings_like_rustfs()
            .legacy_rustfs_post_forms()
            .answer_heads_as_legacy_rustfs()
            .read_empty_headers_as_absent()
            // RustFS's transport gate with TLS required: a target's customer key is refused over
            // cleartext, a copy source's served (rustfs/backlog#1677, R11).
            .sse_config(SseConfig::refusing_only_target_keys_over_plaintext(
                PlaintextCustomerKeyAck::i_understand_customer_keys_will_be_sent_in_the_clear(),
            ))
            .read_request_documents_as_rustfs()
            .write_responses_as_rustfs()
            .host_resolver(Resolver::new(false))
            .observer(RouteObserver {
                routed: Arc::clone(&routed),
            });
        let service = table::register(builder, &recorder)
            .build()
            .map_err(|error| format!("assembly: {error:?}"))?;
        Ok(Self {
            service,
            slot,
            routed,
            answer,
        })
    }

    /// Sends `request` with `answer` (a boxed [`LegacyAnswer`]) queued for its handler, and returns
    /// the whole response the gateway wrote.
    pub(crate) fn answer(&self, request: &RawRequest, answer: Box<dyn Any + Send>) -> Result<WireAnswer, String> {
        *self.answer.lock().map_err(|_| "the answer slot is poisoned".to_owned())? = Some(answer);
        let mut head = request.http_head()?;
        if request.secure {
            head = head.extension(rustfs_gateway::TransportSecurity::Encrypted);
        }
        let http_request = head
            .body(ProbeBody::new(&request.body))
            .map_err(|error| format!("request head: {error}"))?;
        let response = block_on(self.service.call(http_request));
        if take(&self.answer).is_some() {
            return Err(format!("the gateway never reached the handler (status {})", response.status().as_u16()));
        }
        let (parts, body) = response.into_parts();
        let body = block_on(body.collect())
            .map_err(|_| "the gateway response body failed".to_owned())?
            .to_bytes();
        Ok(WireAnswer::new(parts.status.as_u16(), &parts.headers, body.to_vec()))
    }

    /// Sends `request` and reports the routed operation and what the handler ended up with.
    pub(crate) fn send(&self, request: &RawRequest) -> Result<(Option<String>, Answer<Recorded>), String> {
        *self.slot.lock().map_err(|_| "the recording slot is poisoned".to_owned())? = None;
        *self
            .routed
            .lock()
            .map_err(|_| "the routed-operation slot is poisoned".to_owned())? = None;
        let mut head = request.http_head()?;
        if request.secure {
            head = head.extension(rustfs_gateway::TransportSecurity::Encrypted);
        }
        let http_request = head
            .body(ProbeBody::new(&request.body))
            .map_err(|error| format!("request head: {error}"))?;
        let response = block_on(self.service.call(http_request));
        let (parts, body) = response.into_parts();
        let body = block_on(body.collect())
            .map_err(|_| "the gateway response body failed".to_owned())?
            .to_bytes();
        let routed = self
            .routed
            .lock()
            .map_err(|_| "the routed-operation slot is poisoned".to_owned())?
            .take()
            .ok_or_else(|| "the gateway answered without reporting the request to its observer".to_owned())?;
        let recorded = self
            .slot
            .lock()
            .map_err(|_| "the recording slot is poisoned".to_owned())?
            .take();
        match recorded {
            Some(recorded) if routed.as_deref() != Some(recorded.operation) => Err(format!(
                "the service reported {routed:?} and the {} handler was called",
                recorded.operation
            )),
            Some(recorded) => Ok((routed, Answer::Handed(recorded))),
            None => Ok((routed, Answer::refused(parts.status.as_u16(), &body))),
        }
    }
}

/// The pinned legacy backend: every covered operation records the input it was handed, then
/// answers with a queued answer or refuses.
pub(crate) struct LegacyRecorder {
    pub(crate) slot: Slot,
    pub(crate) answer: Queued,
}

/// The pinned legacy service with the recording backend.
pub(crate) struct LegacySeam {
    service: s3s::service::S3Service,
    slot: Slot,
    routed: Arc<Mutex<Option<String>>>,
    answer: Queued,
}

impl LegacySeam {
    pub(crate) fn new() -> Self {
        let slot: Slot = Arc::new(Mutex::new(None));
        let routed = Arc::new(Mutex::new(None));
        let answer: Queued = Arc::new(Mutex::new(None));
        let mut builder = s3s::service::S3ServiceBuilder::new(LegacyRecorder {
            slot: Arc::clone(&slot),
            answer: Arc::clone(&answer),
        });
        builder.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
        // Configured as RustFS main configures the legacy stack (forward-slash normalisation and
        // SigV2 on, `s3tables` signing): the input RustFS is handed is the one this stack hands.
        builder.set_config(Arc::new(s3s::config::StaticConfigProvider::new(Arc::new(
            crate::oracle::rustfs_settings(),
        ))));
        builder.set_access(RecordOperation {
            routed: Arc::clone(&routed),
        });
        Self {
            service: builder.build(),
            slot,
            routed,
            answer,
        }
    }

    /// Sends `request` with `answer` (a boxed [`LegacyAnswer`]) queued for its handler, and returns
    /// the whole response the legacy service wrote.
    pub(crate) fn answer(&self, request: &RawRequest, answer: Box<dyn Any + Send>) -> Result<WireAnswer, String> {
        *self.answer.lock().map_err(|_| "the answer slot is poisoned".to_owned())? = Some(answer);
        let source: s3s::stream::DynByteStream = Box::pin(ProbeBody::new(&request.body));
        let http_request = request
            .http_head()?
            .body(s3s::Body::from(source))
            .map_err(|error| format!("request head: {error}"))?;
        let response = block_on(self.service.call(http_request)).map_err(|error| format!("legacy service failed: {error:?}"))?;
        if take(&self.answer).is_some() {
            return Err("the legacy service never reached the handler".to_owned());
        }
        let (parts, mut body) = response.into_parts();
        let body = block_on(body.store_all_limited(64 << 20)).map_err(|error| format!("legacy response body: {error}"))?;
        Ok(WireAnswer::new(parts.status.as_u16(), &parts.headers, body.to_vec()))
    }

    /// Sends `request` and reports the routed operation and what the handler was handed.
    pub(crate) fn send(&self, request: &RawRequest) -> Result<(Option<String>, Answer<Recorded>), String> {
        *self
            .routed
            .lock()
            .map_err(|_| "the routed-operation slot is poisoned".to_owned())? = None;
        *self.slot.lock().map_err(|_| "the recording slot is poisoned".to_owned())? = None;
        let source: s3s::stream::DynByteStream = Box::pin(ProbeBody::new(&request.body));
        let http_request = request
            .http_head()?
            .body(s3s::Body::from(source))
            .map_err(|error| format!("request head: {error}"))?;
        let response = block_on(self.service.call(http_request));
        let routed = self
            .routed
            .lock()
            .map_err(|_| "the routed-operation slot is poisoned".to_owned())?
            .take();
        if let Some(recorded) = self
            .slot
            .lock()
            .map_err(|_| "the recording slot is poisoned".to_owned())?
            .take()
        {
            return Ok((routed, Answer::Handed(recorded)));
        }
        // A service call that fails without an answer is still an outcome, as in `oracle.rs`.
        let Ok(response) = response else {
            return Ok((
                routed,
                Answer::Refused(S3ErrorView {
                    status: 500,
                    code: None,
                    message: Some("the legacy service call failed without an answer".to_owned()),
                }),
            ));
        };
        let (parts, mut body) = response.into_parts();
        let body = block_on(body.store_all_limited(1 << 20)).map_err(|error| format!("legacy response body: {error}"))?;
        Ok((routed, Answer::refused(parts.status.as_u16(), &body)))
    }
}
