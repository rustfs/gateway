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

//! The s3s side of the decode diff: the pinned s3s service RustFS main runs, with a backend that
//! records what each handler was handed.
//!
//! Responsible for: building the s3s service with an auth provider (so its access hook runs for
//! every request, signed or not) and an access hook that records the operation s3s routed to and
//! allows it; the recording backend's shared slot; and reporting, for one request, the routed
//! operation, what the handler was handed, and the refusal when the handler was never reached.
//! NOT responsible for: which s3s methods the backend implements (`project/mod.rs` generates them)
//! or comparing (`decode.rs`).
//! Upstream: the `compat::s3s_0_17_0` seam's `s3s`. Downstream: `decode.rs`.
//!
//! # Why an auth provider
//!
//! The pinned s3s calls its access hook — the only place it names the operation it routed to —
//! only when an auth provider is configured, and then for every request, anonymous ones included
//! (its `access` module documents both). The provider holds one key nothing signs with; the hook
//! allows everything, as the gateway side's authorizer does.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::decode::{Answer, BodySeen, S3ErrorView};
use crate::encode::WireAnswer;
use crate::fields::Fields;
use crate::probe::{ProbeBody, block_on};
use crate::request::RawRequest;
use crate::s3s;
use s3s::dto as oracle;

/// What one s3s handler call recorded.
pub(crate) struct OracleHanded {
    pub(crate) fields: Fields,
    pub(crate) body: BodySeen,
}

pub(crate) type OracleSlot = Arc<Mutex<Option<OracleHanded>>>;

/// The answer the next handler call returns instead of refusing: the encode diff's output.
pub(crate) type AnswerSlot = Arc<Mutex<Option<crate::project::OracleOutput>>>;

/// The recording backend. Its `s3s::S3` methods are generated beside the projections.
pub(crate) struct RecordingS3 {
    pub(crate) slot: OracleSlot,
    pub(crate) answer: AnswerSlot,
}

impl RecordingS3 {
    /// The queued answer, if the encode diff queued one.
    pub(crate) fn take_answer(&self) -> Option<crate::project::OracleOutput> {
        self.answer.lock().ok().and_then(|mut answer| answer.take())
    }

    /// Records one handler call, draining the body a streaming input carries first.
    pub(crate) async fn record(&self, fields: Fields, body: Option<oracle::StreamingBlob>) {
        let body = match body {
            None => BodySeen::NoBody,
            Some(blob) => drain(blob).await,
        };
        if let Ok(mut slot) = self.slot.lock() {
            *slot = Some(OracleHanded { fields, body });
        }
    }
}

async fn drain(mut blob: oracle::StreamingBlob) -> BodySeen {
    use futures_core::Stream;
    let mut bytes = Vec::new();
    let outcome = std::future::poll_fn(|cx| {
        loop {
            match Pin::new(&mut blob).poll_next(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Some(Ok(chunk))) => bytes.extend_from_slice(&chunk),
                std::task::Poll::Ready(Some(Err(_))) => return std::task::Poll::Ready(Err(())),
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
            }
        }
    })
    .await;
    match outcome {
        Ok(()) => BodySeen::Read(bytes),
        Err(()) => BodySeen::Failed { read: bytes },
    }
}

/// The refusal every recording handler answers with, so no output is ever encoded.
pub(crate) fn recorded<T>() -> s3s::S3Result<s3s::S3Response<T>> {
    Err(s3s::S3Error::with_message(
        s3s::S3ErrorCode::NotImplemented,
        "recorded by the decode diff",
    ))
}

/// The future type the pinned trait's `#[async_trait]` methods return.
pub(crate) type Answered<'a, T> = Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<T>>> + Send + 'a>>;

/// Records the operation s3s routed to and allows it.
struct RecordOperation {
    routed: Arc<Mutex<Option<String>>>,
}

impl s3s::access::S3Access for RecordOperation {
    // The pinned trait is declared with `#[async_trait]`; this is the signature that attribute
    // expands `async fn check(&self, cx: &mut S3AccessContext<'_>)` to, spelled out so this crate
    // needs no proc-macro dependency.
    fn check<'life0, 'life1, 'life2, 'future>(
        &'life0 self,
        cx: &'life1 mut s3s::access::S3AccessContext<'life2>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<()>> + Send + 'future>>
    where
        'life0: 'future,
        'life1: 'future,
        'life2: 'future,
        Self: 'future,
    {
        if let Ok(mut routed) = self.routed.lock() {
            *routed = Some(cx.s3_op().name().to_owned());
        }
        Box::pin(async { Ok(()) })
    }
}

/// A key the provider holds and nothing signs with.
const ACCESS_KEY: &str = "AKIDDIFFTESTORACLE";
const SECRET_KEY: &str = "difftest-oracle-secret";

/// The pinned s3s service and its recording slots.
pub(crate) struct OracleStack {
    service: s3s::service::S3Service,
    slot: OracleSlot,
    routed: Arc<Mutex<Option<String>>>,
    answer: AnswerSlot,
}

impl OracleStack {
    pub(crate) fn new() -> Self {
        let slot: OracleSlot = Arc::new(Mutex::new(None));
        let routed = Arc::new(Mutex::new(None));
        let answer: AnswerSlot = Arc::new(Mutex::new(None));
        let mut builder = s3s::service::S3ServiceBuilder::new(RecordingS3 {
            slot: Arc::clone(&slot),
            answer: Arc::clone(&answer),
        });
        builder.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
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

    /// Sends `request` with `output` queued as its handler's answer, and returns the whole
    /// response s3s wrote.
    pub(crate) fn answer(&self, request: &RawRequest, output: crate::project::OracleOutput) -> Result<WireAnswer, String> {
        *self.answer.lock().map_err(|_| "the answer slot is poisoned".to_owned())? = Some(output);
        let source: s3s::stream::DynByteStream = Box::pin(ProbeBody::new(&request.body));
        let http_request = request
            .http_head()?
            .body(s3s::Body::from(source))
            .map_err(|error| format!("request head: {error}"))?;
        let response = block_on(self.service.call(http_request)).map_err(|error| format!("s3s service failed: {error:?}"));
        let unused = self
            .answer
            .lock()
            .map_err(|_| "the answer slot is poisoned".to_owned())?
            .take();
        let response = response?;
        if unused.is_some() {
            return Err("s3s never reached the handler the answer was queued for".to_owned());
        }
        let (parts, mut body) = response.into_parts();
        let body = block_on(body.store_all_limited(64 << 20)).map_err(|error| format!("s3s response body: {error}"))?;
        Ok(WireAnswer::new(parts.status.as_u16(), &parts.headers, body.to_vec()))
    }

    /// Sends `request` and reports what s3s made of it.
    pub(crate) fn send(&self, request: &RawRequest) -> Result<(Option<String>, Answer<OracleHanded>), String> {
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
        let handed = self
            .slot
            .lock()
            .map_err(|_| "the recording slot is poisoned".to_owned())?
            .take();
        if let Some(handed) = handed {
            return Ok((routed, Answer::Handed(handed)));
        }
        // s3s failing to write any answer (an error document holding a control character it
        // echoed from the request, for one) is still an outcome of the request: it is recorded as
        // a 500 with no error document so that it is compared, whatever the HTTP layer in front
        // of s3s then does with the failed call (it may close the connection instead).
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                return Ok((
                    routed,
                    Answer::Refused(S3ErrorView {
                        status: 500,
                        code: None,
                        message: Some("the s3s service call failed without an answer".to_owned()),
                    }),
                ));
            }
        };
        let (parts, mut body) = response.into_parts();
        let body = block_on(body.store_all_limited(1 << 20)).map_err(|error| format!("s3s response body: {error}"))?;
        Ok((routed, Answer::refused(parts.status.as_u16(), &body)))
    }
}
