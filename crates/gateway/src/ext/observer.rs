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

//! What the deployment is told about a request that has already been answered.
//!
//! Responsible for: [`Observer`], the record it is handed ([`RequestEvent`]), and the default
//! [`NoObserver`].
//! NOT responsible for: changing any outcome. An observer is called after the response has been
//! decided and cannot alter it; a component that needs to change an answer is a
//! [`crate::Authorizer`] or a [`crate::Governor`], not this.
//! Upstream: `rustfs-gateway-core`, `rustfs-gateway-sig`. Downstream: `crate::service`.
//!
//! # Why this one is synchronous when ADR-0002 makes extension points asynchronous
//!
//! It is called on the response path of every request, and it cannot influence the response. An
//! awaiting observer therefore adds latency to a request that is already finished, in exchange for
//! nothing the request can use — and the natural implementation, which enqueues onto a channel and
//! returns, does not need to await at all. An implementation that must do I/O hands the event to
//! its own task; that is a decision it makes visibly rather than one the signature makes for it.
//!
//! # Why the event carries the request identifier
//!
//! An audit line that cannot be joined to the caller's copy of the same event is an audit line
//! nobody can act on: the caller quotes the `x-amz-request-id` it received, and without that value
//! in the record there is nothing to look it up by. The event therefore carries the very same
//! [`RequestId`] the response went out with — the one `crate::service` minted, not a second one —
//! which is what makes "the caller's id and the log's id are the same id" true by construction.
//!
//! # Why the event carries no request bytes
//!
//! [`RequestEvent`] holds the method, the operation name, the status, the access key id, the error
//! code and the server-minted request identifier. It holds no header value, no query string and no body. An observer is the component most likely to
//! be wired to a log sink, and a log line that echoes a request header is how a session token ends
//! up in a log aggregator.
//!
//! # Feeding a host's metrics and audit
//!
//! `docs/metrics-and-audit.md` lists what RustFS records per request, where each fact comes from
//! once the gateway answers, and what this event and the authorization audit event carry of it.

use rustfs_gateway_sig::Identity;
use rustfs_gateway_types::ErrorCode;

use crate::{HandlerDeadlineReport, trace::RequestId};

/// What happened to one request.
#[derive(Debug)]
pub struct RequestEvent<'a> {
    /// The identifier this request was answered with, and the one the caller received. Minted by
    /// the service, never read from the request; see the crate's trace module.
    pub request_id: &'a RequestId,
    /// The operation routing chose, when routing chose one. `None` when the request named none,
    /// which is the case an operator most often needs to see.
    pub operation: Option<&'a str>,
    /// The method the request was answered for, read through [`RequestEvent::method`].
    pub(crate) method: &'a http::Method,
    /// The status the response went out with.
    pub status: u16,
    /// How handler cleanup ended after a deadline. `None` when no handler deadline won, including
    /// requests that never reached a handler.
    pub handler_deadline: Option<HandlerDeadlineReport>,
    /// Who the request ran as. `None` unless authentication succeeded — for an anonymous request,
    /// for one whose authentication failed, and for one refused before authentication ran — so a
    /// request is never attributed to an access key it only claimed. A request refused after
    /// authentication (an authorization denial, say) carries the verified key.
    pub identity: Option<&'a Identity>,
    /// The S3 error code, when the response was an error document.
    pub error: Option<&'a ErrorCode>,
}

impl RequestEvent<'_> {
    /// The method the request was answered for.
    ///
    /// A host's own layer, `RequestContextView::method` and a filter's `ResponseView` see it too;
    /// this is for a counter kept in the observer — the one place that also names the operation of
    /// a request refused before any handler ran — labelled as RustFS labels its
    /// `rustfs_s3_http_requests_total{method, op, outcome}`. A caller chooses the method, and a
    /// refused request is reported too, so a label folds unknown methods into one value rather
    /// than growing with what callers send (RustFS keeps nine and `OTHER`).
    #[must_use]
    pub fn method(&self) -> &http::Method {
        self.method
    }
}

/// Records what happened to a request, and changes nothing.
///
/// **If you need to rewrite something, use [`crate::StageFilter`] or [`crate::OpLayer`]. An
/// `Observer` is read-only, and no `&mut` method will ever be added to it.** Every parameter below
/// is a shared reference to a summary, there is no response to hand back, and the call happens
/// after the response has been decided — so an implementation that wanted to change an answer would
/// have nothing to change it with.
///
/// Synchronous; see the module documentation. Held as `Arc<dyn Observer>` so that the service
/// stays non-generic over it.
///
/// # Examples
///
/// An observer that counts error responses:
///
/// ```
/// use std::sync::atomic::{AtomicU64, Ordering};
///
/// use rustfs_gateway::{Observer, RequestEvent, ServiceBuilder};
///
/// #[derive(Default)]
/// struct Errors(AtomicU64);
///
/// impl Observer for Errors {
///     fn on_response(&self, event: &RequestEvent<'_>) {
///         if event.error.is_some() {
///             self.0.fetch_add(1, Ordering::Relaxed);
///         }
///     }
/// }
///
/// let _builder = ServiceBuilder::new().observer(Errors::default());
/// ```
pub trait Observer: Send + Sync + 'static {
    /// Called exactly once per request, after the response has been decided.
    ///
    /// It is called for a request that was rejected at acceptance too, where `operation` is `None`.
    /// An observer that only saw successful requests would be an audit trail with the interesting
    /// half missing.
    ///
    /// **It reports the head, not the body.** For an ordinary response the call happens before the
    /// response is handed to the transport, so before the first body byte is produced: the event is
    /// the same whether a streaming body then completes, ends short, fails, or is abandoned by the
    /// client. A committed response is the exception: its event waits for the detached work and is
    /// delivered even if the client has already gone.
    ///
    /// **Must not panic.** The framework isolates a panic the way it isolates one in an
    /// [`crate::AuthzAuditSink`]: the event is lost and one fixed `error` event is written (at most
    /// one per five seconds, carrying how many panics it stands for), but the response — including
    /// the terminal document of a committed response, which is sent after this call — goes out
    /// unchanged. The panic payload is released; if its destructor panics in
    /// turn, that second payload is leaked rather than risk a third.
    fn on_response(&self, event: &RequestEvent<'_>);
}

/// Reports `event` to `observer` behind the same boundary the authorization audit sink uses.
pub(crate) fn observe_safely(observer: &dyn Observer, event: &RequestEvent<'_>) {
    static PANICS: crate::logging::Throttle = crate::logging::Throttle::new();
    crate::panic_boundary::contain_report("request observer", &PANICS, || observer.on_response(event));
}

impl<T: Observer + ?Sized> Observer for std::sync::Arc<T> {
    fn on_response(&self, event: &RequestEvent<'_>) {
        (**self).on_response(event);
    }
}

/// The default observer: nothing is recorded.
///
/// # Security
///
/// This default removes the deployment's only in-process audit trail. A refused signature, a
/// denied authorisation and a rate-limited request leave no trace outside the response the caller
/// received, so the caller is the only party that knows it happened. Nothing is widened, and
/// nothing is recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoObserver;

impl Observer for NoObserver {
    fn on_response(&self, _event: &RequestEvent<'_>) {}
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<(Option<String>, u16)>>,
    }

    impl Observer for Recorder {
        fn on_response(&self, event: &RequestEvent<'_>) {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((event.operation.map(str::to_owned), event.status));
            }
        }
    }

    /// Negative — an event that reached no operation is still an event, so an observer cannot be
    /// written on the assumption that `operation` is always present.
    #[test]
    fn an_unrouted_request_is_still_observed() {
        let recorder = Recorder::default();
        recorder.on_response(&RequestEvent {
            request_id: &RequestId::from_bits(1),
            operation: None,
            method: &http::Method::PATCH,
            status: 501,
            handler_deadline: None,
            identity: None,
            error: Some(&ErrorCode::NOT_IMPLEMENTED),
        });
        assert_eq!(recorder.seen.lock().expect("not poisoned").as_slice(), [(None, 501)]);
    }

    /// Negative — the event type has no field that could carry a header or a body, so an observer
    /// cannot log one by accident.
    #[test]
    fn the_event_renders_nothing_from_the_wire() {
        let identity = Identity::new("AKIDEXAMPLE").expect("a valid access key id");
        let rendered = format!(
            "{:?}",
            RequestEvent {
                request_id: &RequestId::from_bits(0xDEAD),
                operation: Some("GetObject"),
                method: &http::Method::GET,
                status: 200,
                handler_deadline: None,
                identity: Some(&identity),
                error: None,
            }
        );
        assert!(rendered.contains("AKIDEXAMPLE"), "{rendered}");
        assert!(rendered.contains("000000000000DEAD"), "{rendered}");
        assert!(!rendered.contains("Authorization"), "{rendered}");
    }

    /// Positive — the default is inert and dyn compatible.
    #[test]
    fn the_default_records_nothing() {
        let observer: std::sync::Arc<dyn Observer> = std::sync::Arc::new(NoObserver);
        observer.on_response(&RequestEvent {
            request_id: &RequestId::from_bits(2),
            operation: Some("ListBuckets"),
            method: &http::Method::GET,
            status: 200,
            handler_deadline: None,
            identity: None,
            error: None,
        });
    }
}
