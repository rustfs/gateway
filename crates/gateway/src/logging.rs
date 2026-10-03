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

//! The vocabulary of every `tracing` event this crate emits: one target, one component, the
//! subsystems and the event names, each spelled once.
//!
//! Responsible for: the constants the event sites share, so that an operator's filter or an alert
//! keyed on `event = "…"` names a value that exists, and a renamed event is a one-line diff here;
//! the reporters of a refused request ([`request_refused`]) and of a panicking extension
//! ([`extension_panicked`]), so every such event has one shape and one level policy; and the
//! [`Throttle`] that bounds the per-request `error` events.
//! NOT responsible for: deciding anything (each stage decides, and calls one reporter here), the
//! authorization refusal (reported where the decision is audited, `crate::ext::authz_audit`),
//! installing a subscriber (the host's: RustFS installs its own, a launcher installs whatever it
//! likes), or the catalogue operators read (`docs/observability.md`, which lists every event, level
//! and field).
//! Upstream: `crate::trace` (the request identifier), `crate::render` (the refusal a stage raised),
//! `crate::clock` (the throttle's monotonic source).
//! Downstream: the posture modules, `crate::builder`, `crate::panic_boundary`, `crate::service`,
//! `crate::ext::authorizer`, `crate::ext::authz_audit`, `crate::ext::observer`.
//!
//! # Why the field shape is RustFS's
//!
//! RustFS embeds this crate and routes its events into its own logging pipeline, where dashboards and
//! alerts select on stable fields in a fixed order: `event`, `component`, `subsystem`, then a
//! `state` or `result`, then context, and a label last (rustfs/rustfs `e870a6d25b`,
//! `.agents/skills/rustfs-logging-governance/SKILL.md`; `rustfs/src/server/layer.rs:458-561` for the
//! HTTP events). Events of this crate carry the same fields in the same order, under a target of
//! their own, so a RustFS filter written for its own events reads these unchanged and a deployment
//! can raise or lower this crate's level alone (`RUST_LOG=rustfs_gateway=debug`). The label is a
//! short sentence, except on a posture event, whose message is the start-up line itself.
//!
//! The levels are RustFS's too, including where they leave an event out: RustFS's default level is
//! `error`, and it reports a disabled security control at `warn` (`tls_verification_disabled`,
//! `rustfs/src/admin/router.rs:794`), so a dangerous assembly is a `warn` event here, visible where
//! RustFS's own is (`docs/observability.md`, "A host's subscriber").
//!
//! # What no event carries
//!
//! A header value, a query string, a body byte, a signature, a secret, a session token or a
//! customer key. The fields are identifiers this crate minted or validated, names from its own
//! vocabulary, and counts; `scripts/check_secret_hygiene.sh` refuses a logging macro that formats
//! a credential-bearing value, and `tests/tracing_events.rs` captures every event the request
//! path emits and holds it to the same rule.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use rustfs_gateway_types::ErrorCode;

use crate::clock::{MonotonicClock, SystemMonotonic};
use crate::render::S3Error;
use crate::trace::RequestId;

/// The target of every event this crate emits.
pub(crate) const TARGET: &str = "rustfs_gateway";

/// The `component` field of every event this crate emits.
pub(crate) const COMPONENT: &str = "gateway";

/// Start-up reports of what an assembly accepts.
pub(crate) const SUBSYSTEM_POSTURE: &str = "posture";
/// Assembly choices that disable or replace a security control.
pub(crate) const SUBSYSTEM_ASSEMBLY: &str = "assembly";
/// The deployment's read-only report callbacks (observer, authorization audit sink).
pub(crate) const SUBSYSTEM_REPORT: &str = "report";
/// A request the signature, the credential or the security floor refused.
pub(crate) const SUBSYSTEM_AUTHENTICATION: &str = "authentication";
/// A request its authorization decision refused.
pub(crate) const SUBSYSTEM_AUTHORIZATION: &str = "authorization";
/// A request a limiter refused.
pub(crate) const SUBSYSTEM_GOVERNOR: &str = "governor";
/// A request whose head could not be accepted or routed.
pub(crate) const SUBSYSTEM_WIRE: &str = "wire";
/// A request whose query, headers, form or body could not be read into its operation's input.
pub(crate) const SUBSYSTEM_DECODE: &str = "decode";
/// A deployment's handler or authorizer.
pub(crate) const SUBSYSTEM_EXTENSION: &str = "extension";

/// The `SECURITY_POSTURE` start-up line.
pub(crate) const EVENT_SECURITY_POSTURE: &str = "gateway_security_posture";
/// The `DIALECT_POSTURE` start-up line.
pub(crate) const EVENT_DIALECT_POSTURE: &str = "gateway_dialect_posture";
/// The `PRESIGNED_EXPIRY_POSTURE` start-up line.
pub(crate) const EVENT_PRESIGNED_EXPIRY_POSTURE: &str = "gateway_presigned_expiry_posture";
/// The `NAMING_POSTURE` start-up line.
pub(crate) const EVENT_NAMING_POSTURE: &str = "gateway_naming_posture";
/// An assembly that disabled or replaced a security control; `reason` says which.
pub(crate) const EVENT_DANGEROUS_ASSEMBLY: &str = "gateway_dangerous_assembly";
/// A report callback panicked; `callback` names which, and the answer went out unchanged.
pub(crate) const EVENT_REPORT_PANICKED: &str = "gateway_report_panicked";
/// A request refused before its handler answered; `subsystem` names the stage.
pub(crate) const EVENT_REQUEST_REFUSED: &str = "gateway_request_refused";
/// A deployment's handler or authorizer panicked; `extension` names which, and the request was
/// answered `500`.
pub(crate) const EVENT_EXTENSION_PANICKED: &str = "gateway_extension_panicked";

/// Reports an assembly choice that disables or replaces a security control, as one `warn` event.
///
/// `reason` is the stable name an alert selects on; `message` is the sentence the start-up log has
/// always carried for it. Both are fixed text written at the call site, never a value read from a
/// request or a configuration file.
pub(crate) fn dangerous_assembly(reason: &'static str, message: &'static str) {
    tracing::warn!(
        target: TARGET,
        event = EVENT_DANGEROUS_ASSEMBLY,
        component = COMPONENT,
        subsystem = SUBSYSTEM_ASSEMBLY,
        reason,
        "{message}"
    );
}

/// Reports the allow-all authorizer in an assembly. Spelled once here because two assembly paths
/// report it: [`crate::ServiceBuilder::build`] and the snapshot an [`crate::AssemblyUpdate`] builds.
pub(crate) fn allow_all_authorizer_assembled() {
    dangerous_assembly(
        "allow_all_authorizer",
        "dangerous allow-all authorizer disables authorization for every request",
    );
}

/// The stage that refused a request, for [`request_refused`].
///
/// An authorization denial is not here: it is reported where the decision is audited, with the
/// decision itself (`crate::ext::authz_audit`). A panicking extension is not either
/// ([`extension_panicked`]). A refusal the deployment answered — its handler's, its filter's — is
/// not a refusal of the gateway's and has no stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The signature, the credential, the signed-payload declaration, a POST policy or the
    /// security floor refused it, or the authenticator could not answer.
    Authentication,
    /// A limiter refused it before any expensive work, or its body outran its quota.
    Governor,
    /// Its head could not be accepted or routed.
    Wire,
    /// Its query, headers, form or body could not be read into the operation's input.
    Decode,
}

impl Refused {
    const fn subsystem(self) -> &'static str {
        match self {
            Self::Authentication => SUBSYSTEM_AUTHENTICATION,
            Self::Governor => SUBSYSTEM_GOVERNOR,
            Self::Wire => SUBSYSTEM_WIRE,
            Self::Decode => SUBSYSTEM_DECODE,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Authentication => "request refused by authentication",
            Self::Governor => "request refused by a limiter",
            Self::Wire => "request refused before routing",
            Self::Decode => "request refused while reading its input",
        }
    }

    /// The stage a refusal raised while the body was read belongs to. The body stage carries three
    /// answers that are not a malformed body: the handler's own answer over a body it never read
    /// (the deployment's, so none), a body that outran its quota (`503 SlowDown`, the limiter's),
    /// and an `aws-chunked` chunk or trailer whose signature does not verify (authentication's).
    /// Any other internal failure (a `5xx`) is not a refusal either.
    pub(crate) fn reading_the_body(error: &S3Error) -> Option<Self> {
        if error.answered_by_handler {
            return None;
        }
        match error.code() {
            Some(code) if *code == ErrorCode::SLOW_DOWN => Some(Self::Governor),
            Some(code) if *code == ErrorCode::SIGNATURE_DOES_NOT_MATCH => Some(Self::Authentication),
            _ if error.status().is_server_error() => None,
            _ => Some(Self::Decode),
        }
    }

    /// The stage a codec's refusal belongs to: the input could not be read, unless the failure was
    /// the gateway's own, encoding an output (a `5xx`), which is no refusal.
    pub(crate) fn reading_the_input(error: &S3Error) -> Option<Self> {
        (!error.status().is_server_error()).then_some(Self::Decode)
    }

    /// The stage a POST form's refusal belongs to: a policy the form fails is its authentication
    /// (`403`); a form that cannot be read is a malformed input.
    pub(crate) fn reading_a_form(error: &S3Error) -> Option<Self> {
        let status = error.status();
        if status.is_server_error() {
            None
        } else if status == http::StatusCode::FORBIDDEN {
            Some(Self::Authentication)
        } else {
            Some(Self::Decode)
        }
    }
}

/// Reports one refused request as one event: `warn` for an authentication refusal, which an
/// operator acts on, and `debug` for the rest. RustFS logs a credential it cannot find, an
/// unsigned `x-amz-*` header and an unsupported algorithm at `warn` (rustfs/rustfs `3268c42e00`,
/// `rustfs/src/auth.rs:238-265`, `:1090-1125`), its own rate-limit refusals at `debug`
/// (`rustfs/src/server/rate_limit.rs:566`), and a request its S3 stack cannot read not above
/// `debug`; this crate logs every authentication refusal at `warn`, as one class, bounded by the
/// limiter's admission of unauthenticated work.
///
/// The fields are the request identifier the caller received, the operation routing chose
/// (`unknown` when it chose none), the status and the error code the caller was answered with —
/// nothing the caller sent. The code is the whole of the "failure class": which rule refused a
/// credential is what the uniform `403` withholds, and a log line is not a place to write it down
/// (`scripts/check_secret_hygiene.sh`, rule 4).
pub(crate) fn request_refused(
    refused: Refused,
    request_id: &RequestId,
    operation: Option<&str>,
    status: u16,
    code: Option<&ErrorCode>,
) {
    let (subsystem, message) = (refused.subsystem(), refused.message());
    let operation = operation.unwrap_or("unknown");
    let code = code.map_or("none", ErrorCode::as_str);
    match refused {
        Refused::Authentication => tracing::warn!(
            target: TARGET,
            event = EVENT_REQUEST_REFUSED,
            component = COMPONENT,
            subsystem,
            result = "refused",
            request_id = %request_id,
            operation,
            status,
            code,
            "{message}"
        ),
        Refused::Governor | Refused::Wire | Refused::Decode => tracing::debug!(
            target: TARGET,
            event = EVENT_REQUEST_REFUSED,
            component = COMPONENT,
            subsystem,
            result = "refused",
            request_id = %request_id,
            operation,
            status,
            code,
            "{message}"
        ),
    }
}

/// A deployment extension that can panic while serving a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Extension {
    /// The operation's handler, and whatever runs inside its dispatch: its operation layers, the
    /// policy source's snapshot, the CORS source.
    Handler,
    /// The authorizer, at either stage.
    Authorizer,
}

impl Extension {
    const fn name(self) -> &'static str {
        match self {
            Self::Handler => "handler",
            Self::Authorizer => "authorizer",
        }
    }

    fn throttle(self) -> &'static Throttle {
        static HANDLER: Throttle = Throttle::new();
        static AUTHORIZER: Throttle = Throttle::new();
        match self {
            Self::Handler => &HANDLER,
            Self::Authorizer => &AUTHORIZER,
        }
    }
}

/// Reports a deployment extension that panicked while serving a request, as one `error` event,
/// at most one per [`Throttle`] interval for each extension, carrying how many it stood for. The
/// payload is deployment text and is never logged.
pub(crate) fn extension_panicked(extension: Extension, request_id: &RequestId, operation: &str) {
    if !tracing::enabled!(target: TARGET, tracing::Level::ERROR) {
        return;
    }
    let Some(suppressed) = extension.throttle().claim() else {
        return;
    };
    let extension = extension.name();
    tracing::error!(
        target: TARGET,
        event = EVENT_EXTENSION_PANICKED,
        component = COMPONENT,
        subsystem = SUBSYSTEM_EXTENSION,
        result = "contained",
        extension,
        request_id = %request_id,
        operation,
        suppressed,
        "{extension} panicked; the request was answered 500"
    );
}

/// At most one event per five seconds for a class of per-request `error` event, each one written
/// carrying how many were held back since the last: RustFS's `LogThrottle` (rustfs/rustfs
/// `3268c42e00`, `crates/utils/src/logging.rs:21-58`), which bounds its own per-request `5xx` line
/// the same way (`rustfs/src/server/layer.rs:74`, `:493-500`). A deployment extension that panics
/// on every request is one line per interval, not one per request.
pub(crate) struct Throttle {
    /// The monotonic millisecond of the last event written; `u64::MAX` before the first.
    last: AtomicU64,
    /// How many were held back since that event.
    suppressed: AtomicU64,
}

impl Throttle {
    const INTERVAL_MILLIS: u64 = 5_000;

    pub(crate) const fn new() -> Self {
        Self {
            last: AtomicU64::new(u64::MAX),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(held back since the last event)` when an event may be written now; `None`, counting
    /// one more held back, when not.
    pub(crate) fn claim(&self) -> Option<u64> {
        static SOURCE: OnceLock<SystemMonotonic> = OnceLock::new();
        self.claim_at(SOURCE.get_or_init(SystemMonotonic::new).monotonic().millis())
    }

    fn claim_at(&self, now: u64) -> Option<u64> {
        let last = self.last.load(Ordering::Relaxed);
        let due = last == u64::MAX || now.saturating_sub(last) >= Self::INTERVAL_MILLIS;
        if due
            && self
                .last
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use rustfs_gateway_core::{HandlerError, ResponseKind};

    use super::*;
    use crate::close::ConnectionIntent;
    use crate::render::from_handler;

    fn refusal(code: ErrorCode) -> S3Error {
        from_handler(HandlerError::new(code, "a refusal"), ResponseKind::Other, ConnectionIntent::MayKeepAlive)
    }

    /// Positive — the first event is written, the ones inside the interval are held back and
    /// counted, and the first one after it carries the count.
    #[test]
    fn a_throttle_writes_one_event_per_interval_with_the_count_it_stood_for() {
        let throttle = Throttle::new();
        assert_eq!(throttle.claim_at(1_000), Some(0));
        assert_eq!(throttle.claim_at(1_001), None);
        assert_eq!(throttle.claim_at(5_999), None);
        assert_eq!(throttle.claim_at(6_000), Some(2));
        assert_eq!(throttle.claim_at(6_001), None);
        assert_eq!(throttle.claim_at(11_000), Some(1));
    }

    /// Negative — a body-stage refusal is the limiter's when it is the quota's `SlowDown`,
    /// authentication's when a chunk's signature failed, a malformed input otherwise, and no
    /// refusal of the gateway's when the handler answered it or it is an internal failure.
    #[test]
    fn a_body_stage_refusal_is_classified_by_what_raised_it() {
        assert_eq!(Refused::reading_the_body(&refusal(ErrorCode::SLOW_DOWN)), Some(Refused::Governor));
        assert_eq!(
            Refused::reading_the_body(&refusal(ErrorCode::SIGNATURE_DOES_NOT_MATCH)),
            Some(Refused::Authentication)
        );
        assert_eq!(Refused::reading_the_body(&refusal(ErrorCode::BAD_DIGEST)), Some(Refused::Decode));
        assert_eq!(Refused::reading_the_body(&refusal(ErrorCode::INTERNAL_ERROR)), None);
        let mut answered = refusal(ErrorCode::NO_SUCH_BUCKET);
        answered.answered_by_handler = true;
        assert_eq!(Refused::reading_the_body(&answered), None);
    }

    /// Negative — a codec failure is a malformed input unless it is the gateway's own `5xx`; a
    /// form refused `403` is its policy's, any other `4xx` a malformed form.
    #[test]
    fn codec_and_form_refusals_are_classified_by_status() {
        assert_eq!(Refused::reading_the_input(&refusal(ErrorCode::MALFORMED_XML)), Some(Refused::Decode));
        assert_eq!(Refused::reading_the_input(&refusal(ErrorCode::INTERNAL_ERROR)), None);
        assert_eq!(Refused::reading_a_form(&refusal(ErrorCode::ACCESS_DENIED)), Some(Refused::Authentication));
        assert_eq!(Refused::reading_a_form(&refusal(ErrorCode::INVALID_ARGUMENT)), Some(Refused::Decode));
        assert_eq!(Refused::reading_a_form(&refusal(ErrorCode::INTERNAL_ERROR)), None);
    }
}
