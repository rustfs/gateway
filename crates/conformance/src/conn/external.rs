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

//! External endpoint exchange over caller-selected HTTP or HTTPS.
//!
//! Responsible for: driving authored request steps without the loopback server's private demand
//! observer, including cleartext delays that stop on observed response bytes. NOT responsible for:
//! endpoint parsing, TLS setup, authored HTTP/2 frames (`super::h2`), controlled bodies, remote fixture lifecycle, request
//! interpretation, or response judgement. Upstream: `super`; downstream: `crate::cli` through
//! [`super::Conn`].

use std::path::Path;
use std::time::{Duration, Instant};

use super::external_endpoint::ExternalEndpoint;
use super::external_pacing::{validate_authored_steps, write_authored_body};
use super::{Conn, DispatchedExchange, Head, budget_of, observe_socket_exchange, read_connection};
#[cfg(test)]
use crate::inprocess::ChunkStep;
use crate::inprocess::InProcess;
use crate::observation::{ConnectionState, Observation};
use crate::socket::{Connection, ReadFailure};
use crate::sut::{ExchangePlan, SutError};

impl Conn {
    /// Builds a target that writes corpus requests to a caller-supplied HTTP(S) endpoint.
    pub fn external(root: std::path::PathBuf, endpoint: &str) -> Result<Conn, SutError> {
        Self::external_with_ca(root, endpoint, None)
    }

    /// Builds an HTTP(S) target, optionally trusting additional PEM-encoded CA certificates.
    pub fn external_with_ca(root: std::path::PathBuf, endpoint: &str, ca_path: Option<&Path>) -> Result<Conn, SutError> {
        Self::external_configured(root, endpoint, ca_path, false)
    }

    /// Builds an HTTP(S) target permitting isolated owned bucket, object, version, and empty-upload fixtures.
    pub fn external_with_fixtures(root: std::path::PathBuf, endpoint: &str, ca_path: Option<&Path>) -> Result<Conn, SutError> {
        Self::external_configured(root, endpoint, ca_path, true)
    }

    /// Sends authored writes to the endpoint, which the operator declared disposable, and empties
    /// every declared bucket at cleanup.
    pub(crate) fn allow_external_writes(&mut self) {
        self.external_fixtures.writes = true;
    }

    fn external_configured(
        root: std::path::PathBuf,
        endpoint: &str,
        ca_path: Option<&Path>,
        external_fixtures: bool,
    ) -> Result<Conn, SutError> {
        Ok(Conn {
            inner: InProcess::new(root),
            external: Some(ExternalEndpoint::parse_with_ca(endpoint, ca_path)?),
            endpoint_fixed_time: None,
            external_fixtures: super::external_fixture::ExternalFixtures::new(external_fixtures),
            listener: None,
            connection: None,
            #[cfg(feature = "production-transports")]
            production: None,
            #[cfg(feature = "production-transports")]
            driver: None,
            #[cfg(feature = "production-transports")]
            production_tls: None,
            pacer: std::sync::Arc::new(crate::socket::Pacer::new()),
            #[cfg(test)]
            setup_delay: std::time::Duration::ZERO,
        })
    }

    pub(super) fn exchange_external(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        self.external_fixtures.clear_control_connection();
        let endpoint = self
            .external
            .clone()
            .ok_or_else(|| SutError::Environment("external exchange has no configured endpoint".to_owned()))?;
        let clock = super::external_clock::external_clock(plan.clock, self.external_now()?, self.endpoint_fixed_time.as_ref())?;
        let reuse = read_connection(plan.connection)?;
        self.inner.set_fixture_now(clock.now.unix_seconds);
        let mut wire = self.inner.read_wire(&plan.request)?;
        super::external_clock::remap_sigv2_authored_dates(&mut wire, &clock)?;
        let request_time = clock.request_time;
        let version_write = self.external_fixtures.version_write(plan.case_id, &wire)?;
        if !wire.h2_frames.is_empty() {
            return self.exchange_h2_external(plan, &wire, &endpoint, reuse);
        }
        if wire.http_version.as_deref() == Some("h2") {
            return Err(SutError::Environment(
                "`request.http_version = \"h2\"` needs authored `request.h2_frames` against an external endpoint; \
                 this target builds no HPACK request of its own"
                    .to_owned(),
            ));
        }
        let budget = budget_of(plan.timeout_ms);
        let started = Instant::now();
        let deadline = started
            .checked_add(budget)
            .ok_or_else(|| SutError::Environment("external endpoint setup deadline cannot be represented".to_owned()))?;
        let cleartext = !endpoint.is_tls();
        validate_authored_steps(&wire, cleartext, budget)?;
        let head = self.head_for_profile(&wire, &request_time, plan.profile)?;
        if version_write.is_some() {
            self.external_fixtures
                .validate_version_head(&wire, &head, endpoint.authority())?;
        }
        let existing = self.connection.as_ref().map(Connection::observe_pending);
        if reuse && existing.is_some_and(|(_, pending)| pending) {
            self.connection = None;
            return Err(SutError::Environment(
                "external endpoint sent unframed bytes before connection reuse".to_owned(),
            ));
        }
        let fresh = !reuse || existing.is_none_or(|(state, _)| state != ConnectionState::Open);
        if fresh {
            self.connection = Some(endpoint.open(deadline)?);
        }
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| SutError::Environment("external endpoint connection was not opened".to_owned()))?;
        let pending_version = version_write.map(|version| self.external_fixtures.begin_version_write(version));
        let result = execute_socket_exchange(connection, &wire, &head, started, deadline, cleartext)?;
        if let Some(index) = pending_version {
            self.external_fixtures.observe_version_write(index, &result.observation)?;
        }
        if result.torn_down || endpoint.is_tls() {
            self.connection = None;
        }
        Ok(result.observation)
    }
}

pub(super) fn execute_socket_exchange(
    connection: &mut Connection,
    wire: &crate::inprocess::Wire,
    head: &Head,
    started: Instant,
    deadline: Instant,
    cleartext: bool,
) -> Result<super::exchange::SocketExchangeResult, SutError> {
    let budget = deadline
        .checked_duration_since(started)
        .ok_or_else(|| SutError::Environment("external endpoint exchange deadline precedes its start".to_owned()))?;
    validate_authored_steps(wire, cleartext, budget)?;
    connection.start_exchange();
    connection.write(&head.bytes)?;
    let progress = write_authored_body(connection, wire, head.declared_length, deadline)?;
    let discard_unfinished_request = progress.measured_at_response && !progress.fully_sent;
    let mut result = observe_socket_exchange(
        connection,
        wire,
        head,
        DispatchedExchange {
            harness_wait: Duration::ZERO,
            progress,
            started,
            deadline,
        },
    );
    if discard_unfinished_request {
        result.torn_down = true;
        result
            .observation
            .notes
            .push("the client discarded the connection after an early response interrupted the request body".to_owned());
    }
    validate_external_response(&result, wire)?;
    result.observation.ttfb_ms = None;
    result
        .observation
        .notes
        .push("external endpoint TTFB is unavailable because this target does not instrument the first response byte".to_owned());
    if connection_closes(&result.observation.headers)
        || crate::socket::parse_head(&head.bytes).is_some_and(|parsed| connection_closes(&parsed.headers))
    {
        result.torn_down = true;
    }
    Ok(result)
}

fn validate_external_response(
    result: &super::exchange::SocketExchangeResult,
    wire: &crate::inprocess::Wire,
) -> Result<(), SutError> {
    match result.read_failure.as_ref() {
        Some(ReadFailure::TimedOut | ReadFailure::Reset) => return Ok(()),
        Some(failure) => {
            return Err(SutError::Environment(format!(
                "external endpoint did not send a complete HTTP/1.1 response: {failure}"
            )));
        }
        None => {}
    }
    if result.pending_input {
        return Err(SutError::Environment(
            "external endpoint sent bytes after the framed response body".to_owned(),
        ));
    }
    let observation = &result.observation;
    let Some(status) = observation.status else {
        return Err(SutError::Environment(
            "external endpoint response completed without an observed status".to_owned(),
        ));
    };
    if (100..200).contains(&status) {
        return Err(SutError::Environment(format!(
            "external endpoint returned informational status {status}; consuming the following final response is not implemented"
        )));
    }
    let framed = observation
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding"));
    if crate::socket::carries_a_body(&wire.method, status) && !framed {
        return Err(SutError::Environment(
            "external endpoint returned a close-delimited response body; this target cannot observe it without consuming connection state"
                .to_owned(),
        ));
    }
    Ok(())
}

fn connection_closes(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && value.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"))
    })
}

/// Outcome of one external fixture-control HTTP/1.1 exchange.
pub(super) enum ControlExchangeOutcome {
    /// A response or timeout completed; `torn_down` is true when the connection must not be reused.
    Completed { observation: Observation, torn_down: bool },
    /// The socket failed before any response head arrived; safe to retry once on a fresh socket
    /// only when the caller reused an idle keep-alive connection for an idempotent control.
    ClosedBeforeResponse { fallback: Result<Observation, SutError> },
}

/// Executes one unpaced external fixture-control exchange without paying the 250 ms post-exchange
/// socket observation window needed only for authored `expect.connection_after` assertions.
pub(super) fn execute_control_exchange(
    connection: &mut Connection,
    wire: &crate::inprocess::Wire,
    head: &Head,
    started: Instant,
    deadline: Instant,
) -> Result<ControlExchangeOutcome, SutError> {
    connection.start_exchange();
    if let Err(error) = connection.write_control(&head.bytes) {
        let sut_error = SutError::Environment(format!("cannot write on the connection: {error}"));
        return if is_stale_write_error(error.kind()) {
            Ok(ControlExchangeOutcome::ClosedBeforeResponse {
                fallback: Err(sut_error),
            })
        } else {
            Err(sut_error)
        };
    }
    if !wire.body.is_empty()
        && let Err(error) = connection.write_control(&wire.body)
    {
        let sut_error = SutError::Environment(format!("cannot write on the connection: {error}"));
        return if is_stale_write_error(error.kind()) {
            Ok(ControlExchangeOutcome::ClosedBeforeResponse {
                fallback: Err(sut_error),
            })
        } else {
            Err(sut_error)
        };
    }
    let read = match super::remaining(deadline) {
        Ok(remaining) => connection.read_response_classified(&wire.method, remaining),
        Err(_) => Err(ReadFailure::TimedOut),
    };
    let elapsed_ms = super::elapsed_ms(started);
    match read {
        Ok(response) => {
            if (100..200).contains(&response.status) {
                return Err(SutError::Environment(format!(
                    "external endpoint returned informational status {}; consuming the following final response is not implemented",
                    response.status
                )));
            }
            let framed = response
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding"));
            if crate::socket::carries_a_body(&wire.method, response.status) && !framed {
                return Err(SutError::Environment(
                    "external endpoint returned a close-delimited response body; this target cannot observe it without consuming connection state"
                        .to_owned(),
                ));
            }
            let torn_down = connection_closes(&response.headers) || connection_closes(&wire.headers);
            let (outcome, termination, before_error, events, event_note) =
                super::classify_body(response.status, &response.headers, &response.body);
            let notes = event_note.into_iter().collect();
            let observation = Observation {
                outcome,
                stream_termination: termination,
                status: Some(response.status),
                http_version: Some("http/1.1".to_owned()),
                h2_control_frames: None,
                socket_read_after: None,
                headers: response.headers,
                trailers: Vec::new(),
                body: response.body,
                body_bytes_before_error: before_error,
                request_body_bytes_sent_at_response: None,
                request_body_fully_sent: Some(true),
                ttfb_ms: None,
                elapsed_ms,
                harness_wait_ms: 0,
                deadline_expiry: None,
                connection_after: None,
                events,
                notes,
            };
            Ok(ControlExchangeOutcome::Completed { observation, torn_down })
        }
        Err(ReadFailure::TimedOut) => Ok(ControlExchangeOutcome::Completed {
            observation: empty_control_observation(crate::observation::Outcome::Hang, elapsed_ms),
            torn_down: true,
        }),
        Err(ReadFailure::Reset) => Ok(ControlExchangeOutcome::ClosedBeforeResponse {
            fallback: Ok(empty_control_observation(crate::observation::Outcome::ConnectionReset, elapsed_ms)),
        }),
        Err(failure @ ReadFailure::ClosedBeforeHead) => Ok(ControlExchangeOutcome::ClosedBeforeResponse {
            fallback: Err(SutError::Environment(format!(
                "external endpoint did not send a complete HTTP/1.1 response: {failure}"
            ))),
        }),
        Err(failure) => Err(SutError::Environment(format!(
            "external endpoint did not send a complete HTTP/1.1 response: {failure}"
        ))),
    }
}

fn is_stale_write_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
    )
}

fn empty_control_observation(outcome: crate::observation::Outcome, elapsed_ms: u64) -> Observation {
    Observation {
        outcome,
        stream_termination: None,
        status: None,
        http_version: None,
        h2_control_frames: None,
        socket_read_after: None,
        headers: Vec::new(),
        trailers: Vec::new(),
        body: Vec::new(),
        body_bytes_before_error: None,
        request_body_bytes_sent_at_response: None,
        request_body_fully_sent: Some(true),
        ttfb_ms: None,
        elapsed_ms,
        harness_wait_ms: 0,
        deadline_expiry: None,
        connection_after: None,
        events: Vec::new(),
        notes: Vec::new(),
    }
}

#[cfg(test)]
mod tests;
