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

    /// Builds an HTTP(S) target whose explicit opt-in permits isolated owned bucket/object fixtures.
    pub fn external_with_fixtures(root: std::path::PathBuf, endpoint: &str, ca_path: Option<&Path>) -> Result<Conn, SutError> {
        Self::external_configured(root, endpoint, ca_path, true)
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
            external_fixtures: super::external_fixture::ExternalFixtures::new(external_fixtures),
            listener: None,
            connection: None,
            #[cfg(feature = "production-transports")]
            production: None,
            #[cfg(feature = "production-transports")]
            driver: None,
            pacer: std::sync::Arc::new(crate::socket::Pacer::new()),
        })
    }

    pub(super) fn exchange_external(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        let endpoint = self
            .external
            .clone()
            .ok_or_else(|| SutError::Environment("external exchange has no configured endpoint".to_owned()))?;
        let (fixed, request_time, _) = crate::inprocess::clock_of(plan.clock)?;
        let reuse = read_connection(plan.connection)?;
        self.inner.set_fixture_now(fixed.unix_seconds);
        let wire = self.inner.read_wire(&plan.request)?;
        self.external_fixtures.ensure_read_only(plan.case_id, &wire)?;
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
        let head = self.head(&wire, &request_time)?;
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
        let result = execute_socket_exchange(connection, &wire, &head, started, deadline, cleartext)?;
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

#[cfg(test)]
mod tests;
