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

//! Owns HTTP/1.1 exchange execution, including concurrent dispatch over distinct observed client
//! sockets. It does not select cases or judge observations. `runner` is upstream through [`Sut`],
//! while the socket response classifier in the parent module is downstream.

use std::collections::BTreeSet;

use super::*;

pub(super) struct SocketExchangeResult {
    pub(super) observation: Observation,
    pub(super) torn_down: bool,
}

pub(super) fn execute_socket_exchange(
    connection: &mut Connection,
    pacer: &Arc<Pacer>,
    wire: &Wire,
    head: &Head,
    budget: Duration,
) -> Result<SocketExchangeResult, SutError> {
    let dispatched = dispatch_socket_exchange(connection, pacer, wire, head, budget)?;
    Ok(observe_socket_exchange(connection, wire, head, dispatched))
}

struct ConcurrentSocketExchange {
    connection: Connection,
    pacer: Arc<Pacer>,
    wire: Wire,
    head: Head,
    budget: Duration,
    dispatched: Option<DispatchedExchange>,
}

impl Conn {
    pub(super) fn exchange_concurrent_sockets(&mut self, plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        if plans.len() < 2 {
            return Err(SutError::Environment(
                "a concurrent socket batch requires at least two exchanges".to_owned(),
            ));
        }
        self.connection = None;
        let mut clock = None;
        let mut local_endpoints = BTreeSet::new();
        let mut prepared = Vec::with_capacity(plans.len());
        for plan in plans {
            read_concurrent_connection(plan.connection)?;
            let (fixed, request_time, skew_ms) = clock_of(plan.clock)?;
            let current_clock = (fixed.unix_seconds, skew_ms);
            if clock.is_some_and(|expected| expected != current_clock) {
                return Err(SutError::Environment(
                    "every exchange in a concurrent batch must use the same fixture clock".to_owned(),
                ));
            }
            clock = Some(current_clock);
            self.inner.set_fixture_now(fixed.unix_seconds);

            let wire = self.inner.read_wire(&plan.request)?;
            if wire.h2_frames || wire.http_version.as_deref() == Some("h2") {
                return Err(SutError::Environment("concurrent batches currently require HTTP/1.1 requests".to_owned()));
            }
            let head = self.head(&wire, &request_time)?;
            let addr = self.addr(fixed.unix_seconds, skew_ms)?;
            let connection = Connection::open(addr)?;
            let local_endpoint = connection.local_addr()?;
            if !local_endpoints.insert(local_endpoint) {
                return Err(SutError::Environment(format!(
                    "concurrent exchanges shared the observed client endpoint {local_endpoint}"
                )));
            }
            let pacer = Arc::new(Pacer::new());
            #[cfg(feature = "production-transports")]
            if let Some(production) = &self.production {
                production.enqueue_pacer(&pacer);
            } else {
                self.listener(fixed.unix_seconds, skew_ms)?.enqueue_pacer(&pacer);
            }
            #[cfg(not(feature = "production-transports"))]
            self.listener(fixed.unix_seconds, skew_ms)?.enqueue_pacer(&pacer);
            prepared.push(ConcurrentSocketExchange {
                connection,
                pacer,
                wire,
                head,
                budget: budget_of(plan.timeout_ms),
                dispatched: None,
            });
        }

        // Release every complete request onto its own socket before awaiting even one response.
        // The server can therefore dispatch all handlers concurrently; declaration order is used
        // only when the observations are returned to the runner for judgement.
        for exchange in &mut prepared {
            exchange.dispatched = Some(dispatch_socket_exchange(
                &mut exchange.connection,
                &exchange.pacer,
                &exchange.wire,
                &exchange.head,
                exchange.budget,
            )?);
        }

        prepared
            .into_iter()
            .map(|mut exchange| {
                let dispatched = exchange.dispatched.take().ok_or_else(|| {
                    SutError::Environment("a concurrent request was not dispatched before observation".to_owned())
                })?;
                Ok(observe_socket_exchange(&mut exchange.connection, &exchange.wire, &exchange.head, dispatched).observation)
            })
            .collect()
    }
}

pub(super) fn read_concurrent_connection(connection: Option<&Value>) -> Result<(), SutError> {
    let empty = Value::empty_table();
    let connection = connection.unwrap_or(&empty);
    if connection.read("connection.concurrent").and_then(Value::as_bool) != Some(true) {
        return Err(SutError::Environment(
            "the runner invoked a concurrent batch without `connection.concurrent = true`".to_owned(),
        ));
    }
    if connection.read("connection.pipeline").is_some() {
        return Err(SutError::Environment(
            "`connection.concurrent` and `connection.pipeline` are mutually exclusive".to_owned(),
        ));
    }
    if connection.read("connection.reuse").is_some() {
        return Err(SutError::Environment(
            "`connection.concurrent` always uses one fresh connection per exchange; `connection.reuse` must be omitted"
                .to_owned(),
        ));
    }
    if connection.read("connection.tls").is_some()
        || connection.read("connection.read_window_bytes").is_some()
        || connection.read("connection.idle_timeout_ms").is_some()
    {
        return Err(SutError::Environment(
            "concurrent batches currently require cleartext sockets without per-connection backpressure or idle-time controls"
                .to_owned(),
        ));
    }
    Ok(())
}
