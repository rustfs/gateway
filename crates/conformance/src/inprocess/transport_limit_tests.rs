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

//! Responsible for: proving the in-process target types exactly its transport limits — the shapes
//! a socket transport carries out and this target cannot — as [`SutError::TransportLimit`], and
//! leaves every other refusal an environment failure (rustfs/gateway#985).
//! NOT responsible for: which outcomes the reference evaluation re-runs (`runner::reference`), or
//! the wording of each refusal (the tests beside each refusal).
//! Upstream: `super::InProcess::read_request`, `super::read_connection`, `Sut::exchange_concurrent`.
//! Downstream: none.

use std::path::PathBuf;

use super::*;
use crate::sut::{Sut, SutError};

fn request(fields: Vec<(&str, Value)>) -> Value {
    Value::Table(fields.into_iter().map(|(name, value)| (name.to_owned(), value)).collect())
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn connection(field: &str, value: Value) -> Value {
    request(vec![(field, value)])
}

/// Every request shape this target refuses because it has no socket is a transport limit.
#[test]
fn every_request_shape_that_needs_a_socket_is_a_transport_limit() {
    let target = InProcess::new(PathBuf::from("."));
    let half_close = Value::Array(vec![request(vec![("action", text("half_close"))])]);
    for shape in [
        request(vec![("raw_head_utf8", text("GET / HTTP/1.1"))]),
        request(vec![("method", text("GET")), ("target", text("/")), ("http_version", text("h2"))]),
        request(vec![("method", text("PUT")), ("target", text("/b/k")), ("chunks", half_close)]),
    ] {
        let error = target.read_request(&shape).expect_err("must be refused");
        assert!(matches!(error, SutError::TransportLimit(_)), "{error:?}");
    }
}

/// Every connection instruction this target refuses because it has no connection is a transport
/// limit.
#[test]
fn every_connection_instruction_that_needs_a_socket_is_a_transport_limit() {
    for instruction in [
        connection("pipeline", Value::Bool(true)),
        connection("tls", request(vec![("alpn", Value::Array(vec![text("h2")]))])),
        connection("read_window_bytes", Value::Integer(1)),
        connection("idle_timeout_ms", Value::Integer(1)),
        connection("reuse", Value::Bool(false)),
    ] {
        let error = read_connection(Some(&instruction)).expect_err("must be refused");
        assert!(matches!(error, SutError::TransportLimit(_)), "{error:?}");
    }
}

/// A declared concurrent batch is a transport limit of a target that has no concurrent dispatch.
#[test]
fn a_concurrent_batch_is_a_transport_limit() {
    let mut target = InProcess::new(PathBuf::from("."));
    let error = target.exchange_concurrent(&[]).expect_err("must be refused");
    assert!(matches!(error, SutError::TransportLimit(_)), "{error:?}");
}

/// Negative — what the harness itself cannot do, on any transport, stays an environment failure:
/// a request without a method, and a signing mode the shared signer does not produce.
#[test]
fn n_a_harness_limit_is_not_a_transport_limit() {
    let target = InProcess::new(PathBuf::from("."));
    let error = target
        .read_request(&request(vec![("target", text("/b/k"))]))
        .expect_err("must be refused");
    assert!(matches!(error, SutError::Environment(_)), "{error:?}");
    let sign = request(vec![("mode", text("sigv4_streaming"))]);
    let wire = target
        .read_request(&request(vec![("method", text("PUT")), ("target", text("/b/k"))]))
        .expect("a plain request is read");
    let request_time = crate::time::parse_rfc3339(crate::time::DEFAULT_FIXED).expect("the default instant");
    let error = sign_request(&sign, &wire, &wire.headers, &request_time, target.limits(), 0)
        .expect_err("a streaming mode is not wired in the shared signer");
    assert!(matches!(error, SutError::Environment(_)), "{error:?}");
}

/// Negative — a clock this target cannot move is refused by the clock every transport shares, so
/// it is not this target's transport limit either.
#[test]
fn n_a_moving_clock_is_not_a_transport_limit() {
    let clock = request(vec![("advance_ms_between_exchanges", Value::Integer(1))]);
    let error = clock_of(Some(&clock)).expect_err("must be refused");
    assert!(matches!(error, SutError::Environment(_)), "{error:?}");
}
