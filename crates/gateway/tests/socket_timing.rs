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

//! Socket-timing integration-test entry point for `rustfs-gateway`.
//!
//! Responsible for: registering the gateway suites that wait on real sockets and timers in a second
//! Cargo target, which `cargo xtask verify --crate rustfs-gateway` runs as its own 30-second loop.
//! NOT responsible for: test behavior or production implementation.
//! Upstream: the gateway socket-timing test modules. Downstream: Cargo's test harness.

#[allow(unused_imports)] // The re-exports for suites in `tests/integration.rs` go unused in this target.
mod support;

#[path = "committed_progress.rs"]
mod committed_progress;
#[path = "connection_teardown.rs"]
mod connection_teardown;
#[path = "file_transfer.rs"]
mod file_transfer;
#[path = "payload_transport.rs"]
mod payload_transport;
#[path = "self_held_expect_continue.rs"]
mod self_held_expect_continue;
#[path = "self_held_http1.rs"]
mod self_held_http1;
#[path = "self_held_refusal_drain.rs"]
mod self_held_refusal_drain;
#[path = "streaming_request.rs"]
mod streaming_request;
#[path = "throughput_request.rs"]
mod throughput_request;
