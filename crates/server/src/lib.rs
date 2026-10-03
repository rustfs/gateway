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

//! General-purpose ring-1 server runtime.
//!
//! Responsible for: listening sockets, TLS, HTTP connection driving, connection admission,
//! connection-level timeouts, generic path dispatch and explicit graceful shutdown.
//! NOT responsible for: S3 protocol behaviour, host normalization, body-read intervals or
//! handler-progress timeouts.
//! Upstream: any `tower::Service`. Downstream: Tokio, Hyper and Rustls.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
// No stdout, no stderr, no `dbg!` outside tests: a diagnostic is a `tracing` event (docs/observability.md).
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro))]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod accept_error;
mod client_admission;
mod config;
mod conn;
mod connection_service;
mod dispatch;
mod driver;
mod io;
pub mod layers;
mod listener;
mod request_capacity;
mod send_deadline;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod sendfile;
mod sendfile_task;
mod shutdown;
mod tls;
mod write_receipt;

pub use config::{ConfigError, ServerConfig, WriteStrategy, conn_memory_budget};
pub use conn::{Server, ServerError};
pub use connection_service::{
    ConnectionBody, ConnectionError, ConnectionResponseBody, ConnectionService, ResponseCompletion, UnfinishedRequestBody,
};
pub use dispatch::PrefixDispatch;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub use driver::FileTransferProgress;
pub use driver::{
    AcceptedConnection, ConnectionDriver, ConnectionFuture, ConnectionInfo, DriverValidationError, HyperConnectionDriver,
    PlaintextConnection, PlaintextTakeoverError, TransportKind,
};
pub use listener::{Listener, ListenerOptions};
pub use request_capacity::RequestCancellation;
pub use shutdown::{RunningServer, ServerMetrics, ShutdownReport, ShutdownTrigger};
pub use tls::{DEFAULT_ALPN_PROTOCOLS, TlsHandle, TlsMaterial, TlsReloadError};
