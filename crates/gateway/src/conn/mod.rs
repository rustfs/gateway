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

//! Production self-held plaintext HTTP/1.1 connection driver.
//!
//! Responsible for: selecting the cleartext connection path once, sequencing HTTP/1.1 requests,
//! invoking the mandatory server lifecycle service and closing the real socket when required.
//! NOT responsible for: S3 request acceptance, signing, routing, XML or response policy.
//! Upstream: the generic server's accepted-connection seam.
//! Downstream: the common gateway service.

mod metrics;
mod request;
mod response;

use std::io;
use std::sync::Arc;

use http::{Request, Response};
use rustfs_gateway_server::{
    AcceptedConnection, ConnectionDriver, ConnectionError, ConnectionFuture, DriverValidationError, PlaintextTakeoverError,
    ServerConfig,
};
use rustfs_gateway_stream::Body;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tower::Service;

pub use metrics::{ResponseFallbackReason, ResponseTransportMetrics};
pub use request::SelfHeldRequestBody;
use request::{ConnectionIo, Expectation, HeaderTimeout, read_request};
use response::{write_bad_request, write_continue, write_expectation_failed, write_response};

/// Driver for an explicitly configured plaintext HTTP/1.1 listener.
///
/// TLS and HTTP/2 remain on the default Hyper driver. This driver is selected once for a listener
/// and owns every accepted socket on that listener until the connection closes.
#[derive(Clone, Copy, Debug, Default)]
pub struct SelfHeldHttp1Driver;

impl SelfHeldHttp1Driver {
    /// Builds a driver whose transport observations are recorded into `metrics`.
    #[must_use]
    pub fn with_metrics(metrics: Arc<ResponseTransportMetrics>) -> MeasuredSelfHeldHttp1Driver {
        MeasuredSelfHeldHttp1Driver { metrics }
    }
}

/// Self-held plaintext HTTP/1.1 driver with a caller-owned observation handle.
#[derive(Clone, Debug)]
pub struct MeasuredSelfHeldHttp1Driver {
    metrics: Arc<ResponseTransportMetrics>,
}

impl MeasuredSelfHeldHttp1Driver {
    /// The transport observations shared by every connection driven by this value.
    #[must_use]
    pub fn metrics(&self) -> &Arc<ResponseTransportMetrics> {
        &self.metrics
    }
}

impl<S> ConnectionDriver<S> for SelfHeldHttp1Driver
where
    S: Service<Request<SelfHeldRequestBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<ConnectionError> + Send + 'static,
{
    fn validate(&self, _config: &ServerConfig, tls_configured: bool) -> Result<(), DriverValidationError> {
        validate_plaintext(tls_configured)
    }

    fn drive(&self, accepted: AcceptedConnection<S>) -> ConnectionFuture {
        Box::pin(run(accepted, None))
    }
}

impl<S> ConnectionDriver<S> for MeasuredSelfHeldHttp1Driver
where
    S: Service<Request<SelfHeldRequestBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<ConnectionError> + Send + 'static,
{
    fn validate(&self, _config: &ServerConfig, tls_configured: bool) -> Result<(), DriverValidationError> {
        validate_plaintext(tls_configured)
    }

    fn drive(&self, accepted: AcceptedConnection<S>) -> ConnectionFuture {
        Box::pin(run(accepted, Some(Arc::clone(&self.metrics))))
    }
}

fn validate_plaintext(tls_configured: bool) -> Result<(), DriverValidationError> {
    if tls_configured {
        Err(Box::new(PlaintextTakeoverError))
    } else {
        Ok(())
    }
}

async fn run<S>(accepted: AcceptedConnection<S>, transport_metrics: Option<Arc<ResponseTransportMetrics>>)
where
    S: Service<Request<SelfHeldRequestBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<ConnectionError> + Send + 'static,
{
    let config = accepted.config().clone();
    let first_header_deadline = accepted.header_deadline();
    let mut shutdown = accepted.shutdown_receiver();
    let Ok((stream, mut service)) = accepted.into_plaintext() else {
        return;
    };
    if let Some(metrics) = &transport_metrics {
        metrics.record_selected_connection();
    }
    let io = Arc::new(Mutex::new(ConnectionIo::new(stream)));
    let mut first_request = true;

    loop {
        if *shutdown.borrow() {
            break;
        }
        let header_timeout = if first_request {
            HeaderTimeout::At(first_header_deadline)
        } else {
            HeaderTimeout::After(config.keep_alive_idle.min(config.header_read_timeout))
        };
        let head = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() {
                    break;
                }
                break;
            }
            result = read_request(Arc::clone(&io), config.h1_max_buf_size, header_timeout) => result,
        };
        let parsed = match head {
            Ok(None) => break,
            Ok(Some(parsed)) => parsed,
            Err(_) => {
                let mut locked = io.lock().await;
                let _ = write_bad_request(&mut locked).await;
                let _ = locked.stream.shutdown().await;
                return;
            }
        };
        first_request = false;
        match parsed.expectation {
            Expectation::Unsupported => {
                let mut locked = io.lock().await;
                let _ = write_expectation_failed(&mut locked).await;
                let _ = locked.stream.shutdown().await;
                return;
            }
            Expectation::Continue if parsed.body_expected => {
                let mut locked = io.lock().await;
                if write_continue(&mut locked).await.is_err() {
                    let _ = locked.stream.shutdown().await;
                    return;
                }
            }
            Expectation::None | Expectation::Continue => {}
        }
        let method = parsed.request.method().clone();
        let mut force_close = parsed.close_after_response || !config.h1_keep_alive;
        let response = match Service::call(&mut service, parsed.request).await {
            Ok(response) => response,
            Err(_) => {
                close_socket(&io).await;
                return;
            }
        };
        let locked = io.lock().await;
        if !locked.body_complete() {
            force_close = true;
        }
        match write_response(locked, response, &method, force_close, transport_metrics.as_deref()).await {
            Ok(true) | Err(_) => {
                close_socket(&io).await;
                return;
            }
            Ok(false) => {}
        }
    }
    close_socket(&io).await;
}

async fn close_socket(io: &Arc<Mutex<ConnectionIo>>) {
    let mut locked = io.lock().await;
    let _result: io::Result<()> = locked.stream.shutdown().await;
}
