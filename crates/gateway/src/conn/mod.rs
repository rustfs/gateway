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

mod body_plan;
mod chunk;
mod metrics;
mod request;
mod response;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response};
use rustfs_gateway_server::{
    AcceptedConnection, ConnectionDriver, ConnectionError, ConnectionFuture, DriverValidationError, PlaintextTakeoverError,
    ServerConfig,
};
use rustfs_gateway_stream::Body;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tower::Service;

use crate::MAX_LINGER_DRAIN_BYTES;
use crate::close::ConnectionIntent;
pub use metrics::{ResponseFallbackReason, ResponseTransportMetrics};
pub use request::SelfHeldRequestBody;
use request::{ConnectionIo, ContinueWithdrawal, Expectation, HeaderTimeout, read_request};
use response::{write_bad_request, write_expectation_failed, write_response};

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
            HeaderTimeout::KeepAlive {
                idle: config.keep_alive_idle,
                header: config.header_read_timeout,
            }
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
            // Invited when the service first reads the body, not here (rustfs/gateway#1222).
            Expectation::Continue if parsed.body_expected => io.lock().await.owe_continue(),
            Expectation::None | Expectation::Continue => {}
        }
        let method = parsed.request.method().clone();
        let force_close = parsed.close_after_response || !config.h1_keep_alive;
        let mut request = parsed.request;
        request.extensions_mut().insert(crate::file_fallback::KernelFileTransfer);
        request.extensions_mut().insert(crate::unread_body::SelfHeldTransport);
        let response = match Service::call(&mut service, request).await {
            Ok(response) => response,
            Err(_) => {
                close_socket(&io).await;
                return;
            }
        };
        let locked = io.lock().await;
        if finish_exchange(
            locked,
            response,
            &method,
            force_close,
            config.lingering_close_time,
            transport_metrics.as_deref(),
        )
        .await
        {
            close_socket(&io).await;
            return;
        }
    }
    close_socket(&io).await;
}

/// Completes one service exchange on `locked`, returning `true` when the connection must close.
async fn finish_exchange(
    mut locked: tokio::sync::MutexGuard<'_, ConnectionIo>,
    response: Response<rustfs_gateway_server::ConnectionBody<rustfs_gateway_server::ConnectionResponseBody<Body>>>,
    method: &http::Method,
    mut force_close: bool,
    lingering_close_time: Duration,
    transport_metrics: Option<&ResponseTransportMetrics>,
) -> bool {
    let response_must_close = response
        .extensions()
        .get::<ConnectionIntent>()
        .copied()
        .is_some_and(ConnectionIntent::must_close);
    let response_needs_linger = needs_lingering_read(&response);
    // A peer never invited to send its body may be waiting for the invitation or may send it
    // anyway: neither is something to wait for, so the connection ends after the answer, as the
    // Hyper driver ends it. If a partial `100 Continue` already reached the wire without
    // finishing, writing a final status line after it would corrupt HTTP/1.1 framing, so abort
    // immediately without writing a response.
    match locked.withdraw_continue() {
        ContinueWithdrawal::None => {}
        ContinueWithdrawal::Withdrawn => force_close = true,
        ContinueWithdrawal::PartiallyWritten => return true,
    }
    if response_needs_linger {
        locked.stream.mark_request_body_unfinished();
    }
    if !locked.body_complete()
        && (force_close || response_must_close || !drain_owed_body(&mut locked, lingering_close_time).await)
    {
        force_close = true;
        locked.stream.mark_request_body_unfinished();
    }
    matches!(
        write_response(locked, response, method, force_close, transport_metrics).await,
        Ok(true) | Err(_)
    )
}

/// Reads and discards what a refused request still owes, so its connection can serve the next one.
///
/// Bounded twice: by [`MAX_LINGER_DRAIN_BYTES`] of body, and by `budget` of time — the same
/// patience `ServerConfig::lingering_close_time` gives a closing peer that still owes a body.
/// Without the second bound a peer that declared a body and stopped sending held its connection,
/// and the request permit of the response waiting behind this drain, for as long as it liked
/// (rustfs/gateway#1207). A drain that runs out of either answers `false`, and the caller closes
/// after the response instead. Hyper's driver never waits here at all: it discards what has
/// already arrived and closes otherwise.
async fn drain_owed_body(io: &mut ConnectionIo, budget: Duration) -> bool {
    matches!(
        tokio::time::timeout(budget, io.drain_request_body(MAX_LINGER_DRAIN_BYTES)).await,
        Ok(Ok(true))
    )
}

async fn close_socket(io: &Arc<Mutex<ConnectionIo>>) {
    let mut locked = io.lock().await;
    let _result: io::Result<()> = locked.stream.shutdown().await;
}

fn needs_lingering_read<B>(response: &Response<B>) -> bool {
    response
        .extensions()
        .get::<rustfs_gateway_server::UnfinishedRequestBody>()
        .is_some()
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test assertions deliberately panic on unexpected socket or server errors.
mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use http::{Method, Request, Response, StatusCode};
    use rustfs_gateway_server::{AcceptedConnection, ConnectionDriver, ConnectionFuture, Server, ServerConfig};
    use rustfs_gateway_stream::Body;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Mutex;
    use tower::Service;

    use super::{ConnectionIo, close_socket, finish_exchange, needs_lingering_read};

    #[test]
    fn an_unfinished_response_requests_a_lingering_read() {
        let mut response = http::Response::new(());
        response.extensions_mut().insert(rustfs_gateway_server::UnfinishedRequestBody);
        assert!(needs_lingering_read(&response));
    }

    #[test]
    fn an_unmarked_response_does_not_request_a_lingering_read() {
        assert!(!needs_lingering_read(&http::Response::new(())));
    }

    #[derive(Clone)]
    struct PartialContinueDriver {
        prewritten: &'static [u8],
    }

    #[derive(Clone)]
    struct RefusalService;

    impl Service<Request<()>> for RefusalService {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<()>) -> Self::Future {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from(bytes::Bytes::from_static(b"refused")))
                .expect("valid refusal");
            std::future::ready(Ok(response))
        }
    }

    impl ConnectionDriver<RefusalService> for PartialContinueDriver {
        fn drive(&self, accepted: AcceptedConnection<RefusalService>) -> ConnectionFuture {
            let prewritten = self.prewritten;
            Box::pin(async move {
                let Ok((stream, mut service)) = accepted.into_plaintext() else {
                    return;
                };
                let io = Arc::new(Mutex::new(ConnectionIo::new(stream)));
                {
                    let mut locked = io.lock().await;
                    if !prewritten.is_empty() {
                        locked.stream.write_all(prewritten).await.expect("partial continue writes");
                    }
                    locked.set_continue_written_for_test(prewritten.len());
                }
                let response = Service::call(&mut service, Request::new(()))
                    .await
                    .expect("refusal service succeeds");
                let locked = io.lock().await;
                let closed = finish_exchange(locked, response, &Method::PUT, false, Duration::from_millis(50), None).await;
                assert!(closed, "withdrawn or partially-written 100 Continue must close the socket");
                close_socket(&io).await;
            })
        }
    }

    /// Negative — when a partial `100 Continue` already reached the wire, `finish_exchange` must
    /// abort and close the socket without writing a final `HTTP/1.1 404` status line after it.
    #[tokio::test]
    async fn n_partial_continue_aborts_socket_without_writing_final_response() {
        let partial = b"HTTP/1.1 10";
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            ..ServerConfig::default()
        };
        let running = Server::new(config, RefusalService)
            .serve_with(PartialContinueDriver { prewritten: partial })
            .expect("server starts");
        let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut wire))
            .await
            .expect("socket closes promptly")
            .expect("wire reads");
        assert_eq!(
            wire,
            partial,
            "final HTTP/1.1 response must not be concatenated onto a partial 100 Continue: {:?}",
            String::from_utf8_lossy(&wire)
        );
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }

    /// Positive control — when `100 Continue` was owed with zero bytes written, `finish_exchange`
    /// still writes the final refusal response cleanly and closes the socket.
    #[tokio::test]
    async fn unstarted_continue_still_writes_final_response_and_closes() {
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            ..ServerConfig::default()
        };
        let running = Server::new(config, RefusalService)
            .serve_with(PartialContinueDriver { prewritten: b"" })
            .expect("server starts");
        let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut wire))
            .await
            .expect("socket closes promptly")
            .expect("wire reads");
        let text = String::from_utf8_lossy(&wire);
        assert!(text.starts_with("HTTP/1.1 404"), "expected 404 refusal, got: {text:?}");
        assert!(!text.contains("100 Continue"), "unexpected 100 Continue: {text:?}");
        assert!(text.to_ascii_lowercase().contains("connection: close"), "{text:?}");
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }
}
