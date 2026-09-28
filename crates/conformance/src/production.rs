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

//! Production server assemblies used by the connection conformance target.
//!
//! Responsible for: starting the real server runtime with either its Hyper or self-held HTTP/1.1
//! driver and exposing request-body demand to the raw client pacer. NOT responsible for: request
//! construction, response observation or assertions. Upstream: `crate::conn`. Downstream:
//! `rustfs-gateway-server` and the two production connection drivers.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::{Request, Response};
use http_body::{Body as HttpBody, Frame, SizeHint};
use rustfs_gateway::{
    Body, ConnectionIntent, MAX_LINGER_DRAIN_BYTES, RunningServer, S3Service, SelfHeldHttp1Driver, Server, ServerConfig,
    TlsHandle, TlsMaterial, TowerService, connection_intent_of,
};

use crate::socket::Pacer;
use crate::sut::SutError;

type Pacers = Arc<Mutex<VecDeque<Arc<Pacer>>>>;

/// Which production connection driver owns the accepted socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionDriver {
    /// The default Hyper HTTP driver.
    Hyper,
    /// The gateway-owned plaintext HTTP/1.1 driver.
    SelfHeld,
}

/// One production listener and the runtime that drives it.
pub struct ProductionServer {
    runtime: tokio::runtime::Runtime,
    running: Option<RunningServer>,
    pacers: Pacers,
}

impl ProductionServer {
    /// Starts one production server on a kernel-selected loopback port.
    pub fn start(service: S3Service, driver: ProductionDriver) -> Result<Self, SutError> {
        Self::start_with(service, driver, None)
    }

    fn start_with(service: S3Service, driver: ProductionDriver, tls: Option<TlsHandle>) -> Result<Self, SutError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| SutError::Environment(format!("cannot build the production server runtime: {error}")))?;
        let pacers = Arc::new(Mutex::new(VecDeque::new()));
        let paced = PacedService {
            inner: service,
            pacers: Arc::clone(&pacers),
            drain_bounded_body: driver == ProductionDriver::Hyper,
        };
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: tls.is_none(),
            tcp_nodelay: true,
            ..ServerConfig::default()
        };
        let running = runtime
            .block_on(async move {
                let server = Server::new(config, paced);
                let server = match tls {
                    Some(tls) => server.with_tls(tls),
                    None => server,
                };
                match driver {
                    ProductionDriver::Hyper => server.serve(),
                    ProductionDriver::SelfHeld => server.serve_with(SelfHeldHttp1Driver),
                }
            })
            .map_err(|error| SutError::Environment(format!("cannot start the production server: {error}")))?;
        Ok(Self {
            runtime,
            running: Some(running),
            pacers,
        })
    }

    /// Starts one production Hyper server behind TLS with a throwaway certificate for
    /// `localhost`, advertising the server's default ALPN protocols. Returns the certificate so
    /// the client can trust exactly it.
    pub fn start_tls(service: S3Service) -> Result<(Self, rustls::pki_types::CertificateDer<'static>), SutError> {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()])
            .map_err(|error| SutError::Environment(format!("cannot mint the listener certificate: {error}")))?;
        let certificate = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let handle = TlsHandle::new(TlsMaterial::from_der(
            vec![certified.cert.der().to_vec()],
            certified.signing_key.serialize_der(),
        ))
        .map_err(|error| SutError::Environment(format!("cannot configure the TLS listener: {error}")))?;
        let server = Self::start_with(service, ProductionDriver::Hyper, Some(handle))?;
        Ok((server, certificate))
    }

    /// Kernel-selected listener address.
    pub fn addr(&self) -> Result<SocketAddr, SutError> {
        self.running
            .as_ref()
            .map(|running| running.local_addr)
            .ok_or_else(|| SutError::Environment("the production server is no longer running".to_owned()))
    }

    /// Associates the next request with its client-side pacing rendezvous.
    pub fn enqueue_pacer(&self, pacer: &Arc<Pacer>) {
        if let Ok(mut pacers) = self.pacers.lock() {
            pacers.push_back(Arc::clone(pacer));
        }
    }
}

impl Drop for ProductionServer {
    fn drop(&mut self) {
        let Some(running) = self.running.take() else { return };
        self.runtime.block_on(async move {
            let _ = running.shutdown.trigger(Duration::from_millis(100)).await;
            let _ = running.task.await;
        });
    }
}

#[derive(Clone)]
struct PacedService {
    inner: S3Service,
    pacers: Pacers,
    drain_bounded_body: bool,
}

impl<B> TowerService<Request<B>> for PacedService
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let pacer = self
            .pacers
            .lock()
            .ok()
            .and_then(|mut pacers| pacers.pop_front())
            .unwrap_or_else(|| Arc::new(Pacer::new()));
        let (parts, body) = request.into_parts();
        let content_length = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let state = Arc::new(Mutex::new(PacedBodyState { inner: Box::pin(body) }));
        let request = Request::from_parts(
            parts,
            PacedBody {
                state: Arc::clone(&state),
                pacer: Arc::clone(&pacer),
            },
        );
        let drain_bounded_body = self.drain_bounded_body;
        let future = TowerService::call(&mut self.inner, request);
        Box::pin(async move {
            let response = future.await?;
            pacer.server_answered();
            if drain_bounded_body
                && content_length.is_some_and(|length| length <= MAX_LINGER_DRAIN_BYTES)
                && !connection_intent_of(&response).is_some_and(ConnectionIntent::must_close)
            {
                drain_body(state).await;
            }
            Ok(response)
        })
    }
}

struct PacedBody<B> {
    state: Arc<Mutex<PacedBodyState<B>>>,
    pacer: Arc<Pacer>,
}

struct PacedBodyState<B> {
    inner: Pin<Box<B>>,
}

impl<B> HttpBody for PacedBody<B>
where
    B: HttpBody,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.pacer.server_wants_body();
        let Ok(mut state) = self.state.lock() else { return Poll::Ready(None) };
        let frame = state.inner.as_mut().poll_frame(context);
        if matches!(frame, Poll::Ready(None)) {
            self.pacer.server_ended_body();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.state.lock().map(|state| state.inner.is_end_stream()).unwrap_or(true)
    }

    fn size_hint(&self) -> SizeHint {
        self.state.lock().map(|state| state.inner.size_hint()).unwrap_or_default()
    }
}

async fn drain_body<B>(state: Arc<Mutex<PacedBodyState<B>>>)
where
    B: HttpBody,
{
    std::future::poll_fn(|context| {
        let Ok(mut state) = state.lock() else { return Poll::Ready(()) };
        loop {
            match state.inner.as_mut().poll_frame(context) {
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(_)) | None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;
}
