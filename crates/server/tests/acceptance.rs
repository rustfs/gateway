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

//! P7-02 acceptance contracts that can be decided without a live socket.
//!
//! Responsible for: default security posture, tuning validation, dependency-neutral dispatch,
//! TLS fail-closed reload and the deterministic connection-memory budget.
//! NOT responsible for: the live socket timing cases in `server_runtime.rs`.
//! Upstream: rustfs/backlog#1739. Downstream: `rustfs-gateway-server`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::convert::Infallible;
use std::future::{Ready, ready as future_ready};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use rustfs_gateway_server::{
    ConfigError, PrefixDispatch, Server, ServerConfig, ServerError, TlsHandle, TlsMaterial, WriteStrategy, conn_memory_budget,
};
use tokio::sync::Semaphore;
use tower::{Service, ServiceExt, service_fn};

#[test]
fn connection_budget_is_linear_and_conservative() {
    assert_eq!(conn_memory_budget(0), 0);
    assert_eq!(conn_memory_budget(1_000), 408 * 1024 * 1_000);
}

#[test]
fn a_srv_0025_tls_is_required_unless_plaintext_is_explicit() {
    let config = ServerConfig::default();
    assert!(!config.plaintext);
    assert!(config.validate_transport(false).is_err());

    let mut explicit = config;
    explicit.plaintext = true;
    assert!(explicit.validate_transport(false).is_ok());
}

#[test]
fn a_srv_0024_tuning_defaults_are_bounded() {
    let config = ServerConfig::default();
    assert_eq!(config.header_read_timeout, Duration::from_secs(10));
    assert_eq!(config.write_progress_timeout, Duration::from_secs(30));
    assert_eq!(config.keep_alive_idle, Duration::from_secs(65));
    assert_eq!(config.connection_lifetime, None);
    assert_eq!(config.write_strategy, WriteStrategy::Auto);
    assert!(config.max_connections > 0);
    assert_eq!(config.max_connections_per_ip, Some(256));
}

#[test]
fn dependency_panic_bounds_are_rejected_with_boundary_controls() {
    let below_hyper_minimum = ServerConfig {
        h1_max_buf_size: 8_191,
        ..ServerConfig::default()
    };
    assert_eq!(below_hyper_minimum.validate(true), Err(ConfigError::Http1BufferSize(8_191)));
    let hyper_minimum = ServerConfig {
        h1_max_buf_size: 8_192,
        ..ServerConfig::default()
    };
    assert!(hyper_minimum.validate(true).is_ok());

    let above_semaphore_maximum = ServerConfig {
        max_connections: Semaphore::MAX_PERMITS + 1,
        ..ServerConfig::default()
    };
    assert_eq!(
        above_semaphore_maximum.validate(true),
        Err(ConfigError::MaxConnections {
            configured: Semaphore::MAX_PERMITS + 1,
            maximum: Semaphore::MAX_PERMITS,
        })
    );
    let semaphore_maximum = ServerConfig {
        max_connections: Semaphore::MAX_PERMITS,
        ..ServerConfig::default()
    };
    assert!(semaphore_maximum.validate(true).is_ok());
}

#[test]
fn h2_initial_windows_enforce_the_protocol_maximum() {
    let oversized_stream_window = ServerConfig {
        h2_initial_stream_window_size: u32::MAX,
        ..ServerConfig::default()
    };
    assert_eq!(
        oversized_stream_window.validate(true),
        Err(ConfigError::Http2WindowSize {
            field: "h2_initial_stream_window_size",
            configured: u32::MAX,
        })
    );

    let oversized_connection_window = ServerConfig {
        h2_initial_connection_window_size: u32::MAX,
        ..ServerConfig::default()
    };
    assert_eq!(
        oversized_connection_window.validate(true),
        Err(ConfigError::Http2WindowSize {
            field: "h2_initial_connection_window_size",
            configured: u32::MAX,
        })
    );

    let maximum = ServerConfig {
        h2_initial_stream_window_size: 2_147_483_647,
        h2_initial_connection_window_size: 2_147_483_647,
        ..ServerConfig::default()
    };
    assert!(maximum.validate(true).is_ok());
}

#[test]
fn zero_optional_intervals_and_stream_ceiling_are_rejected() {
    for (name, config) in [
        (
            "tcp_keepalive",
            ServerConfig {
                tcp_keepalive: Some(Duration::ZERO),
                ..ServerConfig::default()
            },
        ),
        (
            "h2_keep_alive_interval",
            ServerConfig {
                h2_keep_alive_interval: Some(Duration::ZERO),
                ..ServerConfig::default()
            },
        ),
        (
            "connection_lifetime",
            ServerConfig {
                connection_lifetime: Some(Duration::ZERO),
                ..ServerConfig::default()
            },
        ),
        (
            "h2_max_concurrent_streams",
            ServerConfig {
                h2_max_concurrent_streams: 0,
                ..ServerConfig::default()
            },
        ),
    ] {
        assert_eq!(config.validate(true), Err(ConfigError::Zero(name)));
    }

    let one_nanosecond = Duration::from_nanos(1);
    let config = ServerConfig {
        tcp_keepalive: Some(one_nanosecond),
        h2_keep_alive_interval: Some(one_nanosecond),
        connection_lifetime: Some(one_nanosecond),
        h2_max_concurrent_streams: 1,
        ..ServerConfig::default()
    };
    assert!(config.validate(true).is_ok());
}

#[tokio::test]
async fn serve_returns_a_typed_error_before_invalid_hyper_configuration_starts() {
    let config = ServerConfig {
        plaintext: true,
        h1_max_buf_size: 1,
        ..ServerConfig::default()
    };
    let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    });
    let result = Server::new(config, service).serve();
    assert!(matches!(result, Err(ServerError::Config(ConfigError::Http1BufferSize(1)))));

    let config = ServerConfig {
        plaintext: true,
        max_connections: Semaphore::MAX_PERMITS + 1,
        ..ServerConfig::default()
    };
    let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    });
    let result = Server::new(config, service).serve();
    assert!(matches!(
        result,
        Err(ServerError::Config(ConfigError::MaxConnections {
            configured,
            maximum,
        })) if configured == Semaphore::MAX_PERMITS + 1 && maximum == Semaphore::MAX_PERMITS
    ));
}

#[tokio::test]
async fn a_srv_0007_prefix_dispatch_routes_without_protocol_knowledge() {
    let blocked = ReadinessService::blocked();
    let route = ReadinessService::ready(b"route");
    let fallback = ReadinessService::ready(b"fallback");
    let mut dispatch = PrefixDispatch::new(vec![("/blocked/", blocked), ("/x/", route)], fallback);

    for (uri, expected) in [("/x/y", b"route".as_slice()), ("/z", b"fallback".as_slice())] {
        let response = tokio::time::timeout(Duration::from_secs(1), async {
            dispatch
                .ready()
                .await
                .expect("infallible service")
                .call(Request::builder().uri(uri).body(()).expect("fixture request"))
                .await
                .expect("infallible service")
        })
        .await
        .expect("an unrelated pending route must not block the selected service");
        assert_eq!(response.into_body().into_inner(), Some(Bytes::copy_from_slice(expected)));
    }
}

#[derive(Clone)]
struct ReadinessService {
    ready: bool,
    body: &'static [u8],
}

impl ReadinessService {
    fn blocked() -> Self {
        Self {
            ready: false,
            body: b"blocked",
        }
    }

    fn ready(body: &'static [u8]) -> Self {
        Self { ready: true, body }
    }
}

impl Service<Request<()>> for ReadinessService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.ready { Poll::Ready(Ok(())) } else { Poll::Pending }
    }

    fn call(&mut self, _request: Request<()>) -> Self::Future {
        assert!(self.ready, "the permanently pending route must never be called");
        future_ready(Ok(Response::new(Full::new(Bytes::from_static(self.body)))))
    }
}

#[test]
fn bad_tls_reload_preserves_the_previous_config_pointer() {
    let valid = test_material();
    let handle = TlsHandle::new(valid).expect("generated material is valid");
    let before = handle.current();
    let bad = TlsMaterial::from_der(Vec::new(), vec![1, 2, 3]);
    assert!(handle.reload(bad).is_err());
    let after = handle.current();
    assert!(std::sync::Arc::ptr_eq(&before, &after));
}

fn test_material() -> TlsMaterial {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("certificate generation succeeds");
    TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der())
}

#[allow(dead_code)]
fn service_is_a_tower_service<S>(service: &mut S, context: &mut Context<'_>) -> Poll<Result<(), S::Error>>
where
    S: Service<Request<()>>,
{
    service.poll_ready(context)
}
