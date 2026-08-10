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
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use rustfs_gateway_server::{PrefixDispatch, ServerConfig, TlsHandle, TlsMaterial, WriteStrategy, conn_memory_budget};
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
}

#[tokio::test]
async fn a_srv_0007_prefix_dispatch_routes_without_protocol_knowledge() {
    let route =
        service_fn(|_request: Request<()>| async { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"route")))) });
    let fallback = service_fn(|_request: Request<()>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"fallback"))))
    });
    let mut dispatch = PrefixDispatch::new(vec![("/x/", route)], fallback);

    let routed = dispatch
        .ready()
        .await
        .expect("infallible service")
        .call(Request::builder().uri("/x/y").body(()).expect("fixture request"))
        .await
        .expect("infallible service");
    assert_eq!(routed.into_body().into_inner(), Some(Bytes::from_static(b"route")));

    let fallback = dispatch
        .ready()
        .await
        .expect("infallible service")
        .call(Request::builder().uri("/z").body(()).expect("fixture request"))
        .await
        .expect("infallible service");
    assert_eq!(fallback.into_body().into_inner(), Some(Bytes::from_static(b"fallback")));
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
