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

//! Reverse-proxy admission controls: PROXY protocol v1/v2 and trusted-proxy per-IP exemption.
//!
//! Responsible for: proving untrusted peers cannot spoof PROXY headers or bypass per-IP ceilings,
//! trusted proxies fail closed on missing/malformed PROXY headers, attested client IPs drive both
//! per-IP admission and `ConnectionInfo::peer_addr()`, and `ExemptTrustedProxies` lifts the
//! per-IP ceiling only for allowlisted proxy peers.
//! NOT responsible for: PROXY wire-format edge cases (covered in `proxy_protocol.rs` unit tests).
//! Upstream: rustfs/gateway#1632. Downstream: the public server API.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use rustfs_gateway_server::{ConnectionInfo, IpCidr, ProxyPolicy, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tower::service_fn;

fn peer_echo_service(
    calls: Arc<AtomicUsize>,
) -> impl tower::Service<
    Request<hyper::body::Incoming>,
    Response = Response<Full<Bytes>>,
    Error = Infallible,
    Future = impl std::future::Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send,
> + Clone
+ Send
+ 'static {
    service_fn(move |request: Request<hyper::body::Incoming>| {
        let calls = Arc::clone(&calls);
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            let peer = request
                .extensions()
                .get::<ConnectionInfo>()
                .expect("server attaches ConnectionInfo")
                .peer_addr();
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(peer.to_string()))))
        }
    })
}

fn proxy_v2_tcp4(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
    out.push(0x21); // v2 + PROXY
    out.push(0x11); // AF_INET + STREAM
    out.extend_from_slice(&12_u16.to_be_bytes());
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out
}

/// Negative — an untrusted peer cannot spoof a PROXY protocol header or bypass `max_connections_per_ip`.
#[tokio::test]
async fn n_untrusted_peer_cannot_spoof_proxy_header_or_bypass_per_ip_limit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        max_connections_per_ip: Some(1),
        proxy_policy: ProxyPolicy::ProxyProtocol {
            trusted_proxies: vec![IpCidr::host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))],
        },
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = Server::new(config, peer_echo_service(Arc::clone(&calls)))
        .serve()
        .expect("server starts");

    // First loopback peer holds the single per-IP seat and attempts to spoof a PROXY v1 header.
    let mut spoof = TcpStream::connect(server.local_addr).await.expect("first connect");
    tokio::time::timeout(Duration::from_secs(1), async {
        while server.metrics.active_connections() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first connection admitted");

    // Second loopback connection must be rejected at per-IP admission before HTTP/PROXY parsing.
    let mut second = TcpStream::connect(server.local_addr).await.expect("second connect");
    let mut sink = [0_u8; 32];
    let _ = tokio::time::timeout(Duration::from_secs(1), second.read(&mut sink)).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while server.metrics.per_ip_rejections() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second connection from untrusted peer hits per-IP limit");
    assert_eq!(server.metrics.per_ip_rejections(), 1);

    // Sending a spoofed PROXY line from the untrusted peer must NOT be parsed as PROXY.
    spoof
        .write_all(
            b"PROXY TCP4 198.51.100.77 127.0.0.1 40000 80\r\nGET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("spoof payload writes");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), spoof.read_to_end(&mut response)).await;
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "untrusted peer's spoofed PROXY header must never reach the service"
    );

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Negative — a trusted proxy sending raw HTTP or a malformed PROXY header fails closed before the service.
#[tokio::test]
async fn n_trusted_proxy_missing_or_malformed_proxy_header_fails_closed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        proxy_policy: ProxyPolicy::ProxyProtocol {
            trusted_proxies: vec![IpCidr::host(IpAddr::V4(Ipv4Addr::LOCALHOST))],
        },
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = Server::new(config, peer_echo_service(Arc::clone(&calls)))
        .serve()
        .expect("server starts");

    for payload in [
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
        b"PROXY TCP4 999.999.999.999 127.0.0.1 1 80\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
    ] {
        let mut client = TcpStream::connect(server.local_addr).await.expect("connect");
        let _ = client.write_all(payload).await;
        let mut response = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response)).await;
        assert!(
            response.is_empty(),
            "missing or malformed PROXY header must close without an HTTP response, got: {:?}",
            String::from_utf8_lossy(&response)
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Negative + Positive — behind a trusted proxy with `max_connections_per_ip: Some(1)`, two
/// distinct attested client IPs (via PROXY v1 and v2) succeed simultaneously and expose their
/// attested `ConnectionInfo::peer_addr()`, while a duplicate attested client IP hits the per-IP ceiling.
#[tokio::test]
async fn n_trusted_proxy_attests_client_ip_for_per_ip_admission_and_connection_info() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let service = service_fn({
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        move |request: Request<hyper::body::Incoming>| {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                let peer = request
                    .extensions()
                    .get::<ConnectionInfo>()
                    .expect("ConnectionInfo present")
                    .peer_addr();
                if request.uri().path() == "/hold" {
                    entered.notify_one();
                    release.notified().await;
                }
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(peer.to_string()))))
            }
        }
    });
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        max_connections_per_ip: Some(1),
        proxy_policy: ProxyPolicy::ProxyProtocol {
            trusted_proxies: vec![IpCidr::host(IpAddr::V4(Ipv4Addr::LOCALHOST))],
        },
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = Server::new(config, service).serve().expect("server starts");

    // Client A (198.51.100.7) via PROXY v1 holds its single per-IP seat.
    let mut client_a1 = TcpStream::connect(server.local_addr).await.expect("connect A1");
    client_a1
        .write_all(
            b"PROXY TCP4 198.51.100.7 127.0.0.1 41001 80\r\nGET /hold HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write A1");
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("A1 enters handler");

    // Duplicate Client A (198.51.100.7) via PROXY v2 must be rejected by per-IP admission.
    let mut client_a2 = TcpStream::connect(server.local_addr).await.expect("connect A2");
    let mut a2_wire = proxy_v2_tcp4(Ipv4Addr::new(198, 51, 100, 7), 41002, Ipv4Addr::LOCALHOST, 80);
    a2_wire.extend_from_slice(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let _ = client_a2.write_all(&a2_wire).await;
    let mut a2_resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_a2.read_to_end(&mut a2_resp)).await;
    assert!(a2_resp.is_empty(), "duplicate attested client IP must be rejected before HTTP");
    tokio::time::timeout(Duration::from_secs(1), async {
        while server.metrics.per_ip_rejections() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("duplicate attested client IP increments per_ip_rejections");
    assert_eq!(server.metrics.per_ip_rejections(), 1);

    // Distinct Client B (198.51.100.8) via PROXY v2 succeeds even while Client A is held!
    let mut client_b = TcpStream::connect(server.local_addr).await.expect("connect B");
    let mut b_wire = proxy_v2_tcp4(Ipv4Addr::new(198, 51, 100, 8), 42002, Ipv4Addr::LOCALHOST, 80);
    b_wire.extend_from_slice(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    client_b.write_all(&b_wire).await.expect("write B");
    let mut b_resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client_b.read_to_end(&mut b_resp))
        .await
        .expect("B responds")
        .expect("B reads");
    let b_text = String::from_utf8_lossy(&b_resp);
    assert!(
        b_text.starts_with("HTTP/1.1 200") && b_text.ends_with("198.51.100.8:42002"),
        "expected attested PROXY v2 peer address, got: {b_text:?}"
    );

    // Release Client A and confirm its attested PROXY v1 address.
    release.notify_one();
    let mut a1_resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client_a1.read_to_end(&mut a1_resp))
        .await
        .expect("A1 responds")
        .expect("A1 reads");
    let a1_text = String::from_utf8_lossy(&a1_resp);
    assert!(
        a1_text.starts_with("HTTP/1.1 200") && a1_text.ends_with("198.51.100.7:41001"),
        "expected attested PROXY v1 peer address, got: {a1_text:?}"
    );

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Negative + Positive — `ExemptTrustedProxies` lifts `max_connections_per_ip` for allowlisted
/// proxies while keeping untrusted peers capped.
#[tokio::test]
async fn n_exempt_trusted_proxies_lifts_per_ip_limit_only_for_allowlisted_peers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let exempt_config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        max_connections_per_ip: Some(1),
        proxy_policy: ProxyPolicy::ExemptTrustedProxies {
            trusted_proxies: vec![IpCidr::host(IpAddr::V4(Ipv4Addr::LOCALHOST))],
        },
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let exempt_server = Server::new(exempt_config, peer_echo_service(Arc::clone(&calls)))
        .serve()
        .expect("exempt server starts");

    // Hold 3 simultaneous connections from the allowlisted proxy despite max_connections_per_ip == Some(1).
    let mut conns = Vec::new();
    for _ in 0..3 {
        let mut s = TcpStream::connect(exempt_server.local_addr).await.expect("connect");
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write");
        let mut buf = [0_u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
            .await
            .expect("response arrives")
            .expect("read succeeds");
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
        conns.push(s);
    }
    assert_eq!(exempt_server.metrics.per_ip_rejections(), 0);
    drop(conns);
    let _ = exempt_server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(exempt_server.task.await.expect("exempt server joins").is_ok());

    // Negative control: when loopback is NOT in the exempt list, the second connection is rejected.
    let capped_config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        max_connections_per_ip: Some(1),
        proxy_policy: ProxyPolicy::ExemptTrustedProxies {
            trusted_proxies: vec![IpCidr::host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))],
        },
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let capped_server = Server::new(capped_config, peer_echo_service(calls))
        .serve()
        .expect("capped server starts");
    let _held = TcpStream::connect(capped_server.local_addr).await.expect("first connect");
    tokio::time::timeout(Duration::from_secs(1), async {
        while capped_server.metrics.active_connections() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first connection admitted");
    let mut rejected = TcpStream::connect(capped_server.local_addr).await.expect("second connect");
    let mut sink = [0_u8; 16];
    let _ = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut sink)).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while capped_server.metrics.per_ip_rejections() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("untrusted peer hits per-IP cap");
    assert_eq!(capped_server.metrics.per_ip_rejections(), 1);
    drop(_held);
    let _ = capped_server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(capped_server.task.await.expect("capped server joins").is_ok());
}
