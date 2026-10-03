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

//! Who the per-client connection ceiling counts, on a real dual-stack listener (rustfs/gateway#1210).
//!
//! Responsible for: an IPv4 client reported as an IPv4-mapped address being counted as itself,
//! apart from an IPv6 client that shares the mapped form's `/64`.
//! NOT responsible for: two addresses in one IPv6 `/64`, which a loopback host cannot originate;
//! `src/client_admission.rs`'s unit cases pin those.
//! Upstream: `crates/server/src/client_admission.rs`. Downstream: none.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rustfs_gateway_server::{Listener, RunningServer, ServerConfig, ServerMetrics};
use tokio::net::TcpStream;

use super::{echo_server, plaintext_config};

async fn until(metrics: &ServerMetrics, what: &str, condition: impl Fn(&ServerMetrics) -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition(metrics) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{what}: active {} per-IP rejections {}",
            metrics.active_connections(),
            metrics.per_ip_rejections()
        )
    });
}

/// Negative — at a ceiling of one, a second IPv4 loopback connection is refused while an IPv6
/// loopback connection is admitted. The IPv4 peers arrive as `::ffff:127.0.0.1`, whose `/64` is
/// `::`, the same as `::1`'s: counted by prefix as written, the IPv6 client would have been refused
/// for the IPv4 one's seat.
#[tokio::test]
async fn a_dual_stack_listener_counts_its_ipv4_and_ipv6_clients_apart() {
    let config = ServerConfig {
        bind_addr: "[::]:0".parse().expect("fixture address"),
        dual_stack: true,
        max_connections_per_ip: Some(1),
        header_read_timeout: Duration::from_secs(30),
        ..plaintext_config()
    };
    if Listener::bind(&config).is_err() {
        eprintln!(
            "SKIP a_dual_stack_listener_counts_its_ipv4_and_ipv6_clients_apart: this host has no dual-stack loopback listener"
        );
        return;
    }
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(config);
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_addr.port());
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), local_addr.port());
    let _first_v4 = TcpStream::connect(v4).await.expect("IPv4 connects");
    until(&metrics, "the IPv4 client is admitted", |metrics| metrics.active_connections() == 1).await;
    let _first_v6 = TcpStream::connect(v6).await.expect("IPv6 connects");
    until(&metrics, "the IPv6 client is admitted beside it", |metrics| {
        metrics.active_connections() == 2
    })
    .await;
    let _second_v4 = TcpStream::connect(v4).await.expect("the kernel completes the handshake");
    until(&metrics, "the second IPv4 connection is refused", |metrics| {
        metrics.per_ip_rejections() == 1
    })
    .await;
    assert_eq!(metrics.active_connections(), 2, "the refused connection holds no seat");
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}
