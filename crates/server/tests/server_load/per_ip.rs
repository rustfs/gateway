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

//! Per-IP half-open admission under a ten-thousand-connection wave.
//!
//! Responsible for: rejection at the per-IP ceiling and another source IP's p99 while the wave is
//! present. NOT responsible for: TLS handshakes or timeout recovery, covered by `tls_h2.rs`.
//! Upstream: rustfs/backlog#1699. Downstream: the server capacity contract.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99() {
    const TEST_NAME: &str = "per_ip::c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99";
    const ATTEMPTS: usize = 10_000;
    const HALF_OPEN_LIMIT: usize = 256;
    const PROBES: usize = 500;
    const WARMUP_PROBES: usize = 20;
    const PROBE_CEILING: Duration = Duration::from_secs(5);
    if !run_isolated(TEST_NAME) {
        return;
    }

    let mut config = plaintext_config();
    config.bind_addr = "[::]:0".parse().expect("fixture address");
    config.dual_stack = true;
    config.header_read_timeout = Duration::from_secs(120);
    config.keep_alive_idle = Duration::from_secs(120);
    config.max_connections = ATTEMPTS + HALF_OPEN_LIMIT;
    config.max_connections_per_ip = Some(HALF_OPEN_LIMIT);
    if rustfs_gateway_server::Listener::bind(&config).is_err() {
        eprintln!("SKIP c-lim-0037: this host has no dual-stack loopback listener");
        return;
    }
    let (loaded_runtime, loaded) = server_on_own_runtime(config.clone(), Bytes::new());
    let (control_runtime, control) = server_on_own_runtime(config, Bytes::new());
    let loaded_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), loaded.local_addr.port());
    let loaded_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), loaded.local_addr.port());
    let control_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), control.local_addr.port());
    warm_up(control_v6, WARMUP_PROBES, PROBE_CEILING).await;
    warm_up(loaded_v6, WARMUP_PROBES, PROBE_CEILING).await;

    let attack_metrics = loaded.metrics.clone();
    let attack = tokio::spawn(async move {
        let mut sockets = Vec::with_capacity(HALF_OPEN_LIMIT);
        for _ in 0..HALF_OPEN_LIMIT {
            sockets.push(
                TcpStream::connect(loaded_v4)
                    .await
                    .expect("an attack connection reaches the listener"),
            );
        }
        while attack_metrics.active_connections() != HALF_OPEN_LIMIT {
            tokio::task::yield_now().await;
        }
        let mut rejected = 0;
        while rejected < ATTEMPTS - HALF_OPEN_LIMIT {
            let count = (ATTEMPTS - HALF_OPEN_LIMIT - rejected).min(HALF_OPEN_LIMIT);
            let mut overflow = Vec::with_capacity(count);
            for _ in 0..count {
                overflow.push(
                    TcpStream::connect(loaded_v4)
                        .await
                        .expect("an excess connection reaches the listener"),
                );
            }
            rejected += count;
            while attack_metrics.per_ip_rejections() != rejected {
                tokio::task::yield_now().await;
            }
        }
        sockets
    });
    let (control_probes, loaded_probes) = paired_probe_p99(control_v6, loaded_v6, PROBES, PROBE_CEILING).await;
    let sockets = tokio::time::timeout(Duration::from_secs(60), attack)
        .await
        .expect("the ten-thousand-connection wave completes")
        .expect("the attack task joins");
    tokio::time::timeout(Duration::from_secs(5), async {
        while loaded.metrics.per_ip_rejections() != ATTEMPTS - HALF_OPEN_LIMIT
            || loaded.metrics.active_connections() != HALF_OPEN_LIMIT
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the listener accounts for every attack connection");
    eprintln!(
        "c-lim-0037 admission: attempts={ATTEMPTS} active={} rejected={}",
        loaded.metrics.active_connections(),
        loaded.metrics.per_ip_rejections()
    );
    eprintln!(
        "c-lim-0037 p99: control={:?} stalled={} loaded={:?} stalled={}",
        control_probes.p99, control_probes.stalled, loaded_probes.p99, loaded_probes.stalled
    );

    if control_probes.stalled > 0 {
        eprintln!(
            "SKIP c-lim-0037 latency: the idle control stalled {} of {PROBES} probes",
            control_probes.stalled
        );
    } else {
        assert!(
            loaded_probes.stalled <= control_probes.stalled,
            "the other-IP probes do not stall behind the half-open wave"
        );
        let ceiling = control_probes.p99.saturating_mul(8) + Duration::from_millis(100);
        assert!(
            loaded_probes.p99 <= ceiling,
            "other-IP p99 {:?} exceeded the {:?} control-derived ceiling",
            loaded_probes.p99,
            ceiling
        );
    }

    drop(sockets);
    shut_down(control, control_runtime, "the control listener").await;
    shut_down(loaded, loaded_runtime, "the loaded listener").await;
}
