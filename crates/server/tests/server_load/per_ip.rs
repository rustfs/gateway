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

async fn open_partial_headers(addr: SocketAddr, count: usize) -> Vec<TcpStream> {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..count {
        tasks.spawn(async move {
            let mut stream = TcpStream::connect(addr)
                .await
                .expect("a slow connection reaches the listener");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: x")
                .await
                .expect("the partial request head writes");
            stream
        });
    }
    let mut streams = Vec::with_capacity(count);
    while let Some(result) = tasks.join_next().await {
        streams.push(result.expect("the slow-connection task joins"));
    }
    streams
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c_wire_0061_slow_headers_expire_without_rss_or_healthy_p99_growth() {
    const TEST_NAME: &str = "per_ip::c_wire_0061_slow_headers_expire_without_rss_or_healthy_p99_growth";
    const SLOW_HEADERS: usize = 100;
    const PROBES: usize = 200;
    const PROBE_CEILING: Duration = Duration::from_secs(2);
    if !run_isolated(TEST_NAME) {
        return;
    }

    let mut slow_config = plaintext_config();
    slow_config.bind_addr = "[::]:0".parse().expect("fixture address");
    slow_config.dual_stack = true;
    slow_config.header_read_timeout = Duration::from_secs(3);
    slow_config.keep_alive_idle = Duration::from_secs(60);
    slow_config.max_connections = SLOW_HEADERS + PROBES;
    slow_config.max_connections_per_ip = None;
    if rustfs_gateway_server::Listener::bind(&slow_config).is_err() {
        eprintln!("SKIP c-wire-0061: this host has no dual-stack loopback listener");
        return;
    }
    let control_config = slow_config.clone();
    let (loaded_runtime, loaded) = server_on_own_runtime(slow_config, Bytes::new());
    let (control_runtime, control) = server_on_own_runtime(control_config, Bytes::new());
    let slow_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), loaded.local_addr.port());
    let healthy_loaded_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), loaded.local_addr.port());
    let healthy_control_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), control.local_addr.port());
    warm_up(healthy_control_v6, 20, PROBE_CEILING).await;
    warm_up(healthy_loaded_v6, 20, PROBE_CEILING).await;

    let before = rss_bytes();
    let mut slow = open_partial_headers(slow_v4, SLOW_HEADERS).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while loaded.metrics.active_connections() != SLOW_HEADERS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all slow headers are parked before the deadline");
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        for stream in &mut slow {
            stream.write_all(b"x").await.expect("one slow header byte writes");
        }
    }
    if let (Some(before), Some(parked)) = (before, rss_bytes()) {
        let growth = parked.saturating_sub(before);
        let budget = rustfs_gateway_server::conn_memory_budget(SLOW_HEADERS);
        assert!(growth <= budget + budget / 2, "slow-header RSS growth {growth} exceeded {budget}");
    } else {
        eprintln!("SKIP c-wire-0061 RSS: this runner cannot report RSS through ps");
    }

    let (control_probes, loaded_probes) = paired_probe_p99(healthy_control_v6, healthy_loaded_v6, PROBES, PROBE_CEILING).await;
    match control_probes.stalled {
        0 => {
            assert_eq!(loaded_probes.stalled, 0, "slow headers stalled healthy peers");
            let ceiling = control_probes.p99.saturating_mul(8) + Duration::from_millis(100);
            let within_ceiling = loaded_probes.p99 <= ceiling;
            assert!(
                within_ceiling,
                "healthy p99 {:?} exceeded the {:?} control-derived ceiling",
                loaded_probes.p99, ceiling
            );
        }
        stalled => eprintln!("SKIP c-wire-0061 latency: the idle control stalled {stalled} of {PROBES} probes"),
    }

    tokio::time::timeout(Duration::from_secs(4), async {
        for stream in &mut slow {
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.expect("the deadline close is observable"), 0);
        }
    })
    .await
    .expect("the absolute header deadline closes peers that keep making partial progress");
    tokio::time::timeout(Duration::from_secs(2), async {
        while loaded.metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every expired slow-header connection is retired from the active census");

    shut_down(control, control_runtime, "the control listener").await;
    shut_down(loaded, loaded_runtime, "the loaded listener").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c_wire_0064_one_thousand_half_open_connections_are_bounded_and_reused() {
    const TEST_NAME: &str = "per_ip::c_wire_0064_one_thousand_half_open_connections_are_bounded_and_reused";
    const ATTEMPTS: usize = 1_000;
    const PER_IP_LIMIT: usize = 64;
    const GLOBAL_LIMIT: usize = PER_IP_LIMIT * 2;
    if !run_isolated(TEST_NAME) {
        return;
    }

    let mut wave_config = plaintext_config();
    wave_config.bind_addr = "[::]:0".parse().expect("fixture address");
    wave_config.dual_stack = true;
    wave_config.header_read_timeout = Duration::from_secs(60);
    wave_config.keep_alive_idle = Duration::from_secs(60);
    wave_config.max_connections = GLOBAL_LIMIT;
    wave_config.max_connections_per_ip = Some(PER_IP_LIMIT);
    if rustfs_gateway_server::Listener::bind(&wave_config).is_err() {
        eprintln!("SKIP c-wire-0064: this host has no dual-stack loopback listener");
        return;
    }
    let (runtime, running) = server_on_own_runtime(wave_config, Bytes::new());
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), running.local_addr.port());
    let v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), running.local_addr.port());

    let v4_streams = open_partial_headers(v4, ATTEMPTS).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while running.metrics.per_ip_rejections() != ATTEMPTS - PER_IP_LIMIT
            || running.metrics.active_connections() != PER_IP_LIMIT
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the per-IP ceiling refuses every excess slow header");

    let mut v6_streams = open_partial_headers(v6, PER_IP_LIMIT).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while running.metrics.active_connections() != GLOBAL_LIMIT {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both source-IP allowances fill the global admission ceiling");
    let accepted_at_ceiling = running.metrics.accepted_connections();
    let mut queued = TcpStream::connect(v6)
        .await
        .expect("one connection reaches the listen backlog");
    queued
        .write_all(b"GET / HTTP/1.1\r\nHost: x")
        .await
        .expect("the queued partial head writes");
    let first_rss = rss_bytes();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        running.metrics.accepted_connections(),
        accepted_at_ceiling,
        "the accept loop must pause instead of accepting work behind a full admission gate"
    );
    assert_eq!(running.metrics.active_connections(), GLOBAL_LIMIT);
    if let (Some(first), Some(later)) = (first_rss, rss_bytes()) {
        let growth = later.saturating_sub(first);
        let ceiling = rustfs_gateway_server::conn_memory_budget(32);
        assert!(growth <= ceiling, "half-open RSS grew by {growth} bytes while the census was flat");
    } else {
        eprintln!("SKIP c-wire-0064 RSS: this runner cannot report RSS through ps");
    }

    v6_streams.pop();
    tokio::time::timeout(Duration::from_secs(2), async {
        while running.metrics.accepted_connections() == accepted_at_ceiling
            || running.metrics.active_connections() != GLOBAL_LIMIT
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("releasing one permit wakes the paused accept loop");
    assert_eq!(running.metrics.active_connections(), GLOBAL_LIMIT);

    drop(queued);
    drop(v6_streams);
    drop(v4_streams);
    shut_down(running, runtime, "the loaded listener").await;
}
