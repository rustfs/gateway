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

//! A healthy client's p99 beside a hundred slow clients that keep making progress.
//!
//! Responsible for: rustfs/backlog#1739 a-srv-0013 and rustfs/backlog#1766 a-pf-0016 — a third of
//! the slow clients trickle a request head one byte a second, a third trickle a request body, and a
//! third read a large response one byte a second; the healthy client's p99 is measured in lock-step
//! against an identical listener that has none of them. NOT responsible for: deadlines that retire
//! stalled clients, which `c_lim_0061` owns, or wall-clock thresholds on a shared runner.
//! Upstream: `server_load.rs`. Downstream: the p99 ratio recorded on the backlog issues.
//!
//! Release builds only: the probes take tens of microseconds, and a debug build measures the
//! instrumentation. The `perf-evidence.yml` workflow runs it; the PR gate does not.

#[cfg(not(debug_assertions))]
mod release {
    use super::super::*;

    /// How many slow clients of each kind the loaded listener holds.
    const PER_KIND: usize = 34;
    /// Paired probe rounds. At two thousand samples the 99th percentile is the twentieth-worst, which
    /// a lone scheduler hiccup cannot decide.
    const PROBES: usize = 2_000;
    const WARMUP_PROBES: usize = 200;
    const PROBE_CEILING: Duration = Duration::from_secs(5);
    /// Independent lock-step rounds; the median round's ratio is the one reported and gated, so one
    /// round that met a noisy neighbour neither passes nor fails the case on its own.
    const ROUNDS: usize = 5;
    /// The acceptance target: a healthy p99 no more than 20% above the control's. Printed, not
    /// asserted — a shared runner cannot hold a 20% wall-clock bound still.
    const TARGET_RATIO: f64 = 1.20;
    /// The blocking regression gate on the median ratio. Starvation — slow clients holding workers or
    /// buffers the healthy client needs — multiplies latency; host noise on paired rounds does not.
    const REGRESSION_RATIO: f64 = 2.0;

    fn slow_client_config() -> ServerConfig {
        let mut config = plaintext_config();
        config.header_read_timeout = Duration::from_secs(120);
        config.keep_alive_idle = Duration::from_secs(120);
        config.write_progress_timeout = Duration::from_secs(120);
        config.max_connections_per_ip = None;
        config.so_sndbuf = Some(4 * 1024);
        config
    }

    /// Answers `/healthy` at once, drains `/upload` before answering, and gives anything else a body
    /// larger than a loopback socket buffer.
    fn listener(config: ServerConfig) -> (tokio::runtime::Runtime, RunningServer) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a dedicated runtime is available");
        let guard = runtime.enter();
        let large = Bytes::from(vec![b'x'; 8 * 1024 * 1024]);
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let large = large.clone();
            async move {
                let body = match request.uri().path() {
                    "/healthy" => Bytes::from_static(b"ok"),
                    "/upload" => {
                        let _ = http_body_util::BodyExt::collect(request.into_body()).await;
                        Bytes::from_static(b"stored")
                    }
                    _ => large,
                };
                Ok::<_, Infallible>(Response::new(Full::new(body)))
            }
        });
        let server = Server::new(config, service).serve().expect("server starts");
        drop(guard);
        (runtime, server)
    }

    /// One slow client and what it does once a second.
    enum Slow {
        /// Writes one more byte of a request head that never ends.
        Head(TcpStream),
        /// Writes one more byte of a declared one-mebibyte body.
        Body(TcpStream),
        /// Reads one more byte of an eight-mebibyte response.
        Reader(TcpStream),
    }

    async fn open_slow_clients(addr: SocketAddr) -> Vec<Slow> {
        let mut clients = Vec::with_capacity(3 * PER_KIND);
        for _ in 0..PER_KIND {
            let mut head = TcpStream::connect(addr).await.expect("a slow head client connects");
            head.write_all(b"GET /never HTTP/1.1\r\nHost: l")
                .await
                .expect("the first head bytes write");
            clients.push(Slow::Head(head));

            let mut body = TcpStream::connect(addr).await.expect("a slow body client connects");
            body.write_all(b"PUT /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048576\r\n\r\nx")
                .await
                .expect("the upload head writes");
            clients.push(Slow::Body(body));

            let mut reader = pinhole_connect(addr).await;
            reader
                .write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("the large request writes");
            clients.push(Slow::Reader(reader));
        }
        clients
    }

    /// Advances every slow client by one byte, once a second, until `stop` fires. Returns how many
    /// clients were still connected at the end, which the case requires to be all of them: a slow
    /// client that was disconnected is no longer load.
    async fn trickle(mut clients: Vec<Slow>, mut stop: tokio::sync::oneshot::Receiver<()>) -> usize {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        let mut byte = [0_u8; 1];
        loop {
            tokio::select! {
                _ = &mut stop => break,
                _ = ticker.tick() => {}
            }
            for client in &mut clients {
                let _ = match client {
                    Slow::Head(stream) => stream.write_all(b"o").await.map(|()| 1),
                    Slow::Body(stream) => stream.write_all(b"x").await.map(|()| 1),
                    Slow::Reader(stream) => stream.read(&mut byte).await,
                };
            }
        }
        let mut connected = 0;
        for client in &mut clients {
            let (Slow::Head(stream) | Slow::Body(stream) | Slow::Reader(stream)) = client;
            let open = match stream.try_read(&mut byte) {
                Ok(read) => read > 0,
                Err(error) => error.kind() == std::io::ErrorKind::WouldBlock,
            };
            connected += usize::from(open);
        }
        connected
    }

    /// a-srv-0013 / a-pf-0016. A hundred-odd slow clients that keep progressing cost a healthy client
    /// at most a bounded share of its p99, measured against a lock-step control listener.
    ///
    /// The assertion is a regression gate, not the acceptance target: the median of five paired rounds
    /// must stay under twice the control, which holds on a busy shared runner, while the same median
    /// is compared with the 20% target in the printed line and on the issue. A slow client disconnected during the run fails the case, since
    /// the measurement would then be of fewer slow clients than it claims.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_srv_0013_slow_clients_cost_a_healthy_client_little_p99() {
        const TEST_NAME: &str = "slow_clients::release::a_srv_0013_slow_clients_cost_a_healthy_client_little_p99";
        if !run_isolated(TEST_NAME).await {
            return;
        }
        let (loaded_runtime, loaded) = listener(slow_client_config());
        let (control_runtime, control) = listener(slow_client_config());
        warm_up(control.local_addr, WARMUP_PROBES, PROBE_CEILING).await;
        warm_up(loaded.local_addr, WARMUP_PROBES, PROBE_CEILING).await;

        let clients = open_slow_clients(loaded.local_addr).await;
        let slow = clients.len();
        tokio::time::timeout(Duration::from_secs(15), async {
            while loaded.metrics.active_connections() < slow {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("every slow client is admitted");
        let before = rss_bytes();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let trickler = tokio::spawn(trickle(clients, stopped));
        // Two ticks, so every slow client has made progress at least once before measuring starts.
        tokio::time::sleep(Duration::from_millis(2_100)).await;

        let mut rounds = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            rounds.push(paired_probe_p99(control.local_addr, loaded.local_addr, PROBES, PROBE_CEILING).await);
        }
        let after = rss_bytes();
        let _ = stop.send(());
        let connected = trickler.await.expect("the trickle task joins");
        let ratios: Vec<f64> = rounds
            .iter()
            .map(|(control, loaded)| loaded.p99.as_secs_f64() / control.p99.as_secs_f64().max(f64::MIN_POSITIVE))
            .collect();
        let listed = ratios.iter().map(|ratio| format!("{ratio:.3}")).collect::<Vec<_>>().join(",");
        let mut order: Vec<usize> = (0..ROUNDS).collect();
        order.sort_by(|left, right| ratios[*left].total_cmp(&ratios[*right]));
        let middle = order[ROUNDS / 2];
        let median = ratios[middle];
        let (control_p99, loaded_p99) = rounds[middle];
        let control_stalled: usize = rounds.iter().map(|(control, _)| control.stalled).sum();
        let loaded_stalled: usize = rounds.iter().map(|(_, loaded)| loaded.stalled).sum();
        let growth = before.zip(after).map(|(before, after)| after.saturating_sub(before));
        println!(
            "perf-evidence: a-srv-0013 slow_clients={slow} connected_after={connected} rounds={ROUNDS} probes_per_round={PROBES} ratios={listed} median_ratio={median:.3} target_ratio={TARGET_RATIO} within_target={} median_round_control_p99_us={} median_round_loaded_p99_us={} control_stalled={control_stalled} loaded_stalled={loaded_stalled} rss_growth_bytes={}",
            median <= TARGET_RATIO,
            control_p99.p99.as_micros(),
            loaded_p99.p99.as_micros(),
            growth.map_or_else(|| "unavailable".to_owned(), |growth| growth.to_string()),
        );
        assert_eq!(connected, slow, "slow clients were disconnected while they were still making progress");
        if control_stalled > 0 {
            eprintln!(
                "SKIP a-srv-0013 latency: {control_stalled} probes against the idle control went unanswered inside {PROBE_CEILING:?}; this host cannot hold a baseline still"
            );
        } else {
            assert_eq!(loaded_stalled, 0, "the loaded listener left healthy probes unanswered");
            assert!(
                median <= REGRESSION_RATIO,
                "the median healthy-p99 ratio beside {slow} slow clients was {median:.3} ({listed}), past the {REGRESSION_RATIO} regression gate"
            );
        }
        if let Some(growth) = growth {
            let budget = rustfs_gateway_server::conn_memory_budget(slow);
            assert!(
                growth <= budget,
                "{slow} slow clients grew the resident set by {growth} bytes, past {budget}"
            );
        }
        shut_down(control, control_runtime, "the control listener").await;
        shut_down(loaded, loaded_runtime, "the loaded listener").await;
    }
}
