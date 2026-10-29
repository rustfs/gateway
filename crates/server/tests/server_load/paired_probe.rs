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

//! Paired latency probes on a bounded pool of retained connections.
//!
//! Responsible for: collecting every complete response on a fresh connection and retaining it through
//! the census. NOT responsible for: deciding whether the slow-reader wave is present.
//! Upstream: server load tests; downstream: the test listeners.

use super::{ProbeSet, healthy_probe, p99};
use futures_util::StreamExt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn probe(address: SocketAddr, ceiling: Duration) -> (Option<TcpStream>, Duration, bool) {
    let started = Instant::now();
    let result = tokio::time::timeout(ceiling, async {
        let mut stream = TcpStream::connect(address).await.expect("fresh probe connects");
        stream
            .write_all(b"GET /healthy HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("probe request writes");
        let mut answer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.expect("probe response reads");
            assert_ne!(read, 0, "probe closed before its response completed");
            answer.extend_from_slice(&chunk[..read]);
            if let Some(head_end) = answer.windows(4).position(|window| window == b"\r\n\r\n") {
                let body_start = head_end + 4;
                if answer.len() >= body_start + 2 {
                    assert!(answer.starts_with(b"HTTP/1.1 200"), "probe must succeed");
                    assert_eq!(&answer[body_start..], b"ok", "probe must read exactly its response");
                    break;
                }
            }
        }
        stream
    })
    .await;
    match result {
        Ok(stream) => (Some(stream), started.elapsed(), false),
        Err(_) => (None, ceiling, true),
    }
}

pub(super) async fn paired(
    control: &[SocketAddr],
    loaded: &[SocketAddr],
    count: usize,
    ceiling: Duration,
) -> (ProbeSet, ProbeSet, Vec<TcpStream>) {
    assert!(!control.is_empty(), "the probe pool must not be empty");
    assert_eq!(control.len(), loaded.len(), "the paired pools must have equal size");
    assert_eq!(count, control.len(), "each sample needs its own retained connection");
    let mut control_samples = Vec::with_capacity(count);
    let mut loaded_samples = Vec::with_capacity(count);
    let mut control_stalls = 0;
    let mut loaded_stalls = 0;
    let mut retained = Vec::with_capacity(count * 2);
    let pairs = control
        .iter()
        .copied()
        .zip(loaded.iter().copied())
        .enumerate()
        .map(|(index, (control, loaded))| async move {
            if index % 2 == 0 {
                tokio::join!(probe(control, ceiling), probe(loaded, ceiling))
            } else {
                let (loaded, control) = tokio::join!(probe(loaded, ceiling), probe(control, ceiling));
                (control, loaded)
            }
        });
    for (control, loaded) in futures_util::stream::iter(pairs)
        .buffer_unordered(25)
        .collect::<Vec<_>>()
        .await
    {
        if let Some(stream) = control.0 {
            retained.push(stream);
        }
        if let Some(stream) = loaded.0 {
            retained.push(stream);
        }
        control_samples.push(control.1);
        control_stalls += usize::from(control.2);
        loaded_samples.push(loaded.1);
        loaded_stalls += usize::from(loaded.2);
    }
    (
        ProbeSet {
            p99: p99(control_samples),
            stalled: control_stalls,
        },
        ProbeSet {
            p99: p99(loaded_samples),
            stalled: loaded_stalls,
        },
        retained,
    )
}

/// Samples `control` and `loaded` in lock-step and returns a 99th percentile for each.
///
/// Lock-step is the point. The two probes of a round are issued microseconds apart, so a host
/// that stalls for a scheduler quantum stalls whichever of them it lands on, and over `count`
/// rounds that weather is charged to both listeners in equal measure; what survives the
/// comparison is the part only the parked readers can explain. A baseline measured *before* the
/// readers were parked cannot do that — several seconds of unrelated host activity sit between it
/// and the measurement it is the denominator of, and on a busy machine those seconds are the
/// larger term.
///
/// The order within a round alternates so that neither listener permanently owns the position
/// that follows an idle gap.
pub(super) async fn paired_probe_p99(
    control: SocketAddr,
    loaded: SocketAddr,
    count: usize,
    ceiling: Duration,
) -> (ProbeSet, ProbeSet) {
    let mut control_samples = Vec::with_capacity(count);
    let mut loaded_samples = Vec::with_capacity(count);
    let mut control_stalls = 0;
    let mut loaded_stalls = 0;
    for round in 0..count {
        let (control_sample, loaded_sample) = if round % 2 == 0 {
            let control_sample = healthy_probe(control, ceiling).await;
            (control_sample, healthy_probe(loaded, ceiling).await)
        } else {
            let loaded_sample = healthy_probe(loaded, ceiling).await;
            (healthy_probe(control, ceiling).await, loaded_sample)
        };
        control_samples.push(control_sample.0);
        control_stalls += usize::from(control_sample.1);
        loaded_samples.push(loaded_sample.0);
        loaded_stalls += usize::from(loaded_sample.1);
    }
    (
        ProbeSet {
            p99: p99(control_samples),
            stalled: control_stalls,
        },
        ProbeSet {
            p99: p99(loaded_samples),
            stalled: loaded_stalls,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::probe;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn fixture(answer: &'static [u8], delay: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("fixture binds");
        let address = listener.local_addr().expect("fixture address");
        tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.expect("fixture accepts");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = connection.read(&mut buffer).await.expect("fixture receives request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            tokio::time::sleep(delay).await;
            let _ = connection.write_all(answer).await;
        });
        address
    }

    #[tokio::test]
    async fn probe_accepts_only_complete_success_and_reports_timeout() {
        let good = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Duration::ZERO).await;
        assert!(!probe(good, Duration::from_secs(1)).await.2);
        let slow = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Duration::from_millis(100)).await;
        let (_, duration, stalled) = probe(slow, Duration::from_millis(5)).await;
        assert!(stalled);
        assert_eq!(duration, Duration::from_millis(5));
    }

    #[tokio::test]
    async fn probe_rejects_incomplete_bad_status_and_wrong_body() {
        for answer in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\no"[..],
            &b"HTTP/1.1 500 Broken\r\nContent-Length: 2\r\n\r\nok"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno"[..],
        ] {
            let address = fixture(answer, Duration::ZERO).await;
            let task = tokio::spawn(async move { probe(address, Duration::from_secs(1)).await });
            assert!(task.await.is_err(), "invalid responses must be rejected");
        }
    }
    #[tokio::test]
    async fn paired_refuses_missing_mismatched_and_incomplete_pools() {
        for mode in 0..3 {
            let task = tokio::spawn(async move {
                let mut control = Vec::new();
                let mut loaded = Vec::new();
                if mode != 0 {
                    control.push(fixture(b"", Duration::ZERO).await);
                }
                if mode == 2 {
                    loaded.push(fixture(b"", Duration::ZERO).await);
                }
                super::paired(&control, &loaded, 0, Duration::from_secs(1)).await
            });
            let panic = task.await.expect_err("invalid probe pools must be rejected").into_panic();
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("");
            let expected = [
                "the probe pool must not be empty",
                "the paired pools must have equal size",
                "each sample needs its own retained connection",
            ][mode];
            assert!(message.contains(expected), "mode {mode} failed for the wrong reason: {message}");
        }
    }
    #[tokio::test]
    async fn paired_counts_stalls_and_charges_the_ceiling_on_each_side() {
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let control = vec![
            fixture(answer, Duration::ZERO).await,
            fixture(answer, Duration::from_millis(100)).await,
        ];
        let loaded = vec![
            fixture(answer, Duration::from_millis(100)).await,
            fixture(answer, Duration::ZERO).await,
        ];
        let ceiling = Duration::from_millis(10);
        let (control, loaded, retained) = super::paired(&control, &loaded, 2, ceiling).await;
        assert_eq!(retained.len(), 2, "only completed probes keep their connections");
        assert_eq!(control.stalled, 1);
        assert_eq!(loaded.stalled, 1);
        assert_eq!(control.p99, ceiling);
        assert_eq!(loaded.p99, ceiling);
    }
}
