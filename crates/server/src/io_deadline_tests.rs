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

//! Every timer `ProgressIo` arms from configuration survives `Duration::MAX` (rustfs/gateway#1211).
//!
//! Responsible for: driving the idle, write-progress and lingering-close deadlines through the code
//! that rearms each one, with every configured duration at its maximum.
//! NOT responsible for: what those timers decide; the neighbouring `tests` module owns that.
//! Upstream: `ProgressIo`. Downstream: an in-memory duplex transport.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Duration;

use futures_util::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{FARTHEST_DEADLINE, ProgressIo, bounded, deadline_after};

/// Negative — a connection whose idle, write-progress and lingering-close durations are all
/// `Duration::MAX` writes, waits on a full transport, reads and closes. Before #1211 the first
/// rearm of each of those deadlines panicked the connection task.
#[tokio::test]
async fn every_progress_timer_rearms_at_duration_max() {
    // A one-octet duplex: the second write finds the transport full and waits for progress.
    let (transport, mut peer) = tokio::io::duplex(1);
    let mut io = ProgressIo::new(
        transport,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(true)),
        deadline_after(Duration::MAX),
        Duration::MAX,
        Duration::MAX,
        Duration::MAX,
    );
    // Written: the idle and write-progress deadlines are both rearmed.
    io.write_all(b"a").await.expect("the first octet fits");
    // Full: the write-progress wait begins.
    assert!(io.write(b"b").now_or_never().is_none(), "the second octet waits for the peer");
    let mut octet = [0_u8; 1];
    peer.read_exact(&mut octet).await.expect("the peer drains the first octet");
    assert_eq!(&octet, b"a");
    // Read after the first request was seen: the idle deadline is rearmed from the read side.
    peer.write_all(b"c").await.expect("the peer sends one octet");
    io.read_exact(&mut octet).await.expect("the octet arrives");
    assert_eq!(&octet, b"c");
    // Closing arms the lingering-close budget; the peer is gone, so the drain ends at once.
    drop(peer);
    io.shutdown().await.expect("the close completes");
}

/// Positive control — a duration inside the representable range is used as configured, so the
/// clamp cannot hide an ordinary timeout; only what lies past it is shortened.
#[test]
fn only_a_duration_past_the_farthest_deadline_is_clamped() {
    for configured in [Duration::ZERO, Duration::from_secs(65), FARTHEST_DEADLINE] {
        assert_eq!(bounded(configured), configured);
    }
    for configured in [FARTHEST_DEADLINE + Duration::from_nanos(1), Duration::MAX] {
        assert_eq!(bounded(configured), FARTHEST_DEADLINE);
    }
}
