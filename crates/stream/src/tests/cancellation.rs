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

//! Cancellation is ownership: dropping an adapter drops its producer.
//!
//! Responsible for: proving no hidden task or producer survives a cancelled adapted body.
//! NOT responsible for: back-pressure or scheduling policy, which belongs to the driver.
//! Upstream: the pull-to-push adapter. Downstream: nothing.

use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use std::sync::Arc;

use crate::{AsyncPayloadRead, Payload, PayloadCaps, ReadProgress, StreamError, StreamMetrics};

struct DropReader {
    drops: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
}

impl Drop for DropReader {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncPayloadRead for DropReader {
    fn poll_fill(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        self.get_mut().polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

#[test]
fn dropping_an_adapter_drops_its_producer_exactly_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let payload = Payload::from_reader(DropReader {
        drops: Arc::clone(&drops),
        polls: Arc::clone(&polls),
    })
    .expect("the reader declares consistent capabilities");
    let (mut stream, _) = payload
        .try_into_stream(&StreamMetrics::new())
        .expect("a reader adapts to the push model");

    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(stream.as_mut().poll_read(&mut context), Poll::Pending));
    assert_eq!(polls.load(Ordering::SeqCst), 1, "the adapted reader was polled before cancellation");
    assert_eq!(drops.load(Ordering::SeqCst), 0, "the producer remains owned until cancellation");
    drop(stream);
    assert_eq!(drops.load(Ordering::SeqCst), 1, "cancellation drops the producer once");
}
