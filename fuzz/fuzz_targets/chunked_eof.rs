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

//! Responsible for: exercising every body truncation point against the typed EOF boundary.
//! NOT responsible for: parsing framing or assigning protocol meaning to trailers.
//! Upstream: libFuzzer. Downstream: `rustfs-gateway-stream::ByteStream` length enforcement.

#![no_main]

use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, StreamErrorKind, TrailingHeaders};

struct TruncatedStream {
    prefix: Option<Bytes>,
    declared: u64,
    ended: bool,
}

impl PayloadStream for TruncatedStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take()
            && !prefix.is_empty()
        {
            return Poll::Ready(Ok(PayloadRead::Chunk(prefix)));
        }
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        this.ended = true;
        Poll::Ready(Ok(PayloadRead::Eof {
            trailers: TrailingHeaders::empty(),
        }))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.declared)
    }
}

fuzz_target!(|input: &[u8]| {
    if input.is_empty() || input.len() > 4096 {
        return;
    }
    let body = Bytes::copy_from_slice(input);
    for cutoff in 0..body.len() {
        let inner: Pin<Box<dyn PayloadStream + Send>> = Box::pin(TruncatedStream {
            prefix: Some(body.slice(..cutoff)),
            declared: body.len() as u64,
            ended: false,
        });
        let mut stream = Box::pin(ByteStream::new(inner).expect("declared length is consistent"));
        let mut context = Context::from_waker(Waker::noop());

        loop {
            match stream.as_mut().poll_read(&mut context) {
                Poll::Ready(Ok(PayloadRead::Chunk(_))) => {}
                Poll::Ready(Ok(PayloadRead::Eof { .. })) => panic!("a truncated body reached EOF"),
                Poll::Ready(Err(error)) => {
                    assert!(matches!(error.kind(), StreamErrorKind::IncompleteBody));
                    break;
                }
                Poll::Pending => panic!("the deterministic fuzz producer cannot pend"),
            }
        }

        let terminal = stream.as_mut().poll_read(&mut context);
        assert!(matches!(
            terminal,
            Poll::Ready(Err(ref error)) if matches!(error.kind(), StreamErrorKind::PolledAfterEof)
        ));
    }
});
