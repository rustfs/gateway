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

//! Responsible for: observing GOAWAY facts separately from measured TCP receive termination.
//! NOT responsible for: writing GOAWAY, retrying streams, or flow-control accounting.
//! Upstream: real loopback peer bytes; downstream: the authored HTTP/2 observer.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8 — GOAWAY can precede completion of in-flight streams.

use super::*;
use crate::observation::{ObservedH2ControlFrame, SocketReadState};

fn goaway(last: u32, code: u32) -> Vec<u8> {
    let mut bytes = hex("000008 07 00 00000000");
    bytes.extend(last.to_be_bytes());
    bytes.extend(code.to_be_bytes());
    bytes
}

fn run_peer(frames: Vec<u8>, stay_open: bool) -> Result<Observation, SutError> {
    let (release, held) = mpsc::channel();
    let (addr, peer) = peer(anonymous_wire_image().len(), move |stream| {
        stream.write_all(&frames).expect("peer frames written");
        if stay_open {
            let _ = held.recv_timeout(Duration::from_secs(3));
        }
    });
    let result = execute(addr, &anonymous_script(), Duration::from_millis(200));
    let _ = release.send(());
    peer.join().expect("peer completes");
    result
}

#[test]
fn goaway_alone_does_not_invent_eof_reset_or_reusability() {
    let seen = run_peer(goaway(0, 0), true).expect("GOAWAY observed");
    assert_eq!(seen.outcome, Outcome::Hang);
    assert_eq!(seen.status, None);
    assert_eq!(seen.stream_termination, None);
    assert_eq!(seen.socket_read_after, Some(SocketReadState::NoTerminationObserved));
    assert_eq!(seen.connection_after, None, "GOAWAY forbids new streams even while TCP stays open");
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 0,
            error_code: 0
        }])
    );
}

#[test]
fn an_in_flight_response_can_complete_after_goaway() {
    let mut frames = goaway(1, 0);
    frames.extend(hex("000001 01 05 00000001 88"));
    let seen = run_peer(frames, true).expect("in-flight response completes");
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.status, Some(200));
    assert_eq!(seen.socket_read_after, Some(SocketReadState::NoTerminationObserved));
    assert_eq!(seen.connection_after, None);
}

#[test]
fn eof_without_goaway_does_not_fabricate_an_announcement() {
    let seen = run_peer(Vec::new(), false).expect("actual EOF observed");
    assert_eq!(seen.socket_read_after, Some(SocketReadState::Eof));
    assert_eq!(seen.h2_control_frames, Some(Vec::new()));
    assert_ne!(seen.outcome, Outcome::StreamReset);
}

#[test]
fn goaway_then_eof_retains_the_frame_and_the_independent_eof() {
    let seen = run_peer(goaway(0, 0xffff_fffe), false).expect("frame and EOF observed");
    assert_eq!(seen.socket_read_after, Some(SocketReadState::Eof));
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 0,
            error_code: 0xffff_fffe
        }])
    );
    assert_ne!(seen.outcome, Outcome::StreamReset);
}

#[test]
fn multiple_goaways_and_resets_keep_arrival_order_and_numeric_fields() {
    let mut frames = goaway(0x7fff_ffff, 0);
    frames.extend(hex("000004 03 00 00000003 01020304"));
    frames.extend(goaway(1, 0xffff_fffe));
    frames.extend(hex("000004 03 00 00000001 00000008"));
    let seen = run_peer(frames, true).expect("ordered control frames observed");
    assert_eq!(seen.outcome, Outcome::StreamReset);
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![
            ObservedH2ControlFrame::GoAway {
                last_stream_id: 0x7fff_ffff,
                error_code: 0
            },
            ObservedH2ControlFrame::ResetStream {
                stream_id: 3,
                error_code: 0x01020304
            },
            ObservedH2ControlFrame::GoAway {
                last_stream_id: 1,
                error_code: 0xffff_fffe
            },
            ObservedH2ControlFrame::ResetStream {
                stream_id: 1,
                error_code: 8
            },
        ])
    );
}

#[test]
fn reserved_last_stream_bit_is_not_part_of_the_identifier() {
    let mut frames = goaway(0x8000_0001, 0);
    frames.extend(hex("000001 01 05 00000001 88"));
    let seen = run_peer(frames, true).expect("reserved bit ignored");
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 1,
            error_code: 0
        }])
    );
}

#[test]
fn short_goaway_payloads_are_refused() {
    for length in [0_u8, 3, 4, 7] {
        let mut bytes = vec![0, 0, length, 7, 0, 0, 0, 0, 0];
        bytes.extend(vec![0; usize::from(length)]);
        let error = run_peer(bytes, false).expect_err("GOAWAY needs two complete numeric fields");
        assert!(error.to_string().contains("GOAWAY"));
    }
}

#[test]
fn goaway_cannot_be_addressed_to_a_nonzero_stream() {
    let mut bytes = goaway(1, 0);
    bytes[8] = 1;
    let error = run_peer(bytes, false).expect_err("GOAWAY is connection scoped");
    assert!(error.to_string().contains("GOAWAY"));
}

#[test]
fn opaque_debug_data_is_neither_a_frame_nor_a_persisted_diagnostic() {
    for after_head in [false, true] {
        let mut frames = if after_head {
            hex("000001 01 04 00000001 88")
        } else {
            Vec::new()
        };
        let mut announcement = goaway(1, 0);
        let debug = b"private-debug-marker";
        announcement[2] += u8::try_from(debug.len()).expect("small fixture");
        announcement.extend(debug);
        frames.extend(announcement);
        frames.extend(if after_head {
            hex("000000 00 01 00000001")
        } else {
            hex("000001 01 05 00000001 88")
        });
        let seen = run_peer(frames, true).expect("opaque trailing debug bytes accepted");
        assert_eq!(
            seen.h2_control_frames,
            Some(vec![ObservedH2ControlFrame::GoAway {
                last_stream_id: 1,
                error_code: 0
            }])
        );
        assert!(seen.headers.is_empty(), "debug bytes are not HTTP response fields");
        assert!(!format!("{seen:?}").contains("private-debug-marker"));
    }
}
