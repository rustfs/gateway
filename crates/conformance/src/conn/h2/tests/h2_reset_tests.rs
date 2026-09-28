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

//! Received HTTP/2 control-frame facts from independent loopback peer bytes; initially RST_STREAM only.
//! Responsible for: separating stream resets, connection failures, and successful stream endings.
//! The list covers supported control types only; it never claims to capture all received frames.
//! NOT responsible for: GOAWAY, window accounting, or expanding supported request transports.
//! Upstream: the authored HTTP/2 transport; downstream: the conformance verification suite.

use super::*;
use crate::observation::ObservedH2ControlFrame;

fn reset(stream_id: u32, error_code: u32) -> Vec<u8> {
    let mut bytes = vec![0, 0, 4, 3, 0];
    bytes.extend_from_slice(&stream_id.to_be_bytes());
    bytes.extend_from_slice(&error_code.to_be_bytes());
    bytes
}

// The peer keeps TCP open until the observer returns; receiving RST_STREAM must not require EOF.
fn received_while_open(frames: Vec<u8>) -> Result<Observation, SutError> {
    let (release, held) = mpsc::channel();
    let (addr, peer) = peer(anonymous_wire_image().len(), move |stream| {
        stream.write_all(&frames).expect("peer frames written");
        let _ = held.recv_timeout(Duration::from_secs(3));
    });
    let observed = execute(addr, &anonymous_script(), Duration::from_secs(2));
    let _ = release.send(());
    peer.join().expect("peer completes");
    observed
}

#[test]
fn pre_header_reset_is_a_stream_reset_while_tcp_stays_open() {
    let observed = received_while_open(reset(1, 8)).expect("valid reset is measured");
    assert_eq!(observed.outcome, Outcome::StreamReset);
    assert_eq!(observed.status, None);
    assert_eq!(observed.stream_termination, None);
    assert_eq!(observed.http_version.as_deref(), Some("h2"));
    assert_eq!(observed.connection_after, Some(ConnectionState::Open));
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::ResetStream {
            stream_id: 1,
            error_code: 8
        }])
    );
    assert!(observed.events.is_empty(), "HTTP/2 reset is not an application event");
}

#[test]
fn post_header_reset_counts_unpadded_body_bytes_and_retains_the_response() {
    let mut frames = hex("000001 01 04 00000001 88");
    frames.extend(hex("000005 00 08 00000001 02 6869 0000"));
    frames.extend(reset(1, 2));
    let observed = received_while_open(frames).expect("response and reset are measured");
    assert_eq!(observed.outcome, Outcome::StreamError);
    assert_eq!(observed.stream_termination, Some(StreamTermination::Reset));
    assert_eq!(observed.status, Some(200));
    assert_eq!(observed.body, b"hi");
    assert_eq!(observed.body_bytes_before_error, Some(2));
    assert_eq!(observed.connection_after, Some(ConnectionState::Open));
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::ResetStream {
            stream_id: 1,
            error_code: 2
        }])
    );
}

#[test]
fn a_reset_on_another_stream_does_not_end_the_selected_response() {
    let mut frames = reset(3, 7);
    frames.extend(hex("000001 01 05 00000001 88"));
    let observed = received_while_open(frames).expect("selected stream completes");
    assert_eq!(observed.outcome, Outcome::Response);
    assert_eq!(observed.status, Some(200));
    assert_eq!(observed.stream_termination, None);
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::ResetStream {
            stream_id: 3,
            error_code: 7
        }])
    );
}

#[test]
fn reset_stream_ids_unknown_error_codes_and_arrival_order_are_not_normalized() {
    let mut frames = reset(3, 0xffff_fffe);
    frames.extend(reset(1, 0x1020_3040));
    let observed = received_while_open(frames).expect("numeric error codes are preserved");
    assert_eq!(observed.outcome, Outcome::StreamReset);
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![
            ObservedH2ControlFrame::ResetStream {
                stream_id: 3,
                error_code: 0xffff_fffe
            },
            ObservedH2ControlFrame::ResetStream {
                stream_id: 1,
                error_code: 0x1020_3040
            },
        ])
    );
}

#[test]
fn malformed_reset_payload_lengths_do_not_become_reset_facts() {
    for payload in [vec![], vec![0, 0, 8], vec![0, 0, 0, 8, 0]] {
        let mut frames = vec![0, 0, u8::try_from(payload.len()).expect("small fixture"), 3, 0, 0, 0, 0, 1];
        frames.extend(payload);
        let error = received_while_open(frames).expect_err("RST_STREAM requires exactly four payload octets");
        assert!(error.to_string().contains("RST_STREAM"), "{error}");
    }
}

#[test]
fn a_connection_level_reset_frame_is_not_a_stream_reset() {
    let error = received_while_open(reset(0, 8)).expect_err("RST_STREAM cannot target stream zero");
    assert!(error.to_string().contains("RST_STREAM"), "{error}");
}

#[test]
fn normal_end_stream_records_measured_absence_of_resets() {
    let observed = received_while_open(hex("000001 01 05 00000001 88")).expect("normal response");
    assert_eq!(observed.outcome, Outcome::Response);
    assert_eq!(observed.status, Some(200));
    assert_eq!(observed.h2_control_frames, Some(Vec::new()));
}

#[test]
fn eof_after_headers_is_not_a_received_reset_frame() {
    let (addr, peer) = peer(anonymous_wire_image().len(), |stream| {
        stream
            .write_all(&hex("000001 01 04 00000001 88"))
            .expect("response head written");
    });
    let observed = execute(addr, &anonymous_script(), Duration::from_secs(2)).expect("EOF measured");
    peer.join().expect("peer closes");
    assert_eq!(observed.outcome, Outcome::StreamError);
    assert_eq!(observed.stream_termination, Some(StreamTermination::AbruptClose));
    assert_eq!(observed.h2_control_frames, Some(Vec::new()));
}

// This is a classification control for an already measured socket reset, not a new TCP-RST probe.
#[test]
fn tcp_reset_without_headers_does_not_fabricate_an_http2_reset_frame() {
    let response = Response {
        cut_short: Some(ReadFailure::Reset),
        ..Response::default()
    };
    let observed = observe(response, 0, Duration::ZERO, Some(ConnectionState::Reset), 1).expect("socket reset classified");
    assert_eq!(observed.outcome, Outcome::ConnectionReset);
    assert_eq!(observed.connection_after, Some(ConnectionState::Reset));
    assert_eq!(observed.status, None);
    assert_eq!(observed.h2_control_frames, Some(Vec::new()));
}

#[test]
fn tcp_reset_after_headers_has_no_rst_stream_evidence() {
    let response = Response {
        status: Some(200),
        cut_short: Some(ReadFailure::Reset),
        ..Response::default()
    };
    let observed = observe(response, 0, Duration::ZERO, Some(ConnectionState::Reset), 1).expect("socket reset classified");
    assert_eq!(observed.outcome, Outcome::StreamError);
    assert_eq!(observed.stream_termination, Some(StreamTermination::Reset));
    assert_eq!(observed.connection_after, Some(ConnectionState::Reset));
    assert_eq!(observed.h2_control_frames, Some(Vec::new()));
}

/// Negative and measured — EOF after a head and three DATA octets is an abrupt close whose
/// received-byte count is the three octets that arrived, not an unavailable fact.
#[test]
fn eof_after_partial_data_reports_the_bytes_received_before_it() {
    let (addr, peer) = peer(anonymous_wire_image().len(), |stream| {
        stream
            .write_all(&hex("000001 01 04 00000001 88 000003 00 00 00000001 616263"))
            .expect("response head and partial body written");
    });
    let observed = execute(addr, &anonymous_script(), Duration::from_secs(2)).expect("EOF measured");
    peer.join().expect("peer closes");
    assert_eq!(observed.outcome, Outcome::StreamError);
    assert_eq!(observed.stream_termination, Some(StreamTermination::AbruptClose));
    assert_eq!(observed.body, b"abc");
    assert_eq!(observed.body_bytes_before_error, Some(3));
}
