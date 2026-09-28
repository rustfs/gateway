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
//! Responsible for: scripts that open more than one stream on one connection — which stream is
//! observed, and how the other streams' frames are read without being mistaken for it.
//! NOT responsible for: judging a real server; the c-h2 corpus cases do that on production Hyper.
//! Upstream: `super::compile` and `super::execute`; downstream: the repository verification gate.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-4.3 — a receiver decompresses
//! every field block, even one on a stream it discards, because each block can change the shared
//! compression context.

use super::*;
use crate::observation::ObservedH2ControlFrame;

fn script(frames: &str) -> Script {
    compile(&read(&block(&format!("{HEAD}{frames}")))).expect("the script compiles")
}

fn request(stream_id: u32, flags: &str) -> String {
    format!(
        "[[h2_frames]]\ntype = \"headers\"\nstream_id = {stream_id}\nflags = [{flags}]\npayload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n"
    )
}

const ENDS: &str = "\"end_headers\", \"end_stream\"";

fn two_requests() -> Script {
    script(&format!("{}{}", request(1, ENDS), request(3, ENDS)))
}

fn written_length(script: &Script) -> usize {
    24 + script
        .envelopes
        .iter()
        .map(|envelope| FRAME_HEADER_LEN + envelope.payload.len())
        .sum::<usize>()
}

fn answered(script: &Script, frames: Vec<u8>) -> Result<Observation, SutError> {
    let (release, held) = mpsc::channel();
    let (addr, peer) = peer(written_length(script), move |stream| {
        stream.write_all(&frames).expect("peer frames written");
        let _ = held.recv_timeout(Duration::from_secs(3));
    });
    let observed = execute(addr, script, Duration::from_millis(500));
    let _ = release.send(());
    peer.join().expect("peer completes");
    observed
}

/// `:status` from the static table: 0x88 is 200, 0x89 is 204.
fn head(stream_id: u32, status: u8, end_stream: bool) -> Vec<u8> {
    let mut bytes = vec![0, 0, 1, HEADERS, END_HEADERS | if end_stream { END_STREAM } else { 0 }];
    bytes.extend(stream_id.to_be_bytes());
    bytes.push(status);
    bytes
}

fn data(stream_id: u32, payload: &[u8], end_stream: bool) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut bytes = vec![length[1], length[2], length[3], DATA, if end_stream { END_STREAM } else { 0 }];
    bytes.extend(stream_id.to_be_bytes());
    bytes.extend(payload);
    bytes
}

#[test]
fn the_last_stream_a_headers_frame_opens_is_the_observed_one() {
    assert_eq!(two_requests().stream_id, 3);
    let reversed = script(&format!("{}{}", request(3, ENDS), request(1, ENDS)));
    assert_eq!(reversed.stream_id, 1, "an ordering violation stays authorable");
    let interleaved = script(&format!(
        "{}{}[[h2_frames]]\ntype = \"data\"\nstream_id = 1\nflags = [\"end_stream\"]\n",
        request(1, "\"end_headers\""),
        request(3, ENDS)
    ));
    assert_eq!(interleaved.stream_id, 3);
}

/// Positive — the other stream's complete response is read and discarded; the observation is the
/// selected stream's, with a different status so the two cannot be confused.
#[test]
fn a_response_on_another_stream_is_read_but_not_observed() {
    let mut frames = head(1, 0x88, false);
    frames.extend(data(1, b"first", true));
    frames.extend(head(3, 0x89, true));
    let observed = answered(&two_requests(), frames).expect("both responses are read");
    assert_eq!(observed.outcome, Outcome::Response, "{observed:?}");
    assert_eq!(observed.status, Some(204));
    assert!(observed.body.is_empty(), "stream 1's body is not stream 3's: {observed:?}");
}

/// Negative — a response only on the other stream is not a response on the selected one.
#[test]
fn a_response_only_on_another_stream_is_not_the_observed_response() {
    let observed = answered(&two_requests(), head(1, 0x88, true)).expect("the silence is measured");
    assert_eq!(observed.outcome, Outcome::Hang, "{observed:?}");
    assert_eq!(observed.status, None);
}

/// Positive — the other stream's header block is decompressed, so a dynamic-table entry it inserts
/// is available to the selected stream's block.
#[test]
fn another_streams_header_block_updates_the_shared_dynamic_table() {
    // Stream 1: :status 200, then `x-a: b` as a literal with incremental indexing (dynamic index 62).
    let mut frames = vec![
        0,
        0,
        8,
        HEADERS,
        END_HEADERS | END_STREAM,
        0,
        0,
        0,
        1,
        0x88,
        0x40,
        3,
        b'x',
        b'-',
        b'a',
        1,
        b'b',
    ];
    // Stream 3: :status 204 and the dynamic entry by index.
    frames.extend([0, 0, 2, HEADERS, END_HEADERS | END_STREAM, 0, 0, 0, 3, 0x89, 0xbe]);
    let observed = answered(&two_requests(), frames).expect("both blocks decode");
    assert_eq!(observed.status, Some(204), "{observed:?}");
    assert_eq!(observed.header("x-a"), Some("b"), "{observed:?}");
}

/// Negative — DATA on the other stream still spends connection credit: together with the selected
/// stream's DATA it cannot exceed the connection window the client granted.
#[test]
fn other_stream_data_spends_the_shared_connection_window() {
    let mut frames = head(1, 0x88, false);
    frames.extend(data(1, &vec![b'a'; 16_384], false));
    frames.extend(data(1, &vec![b'a'; 16_384], false));
    frames.extend(data(1, &vec![b'a'; 16_384], false));
    frames.extend(data(1, &vec![b'a'; 16_383], false));
    frames.extend(head(3, 0x88, false));
    frames.extend(data(3, b"x", true));
    let error = answered(&two_requests(), frames).expect_err("65,536 octets exceed the connection window");
    assert!(error.to_string().contains("exceeds received connection or stream credit"), "{error}");
}

/// Positive and negative — a WINDOW_UPDATE or RST_STREAM on another opened stream is recorded in
/// arrival order without ending the selected stream; one on a stream the script never opened is
/// still refused.
#[test]
fn controls_on_another_opened_stream_are_recorded() {
    let mut frames = hex("000004 08 00 00000001 00000010");
    frames.extend(hex("000004 03 00 00000001 00000008"));
    frames.extend(head(3, 0x88, true));
    let observed = answered(&two_requests(), frames).expect("recorded");
    assert_eq!(observed.outcome, Outcome::Response, "{observed:?}");
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![
            ObservedH2ControlFrame::WindowUpdate {
                stream_id: 1,
                increment: 16
            },
            ObservedH2ControlFrame::ResetStream {
                stream_id: 1,
                error_code: 8
            },
        ])
    );
    let error = answered(&two_requests(), hex("000004 08 00 00000005 00000010")).expect_err("stream 5 was never opened");
    assert!(error.to_string().contains("untracked stream"), "{error}");
}

/// Negative — another stream's header block may not interleave the selected stream's unfinished one.
#[test]
fn another_streams_frame_inside_an_unfinished_block_is_refused() {
    let mut frames = vec![0, 0, 1, HEADERS, 0, 0, 0, 0, 3, 0x88];
    frames.extend(head(1, 0x88, true));
    let error = answered(&two_requests(), frames).expect_err("refused");
    assert!(error.to_string().contains("inside an unfinished header block"), "{error}");
}

/// Negative — request progress counts only the selected stream: DATA authored on the other stream,
/// even with END_STREAM, is neither body progress nor the end of the observed request.
#[test]
fn another_streams_authored_data_is_not_the_selected_request_body() {
    let body = script(&format!(
        "{}{}[[h2_frames]]\ntype = \"data\"\nstream_id = 1\nflags = [\"end_stream\"]\npayload_hex = \"6869\"\n",
        request(1, "\"end_headers\""),
        request(3, "\"end_headers\"")
    ));
    let observed = answered(&body, head(3, 0x88, true)).expect("measured");
    assert_eq!(observed.request_body_bytes_sent_at_response, Some(0), "{observed:?}");
    assert_eq!(observed.request_body_fully_sent, Some(false), "stream 3 never ended its request");
}

/// Positive — request trailers on an earlier stream do not move the observation to it.
#[test]
fn trailers_on_an_earlier_stream_do_not_move_the_observation() {
    let trailers = script(&format!("{}{}{}", request(1, "\"end_headers\""), request(3, ENDS), request(1, ENDS)));
    assert_eq!(trailers.stream_id, 3);
    assert_eq!(trailers.opened, [1, 3]);
}

/// Positive — another stream's header block may continue in CONTINUATION frames on its own stream,
/// and it is still decompressed and discarded.
#[test]
fn another_streams_continued_block_is_read_and_discarded() {
    let mut frames = vec![0, 0, 1, HEADERS, END_STREAM, 0, 0, 0, 1, 0x88];
    frames.extend([0, 0, 0, CONTINUATION, END_HEADERS, 0, 0, 0, 1]);
    frames.extend(head(3, 0x89, true));
    let observed = answered(&two_requests(), frames).expect("both blocks are read");
    assert_eq!(observed.outcome, Outcome::Response, "{observed:?}");
    assert_eq!(observed.status, Some(204));
}

/// Negative — the other stream's unfinished block may not be interrupted by the selected stream.
#[test]
fn another_streams_unfinished_block_cannot_be_interleaved() {
    let mut frames = vec![0, 0, 1, HEADERS, END_STREAM, 0, 0, 0, 1, 0x88];
    frames.extend(head(3, 0x89, true));
    let error = answered(&two_requests(), frames).expect_err("refused");
    assert!(error.to_string().contains("inside an unfinished header block"), "{error}");
}

/// Positive — exactly the connection window, spent entirely by the other stream, is accepted.
#[test]
fn other_stream_data_up_to_the_connection_window_is_accepted() {
    let mut frames = head(1, 0x88, false);
    frames.extend(data(1, &vec![b'a'; 16_384], false));
    frames.extend(data(1, &vec![b'a'; 16_384], false));
    frames.extend(data(1, &vec![b'a'; 16_384], false));
    frames.extend(data(1, &vec![b'a'; 16_383], true));
    frames.extend(head(3, 0x89, true));
    let observed = answered(&two_requests(), frames).expect("65,535 octets fit the connection window");
    assert_eq!(observed.status, Some(204), "{observed:?}");
}

/// Negative — after an authored grant makes connection credit unknowable, another stream's DATA
/// is refused like the observed stream's rather than checked against a window nobody knows.
#[test]
fn other_stream_data_is_refused_after_an_invalid_authored_grant() {
    let overflow = script(&format!(
        "{}{}[[h2_frames]]\ntype = \"window_update\"\nstream_id = 0\nincrement = 2147483647\n",
        request(1, ENDS),
        request(3, ENDS)
    ));
    let mut frames = head(1, 0x88, false);
    frames.extend(data(1, b"a", true));
    let error = answered(&overflow, frames).expect_err("unknown credit");
    assert!(error.to_string().contains("unknown after an invalid authored grant"), "{error}");
}
