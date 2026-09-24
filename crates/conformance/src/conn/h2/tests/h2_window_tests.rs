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

//! Responsible for: literal WINDOW_UPDATE scripts and measured two-scope receive credit.
//! NOT responsible for: silently pacing authored DATA, granting unrequested credit, or SDK framing.
//! Upstream: raw loopback peers and authored frames; downstream: HTTP/2 transport regression tests.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9 — stream and connection credit are independent.

use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("bounded fixture").to_be_bytes();
    let mut bytes = length[1..].to_vec();
    bytes.extend([kind, flags]);
    bytes.extend(stream.to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn update(stream: u32, increment: u32) -> Vec<u8> {
    frame(WINDOW_UPDATE, 0, stream, &increment.to_be_bytes())
}
fn window(stream: u32, increment: u32) -> Envelope {
    Envelope {
        frame_type: WINDOW_UPDATE,
        flags: 0,
        stream_id: stream,
        payload: increment.to_be_bytes().to_vec(),
        delay_ms: 0,
    }
}
fn bytes(script: &Script) -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    for envelope in &script.envelopes {
        bytes.extend(envelope.bytes());
    }
    bytes
}
fn response_data(total: usize, padded: bool, end: bool) -> Vec<u8> {
    let mut frames = hex("000001 01 04 00000001 88");
    let mut remaining = total;
    while remaining != 0 {
        let count = remaining.min(16_384);
        remaining -= count;
        let mut payload = vec![b'x'; count];
        let mut flags = if remaining == 0 && end { END_STREAM } else { 0 };
        if padded && remaining == 0 {
            assert!(count >= 2);
            flags |= PADDED;
            payload[0] = 1;
            payload[count - 1] = 0;
        }
        frames.extend(frame(DATA, flags, 1, &payload));
    }
    frames
}
fn exchange(script: Script, answer: Vec<u8>) -> Result<Observation, SutError> {
    let expected = bytes(&script);
    let (addr, peer) = peer(expected.len(), move |stream| {
        stream.write_all(&answer).expect("peer response");
    });
    let observed = execute(addr, &script, Duration::from_secs(2));
    assert!(
        peer.join().expect("peer completes") == expected,
        "the authored wire script must be byte-exact"
    );
    observed
}

#[test]
fn authored_window_updates_preserve_scope_increment_and_delay() {
    let request = block(&format!(
        "{HEAD}[[h2_frames]]\ntype='headers'\nstream_id=1\nflags=['end_headers','end_stream']\npayload_hex='{ANONYMOUS_GET_ROOT_HPACK}'\n[[h2_frames]]\ntype='window_update'\nstream_id=0\nincrement=17\ndelay_ms=37\n[[h2_frames]]\ntype='window_update'\nstream_id=1\nincrement=23\n"
    ));
    let script = compile(&read(&request)).expect("authored WINDOW_UPDATE is executable");
    assert_eq!(script.envelopes[1].bytes(), update(0, 17));
    assert_eq!(script.envelopes[1].delay_ms, 37);
    assert_eq!(script.envelopes[2].bytes(), update(1, 23));
    exchange(script, hex("000001 01 05 00000001 88")).expect("literal frames and response observed");
}

#[test]
fn zero_increment_remains_an_authored_protocol_violation_not_a_normalized_value() {
    let request = block(&format!(
        "{HEAD}[[h2_frames]]\ntype='headers'\nstream_id=1\nflags=['end_headers','end_stream']\npayload_hex='{ANONYMOUS_GET_ROOT_HPACK}'\n[[h2_frames]]\ntype='window_update'\nstream_id=0\nincrement=0\n"
    ));
    let script = compile(&read(&request)).expect("a representable malformed increment remains literal");
    assert_eq!(script.envelopes[1].bytes(), update(0, 0));
    let seen = exchange(script, hex("000008 07 00 00000000 00000000 00000001")).expect("peer rejection is observed");
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 0,
            error_code: 1
        }])
    );
}

#[test]
fn ambiguous_window_payload_and_increment_are_refused() {
    for payload in ["00000002", ""] {
        let error = compile_error(&format!(
            "{HEAD}[[h2_frames]]\ntype='headers'\nstream_id=1\npayload_hex='{ANONYMOUS_GET_ROOT_HPACK}'\n[[h2_frames]]\ntype='window_update'\nstream_id=0\nincrement=1\npayload_hex='{payload}'\n"
        ));
        assert!(error.contains("increment") && error.contains("payload_hex"), "{error}");
    }
}

#[test]
fn received_window_updates_keep_order_scope_and_reserved_bit_semantics() {
    let mut answer = update(0, 0x8000_0007);
    answer.extend(hex("000004 03 00 00000003 00000008"));
    answer.extend(update(1, 11));
    answer.extend(hex("000001 01 05 00000001 88"));
    let seen = exchange(anonymous_script(), answer).expect("window facts measured");
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![
            ObservedH2ControlFrame::WindowUpdate {
                stream_id: 0,
                increment: 7
            },
            ObservedH2ControlFrame::ResetStream {
                stream_id: 3,
                error_code: 8
            },
            ObservedH2ControlFrame::WindowUpdate {
                stream_id: 1,
                increment: 11
            },
        ])
    );
}

#[test]
fn zero_received_window_increments_are_refused_in_both_scopes() {
    for stream in [0, 1] {
        for increment in [0, 0x8000_0000] {
            let mut answer = update(stream, increment);
            answer.extend(hex("000001 01 05 00000001 88"));
            let error = exchange(anonymous_script(), answer).expect_err("zero credit is a protocol error");
            assert!(error.to_string().contains("WINDOW_UPDATE"), "{error}");
        }
    }
}

#[test]
fn window_update_payload_lengths_are_exact() {
    for length in [0, 3, 5] {
        let mut answer = frame(WINDOW_UPDATE, 0, 0, &vec![1; length]);
        answer.extend(hex("000001 01 05 00000001 88"));
        let error = exchange(anonymous_script(), answer).expect_err("WINDOW_UPDATE payload must have four octets");
        assert!(error.to_string().contains("WINDOW_UPDATE"), "{error}");
    }
}

#[test]
fn credit_overflow_is_refused_at_connection_and_stream_scope() {
    for stream in [0, 1] {
        let mut answer = update(stream, 0x7fff_ffff);
        answer.extend(hex("000001 01 05 00000001 88"));
        let error = exchange(anonymous_script(), answer).expect_err("initial credit plus update exceeds 31 bits");
        assert!(error.to_string().contains("flow-control"), "{error}");
    }
}

#[test]
fn exactly_the_initial_credit_can_complete_including_padding() {
    let seen = exchange(anonymous_script(), response_data(65_535, true, true)).expect("exact window can complete");
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.body.len(), 65_533, "payload padding is credit, not response body");
}

#[test]
fn connection_credit_cannot_substitute_for_stream_credit_even_on_end_stream() {
    let mut script = anonymous_script();
    script.envelopes.push(window(0, 1));
    let error = exchange(script, response_data(65_536, false, true)).expect_err("stream credit is exhausted");
    assert!(error.to_string().contains("flow-control"), "{error}");
}

#[test]
fn stream_credit_cannot_substitute_for_connection_credit_even_on_end_stream() {
    let mut script = anonymous_script();
    script.envelopes.push(window(1, 1));
    let error = exchange(script, response_data(65_536, false, true)).expect_err("connection credit is exhausted");
    assert!(error.to_string().contains("flow-control"), "{error}");
}

#[test]
fn actual_authored_updates_extend_both_receive_windows() {
    let mut script = anonymous_script();
    script.envelopes.extend([window(0, 1), window(1, 1)]);
    let seen = exchange(script, response_data(65_536, true, true)).expect("both actual grants replenish credit");
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.body.len(), 65_534);
}

#[test]
fn advertised_stream_window_debits_padding_before_accepting_end_stream() {
    let mut script = anonymous_script();
    script.envelopes[0].payload = hex("0004 00000001");
    let answer = hex("000001 01 04 00000001 88 000004 00 09 00000001 02 78 0000");
    let error = exchange(script, answer).expect_err("four payload bytes exceed stream credit one");
    assert!(error.to_string().contains("flow-control"), "{error}");
}

#[test]
fn exhausted_receive_credit_does_not_generate_unrequested_window_updates() {
    let script = anonymous_script();
    let expected = bytes(&script);
    let (addr, peer) = peer(expected.len(), |stream| {
        stream
            .write_all(&response_data(65_535, false, false))
            .expect("credit-sized response prefix");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bounded peer read");
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).expect("observer eventually closes"),
            0,
            "no unrequested WINDOW_UPDATE may be sent"
        );
    });
    let seen = execute(addr, &script, Duration::from_millis(200));
    assert!(peer.join().expect("peer exits") == expected);
    let seen = seen.expect("lack of authored credit is measured as a stalled response");
    assert_eq!(seen.outcome, Outcome::Hang);
    assert_eq!(seen.body.len(), 65_535);
}

#[test]
fn default_literal_data_can_exceed_peer_credit_and_receive_a_real_rejection() {
    let mut script = anonymous_script();
    script.envelopes[1].flags = END_HEADERS;
    for index in 0..4 {
        script.envelopes.push(Envelope {
            frame_type: DATA,
            flags: if index == 3 { END_STREAM } else { 0 },
            stream_id: 1,
            payload: vec![b'x'; 16_384],
            delay_ms: 0,
        });
    }
    let seen = exchange(script, hex("000008 07 00 00000000 00000001 00000003"))
        .expect("the malformed script reaches the peer unchanged");
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 1,
            error_code: 3
        }])
    );
    assert_eq!(seen.status, None);
}

#[test]
fn a_peer_withholds_more_data_until_both_authored_grants_arrive() {
    for first_scope in [0, 1] {
        let mut script = anonymous_script();
        let prefix = bytes(&script);
        let mut first = window(first_scope, 1);
        first.delay_ms = 80;
        let mut second = window(1 - first_scope, 1);
        second.delay_ms = 80;
        script.envelopes.extend([first, second]);
        let (addr, peer) = peer(prefix.len(), move |stream| {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("bounded credit wait");
            stream
                .write_all(&response_data(65_535, false, false))
                .expect("initial credit only");
            let mut received = [0; 13];
            stream.read_exact(&mut received).expect("first authored grant");
            assert_eq!(received.as_slice(), update(first_scope, 1));
            // No next DATA is written while only one scope has credit; the second read is real.
            stream.read_exact(&mut received).expect("second authored grant");
            assert_eq!(received.as_slice(), update(1 - first_scope, 1));
            stream
                .write_all(&frame(DATA, END_STREAM, 1, b"y"))
                .expect("both credits now permit one DATA byte");
        });
        let observed = execute(addr, &script, Duration::from_secs(2));
        assert!(peer.join().expect("peer finishes") == prefix);
        let observed = observed.expect("flow resumes after actual credit grants");
        assert_eq!(observed.outcome, Outcome::Response);
        assert_eq!(observed.body.len(), 65_536);
        assert_eq!(observed.body.last(), Some(&b'y'));
    }
}

#[test]
fn an_explicit_raw_window_payload_keeps_its_malformed_length() {
    let request = block(&format!(
        "{HEAD}[[h2_frames]]\ntype='headers'\nstream_id=1\nflags=['end_headers','end_stream']\npayload_hex='{ANONYMOUS_GET_ROOT_HPACK}'\n[[h2_frames]]\ntype='window_update'\nstream_id=0\npayload_hex='000001'\n"
    ));
    let script = compile(&read(&request)).expect("raw payload without increment remains literal");
    assert_eq!(script.envelopes[1].bytes(), frame(WINDOW_UPDATE, 0, 0, &[0, 0, 1]));
    let seen = exchange(script, hex("000008 07 00 00000000 00000000 00000006")).expect("peer frame-size rejection observed");
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 0,
            error_code: 6
        }])
    );
}
