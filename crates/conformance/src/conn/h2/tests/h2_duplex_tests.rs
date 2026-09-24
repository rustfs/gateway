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

//! Responsible for: duplex credit ordering and early peer controls during unfinished literal writes.
//! NOT responsible for: TLS, multiple streams, automatic grants, or protocol pacing of authored DATA.
//! Upstream: bounded cleartext loopback peers; downstream: the HTTP/2 execution pump.

use super::*;

const BUDGET: Duration = Duration::from_secs(2);

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("bounded fixture").to_be_bytes();
    let mut bytes = length[1..].to_vec();
    bytes.extend([kind, flags]);
    bytes.extend(stream.to_be_bytes());
    bytes.extend(payload);
    bytes
}

fn grants(script: &mut Script, delay: u64) {
    for stream_id in [0, 1] {
        script.envelopes.push(Envelope {
            frame_type: WINDOW_UPDATE,
            flags: 0,
            stream_id,
            payload: 1_u32.to_be_bytes().to_vec(),
            delay_ms: if stream_id == 0 { delay } else { 0 },
        });
    }
}

fn listener() -> (SocketAddr, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("bounded accept");
    (listener.local_addr().expect("loopback endpoint"), listener)
}

fn accept(listener: TcpListener) -> TcpStream {
    let deadline = Instant::now() + BUDGET;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("blocking fixture socket");
                stream.set_read_timeout(Some(BUDGET)).expect("bounded fixture read");
                stream.set_write_timeout(Some(BUDGET)).expect("bounded fixture write");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            other => panic!("client did not connect within the fixture budget: {other:?}"),
        }
    }
}

fn response(total: usize, end: bool) -> Vec<u8> {
    let mut bytes = hex("000001 01 04 00000001 88");
    let payload = vec![b'x'; total];
    let mut sent = 0;
    for chunk in payload.chunks(16_384) {
        sent += chunk.len();
        bytes.extend(frame(DATA, if end && sent == total { END_STREAM } else { 0 }, 1, chunk));
    }
    bytes
}

fn pregrant_response(total: usize, initial_stream: Option<u32>) -> Result<Observation, SutError> {
    let mut script = anonymous_script();
    let mut prefix = anonymous_wire_image();
    if let Some(window) = initial_stream {
        script.envelopes[0].payload = [vec![0, 4], window.to_be_bytes().to_vec()].concat();
        prefix = PREFACE.to_vec();
        prefix.extend(hex(match window {
            1 => "000006 04 00 00000000 000400000001",
            65_536 => "000006 04 00 00000000 000400010000",
            _ => panic!("fixture has no independent SETTINGS wire image for this window"),
        }));
        prefix.extend(hex("000013 01 05 00000001"));
        prefix.extend(hex(ANONYMOUS_GET_ROOT_HPACK));
    }
    grants(&mut script, 50);
    let (addr, listener) = listener();
    let (written_tx, written_rx) = mpsc::channel();
    let peer = thread::spawn(move || {
        let mut stream = accept(listener);
        let mut actual = vec![0; prefix.len()];
        stream.read_exact(&mut actual).expect("request prefix arrives");
        assert_eq!(actual, prefix);
        stream
            .write_all(&response(total, true))
            .expect("DATA is sent before either grant");
        written_tx.send(()).expect("report actual completed response write");
        // Keep reading until client exit so baseline grants cannot fail merely because the peer closed.
        let mut remainder = Vec::new();
        stream
            .read_to_end(&mut remainder)
            .expect("client finishes or refuses the exchange");
        remainder
    });
    let result = execute_paced(addr, &script, BUDGET, &mut |delay| {
        written_rx
            .recv_timeout(BUDGET)
            .expect("the over-credit DATA precedes grant eligibility");
        thread::sleep(delay);
    });
    peer.join().expect("bounded peer completes");
    result
}

#[test]
fn a_late_stream_grant_cannot_legalize_already_received_data() {
    let error = pregrant_response(2, Some(1)).expect_err("the stream had only one byte of credit when DATA arrived");
    assert!(error.to_string().contains("flow-control DATA payload exceeds"), "{error}");
}

#[test]
fn a_late_connection_grant_cannot_legalize_already_received_data() {
    let error = pregrant_response(65_536, Some(65_536)).expect_err("connection credit was exhausted before either grant");
    assert!(error.to_string().contains("flow-control DATA payload exceeds"), "{error}");
}

#[test]
fn a_peer_waiting_for_both_delayed_grants_can_finish() {
    let mut script = anonymous_script();
    grants(&mut script, 50);
    let (addr, listener) = listener();
    let (written_tx, written_rx) = mpsc::channel();
    let peer = thread::spawn(move || {
        let mut stream = accept(listener);
        let prefix = anonymous_wire_image();
        let mut actual = vec![0; prefix.len()];
        stream.read_exact(&mut actual).expect("request prefix arrives");
        assert_eq!(actual, prefix);
        stream
            .write_all(&response(65_535, false))
            .expect("exact initial credit is written");
        written_tx.send(()).expect("initial credit write completed");
        let mut grants = [0; 26];
        stream.read_exact(&mut grants).expect("both authored grants arrive");
        assert_eq!(grants.as_slice(), hex("000004 08 00 00000000 00000001 000004 08 00 00000001 00000001"));
        stream
            .write_all(&frame(DATA, END_STREAM, 1, b"y"))
            .expect("one newly credited byte completes");
    });
    let result = execute_paced(addr, &script, BUDGET, &mut |delay| {
        written_rx
            .recv_timeout(BUDGET)
            .expect("initial credit was actually written before grants");
        thread::sleep(delay);
    });
    peer.join().expect("bounded peer completes");
    let seen = result.expect("credit arriving after initial DATA permits subsequent DATA");
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.body, [vec![b'x'; 65_535], vec![b'y']].concat());
}

fn undrained_request(reply: &str, expected_controls: Vec<ObservedH2ControlFrame>) {
    let reply = hex(reply);
    let mut script = anonymous_script();
    script.envelopes[1].flags = END_HEADERS;
    let mut prefix = anonymous_wire_image();
    // Independently spell HEADERS without END_STREAM; the original prefix ends in 19 HPACK bytes.
    let flags_index = prefix.len() - 19 - 9 + 4;
    prefix[flags_index] = END_HEADERS;
    let mut expected = prefix.clone();
    for index in 0..32 {
        let payload = vec![b'x'; 1_048_576];
        let flags = if index == 31 { END_STREAM } else { 0 };
        expected.extend(frame(DATA, flags, 1, &payload));
        script.envelopes.push(Envelope {
            frame_type: DATA,
            flags,
            stream_id: 1,
            payload,
            delay_ms: 0,
        });
    }
    let (addr, listener) = listener();
    let (finished_tx, finished_rx) = mpsc::channel();
    let peer = thread::spawn(move || {
        let mut stream = accept(listener);
        // Prove a nonzero payload prefix arrived before the reset, so a constant zero
        // request-progress observation cannot satisfy this control by winning a race.
        let mut actual = vec![0; prefix.len() + FRAME_HEADER_LEN + 17];
        stream
            .read_exact(&mut actual)
            .expect("request prefix and partial DATA arrive");
        assert_eq!(actual, expected[..actual.len()]);
        stream
            .write_all(&reply)
            .expect("actual early peer control frames are written");
        // Refuse to drain DATA until the observer has returned; socket closure is not the stimulus.
        if finished_rx.recv_timeout(Duration::from_secs(4)).is_err() {
            // Rescue the current blocking writer without turning a fixture timeout into peer evidence.
            stream
                .shutdown(std::net::Shutdown::Both)
                .expect("release a blocked client at the fixture deadline");
            return None;
        }
        stream
            .read_to_end(&mut actual)
            .expect("capture only the prefix actually transmitted before exit");
        assert!(actual.len() < expected.len(), "fixture did not leave an incomplete authored request");
        assert_eq!(actual, expected[..actual.len()], "partial transmission must still be byte-exact");
        let data_wire = actual.len() - prefix.len();
        Some((data_wire / (1_048_576 + 9)) * 1_048_576 + (data_wire % (1_048_576 + 9)).saturating_sub(9))
    });
    let result = execute(addr, &script, BUDGET);
    // A closed receiver means the fixture rescue fired; the real execution result is asserted first.
    let _ = finished_tx.send(());
    let sent_payload = peer.join().expect("bounded peer completes");
    let seen = result.expect("a blocked request write must not discard an actual early reset");
    let sent_payload = sent_payload.expect("the observer must return before the fixture rescue closes the socket");
    assert!(sent_payload >= 17, "the peer proved a nonzero DATA prefix arrived before resetting");
    assert_eq!(seen.outcome, Outcome::StreamReset);
    assert_eq!(seen.h2_control_frames, Some(expected_controls));
    assert_eq!(seen.request_body_fully_sent, Some(false));
    assert_eq!(
        seen.request_body_bytes_sent_at_response,
        Some(u64::try_from(sent_payload).expect("bounded captured payload"))
    );
}

#[test]
fn early_reset_is_observed_without_finishing_an_undrained_request() {
    undrained_request(
        "000004 03 00 00000001 00000008",
        vec![ObservedH2ControlFrame::ResetStream {
            stream_id: 1,
            error_code: 8,
        }],
    );
}

#[test]
fn early_goaway_does_not_hide_the_following_reset_during_an_undrained_request() {
    undrained_request(
        "000008 07 00 00000000 00000001 00000000 000004 03 00 00000001 00000008",
        vec![
            ObservedH2ControlFrame::GoAway {
                last_stream_id: 1,
                error_code: 0,
            },
            ObservedH2ControlFrame::ResetStream {
                stream_id: 1,
                error_code: 8,
            },
        ],
    );
}

fn completed_request(flags: u8, payload: &[u8]) -> Observation {
    let mut script = anonymous_script();
    script.envelopes[1].flags = END_HEADERS;
    script.envelopes.push(Envelope {
        frame_type: DATA,
        flags: flags | END_STREAM,
        stream_id: 1,
        payload: payload.to_vec(),
        delay_ms: 0,
    });
    let mut expected = anonymous_wire_image();
    let flags_index = expected.len() - 19 - FRAME_HEADER_LEN + 4;
    expected[flags_index] = END_HEADERS;
    expected.extend(frame(DATA, flags | END_STREAM, 1, payload));
    let (addr, listener) = listener();
    let peer = thread::spawn(move || {
        let mut stream = accept(listener);
        let mut actual = vec![0; expected.len()];
        stream.read_exact(&mut actual).expect("the complete authored request arrives");
        assert_eq!(actual, expected, "progress does not rewrite padding or literal payload bytes");
        stream
            .write_all(&hex("000001 01 05 00000001 88"))
            .expect("response after complete request");
    });
    let seen = execute(addr, &script, BUDGET);
    peer.join().expect("bounded peer completes");
    seen.expect("the completed request receives its actual response")
}

#[test]
fn completed_literal_data_has_exact_nonzero_progress_and_a_true_completion_flag() {
    let seen = completed_request(0, b"abcd");
    assert_eq!(seen.status, Some(200));
    assert_eq!(seen.request_body_bytes_sent_at_response, Some(4));
    assert_eq!(seen.request_body_fully_sent, Some(true));
}

#[test]
fn padded_authored_data_cannot_fabricate_an_application_byte_counter() {
    for payload in [&[2, b'x', 0, 0][..], &[7, b'x'][..]] {
        let seen = completed_request(PADDED, payload);
        assert_eq!(seen.status, Some(200));
        assert_eq!(seen.request_body_bytes_sent_at_response, None);
        assert_eq!(seen.request_body_fully_sent, Some(true));
    }
}

#[test]
fn a_partial_data_frame_cannot_borrow_a_later_stream_grant() {
    let mut script = anonymous_script();
    script.envelopes[0].payload = hex("000400000001");
    script.envelopes.push(Envelope {
        frame_type: WINDOW_UPDATE,
        flags: 0,
        stream_id: 1,
        payload: 1_u32.to_be_bytes().to_vec(),
        delay_ms: 50,
    });
    let mut expected = PREFACE.to_vec();
    expected.extend(hex("000006 04 00 00000000 000400000001 000013 01 05 00000001"));
    expected.extend(hex(ANONYMOUS_GET_ROOT_HPACK));
    let (addr, listener) = listener();
    let (partial_tx, partial_rx) = mpsc::channel();
    let peer = thread::spawn(move || {
        let mut stream = accept(listener);
        let mut prefix = vec![0; expected.len()];
        stream
            .read_exact(&mut prefix)
            .expect("initial stream credit and request arrive");
        assert_eq!(prefix, expected);
        stream
            .write_all(&hex("000001 01 04 00000001 88 000002 00 01 00000001 78"))
            .expect("DATA header and first payload byte are actually sent");
        partial_tx.send(()).expect("report partial frame write");
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("bounded pre-remainder observation");
        let mut grant = [0; 13];
        let early = match stream.read(&mut grant) {
            Ok(count) => grant[..count].to_vec(),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Vec::new(),
            other => panic!("unexpected grant observation: {other:?}"),
        };
        stream
            .write_all(b"y")
            .expect("complete DATA only after observing whether a grant arrived");
        early
    });
    let result = execute_paced(addr, &script, BUDGET, &mut |delay| {
        partial_rx
            .recv_timeout(BUDGET)
            .expect("partial DATA precedes grant eligibility");
        thread::sleep(delay);
    });
    let early = peer.join().expect("bounded peer completes");
    let error = result.expect_err("an incomplete over-credit DATA frame cannot borrow the queued grant");
    assert!(error.to_string().contains("flow-control DATA payload exceeds"), "{error}");
    assert!(
        early.is_empty(),
        "the later grant preceded completion of the already received DATA frame: {early:?}"
    );
}

#[test]
fn measured_author_pacing_extends_the_deadline_by_only_its_actual_wait() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(1);
    let mut clock = ExchangeClock::until(deadline);
    clock.paced(|| std::thread::sleep(Duration::from_millis(2)));
    assert!(clock.harness_wait >= Duration::from_millis(2));
    assert_eq!(clock.deadline.duration_since(deadline), clock.harness_wait);
    assert!(clock.harness_wait <= started.elapsed());
}
