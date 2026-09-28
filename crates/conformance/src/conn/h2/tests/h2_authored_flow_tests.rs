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

//! Responsible for: literal authored flow violations followed by actual peer control frames.
//! NOT responsible for: validating the peer's protocol decision or normalizing authored frames.
//! Upstream: byte-exact loopback scripts; downstream: the HTTP/2 writer and receive observer.

use super::*;

fn authored(tail: &str) -> Script {
    compile(&read(&block(&format!(
        "{HEAD}[[h2_frames]]\ntype='settings'\n[[h2_frames]]\ntype='headers'\nstream_id=1\nflags=['end_headers','end_stream']\npayload_hex='{ANONYMOUS_GET_ROOT_HPACK}'\n{tail}"
    ))))
    .expect("a representable protocol violation must remain an authored script")
}

fn exchanged(tail: &str, tail_wire: &str, reply_wire: &str) -> Result<Observation, SutError> {
    let script = authored(tail);
    let mut expected = anonymous_wire_image();
    expected.extend(hex(tail_wire));
    let expected_len = expected.len();
    let reply = hex(reply_wire);
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("bounded accept");
    let addr = listener.local_addr().expect("loopback address");
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                other => panic!("client did not connect before the fixture deadline: {other:?}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking accepted socket");
        stream.set_read_timeout(Some(Duration::from_secs(2))).expect("bounded read");
        stream.set_write_timeout(Some(Duration::from_secs(2))).expect("bounded reply");
        let mut received = vec![0; expected_len];
        stream
            .read_exact(&mut received)
            .expect("every authored byte must reach the peer");
        let written = stream.write_all(&reply);
        (received, written)
    });
    let observed = execute(addr, &script, Duration::from_secs(2));
    let (received, written) = peer.join().expect("bounded peer completes");
    assert_eq!(received, expected, "malformed flow frames must be transmitted without normalization");
    if observed.is_ok() {
        written.expect("the peer's reply is written");
    }
    observed
}

fn measured(tail: &str, tail_wire: &str, reply_wire: &str) -> Observation {
    exchanged(tail, tail_wire, reply_wire)
        .expect("after writing a literal violation, observe the peer instead of refusing local accounting")
}

const CONNECTION_OVERFLOW: &str = "[[h2_frames]]\ntype='window_update'\nstream_id=0\nincrement=2147483647\n";
const CONNECTION_OVERFLOW_WIRE: &str = "000004 08 00 00000000 7fffffff";
const FLOW_GOAWAY: &str = "000008 07 00 00000000 00000001 00000003";

fn assert_flow_goaway(seen: &Observation) {
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::GoAway {
            last_stream_id: 1,
            error_code: 3,
        }])
    );
    assert_ne!(seen.outcome, Outcome::StreamReset, "GOAWAY is not a stream reset");
}

#[test]
fn authored_connection_window_overflow_retains_the_peer_goaway() {
    assert_flow_goaway(&measured(CONNECTION_OVERFLOW, CONNECTION_OVERFLOW_WIRE, FLOW_GOAWAY));
}

#[test]
fn authored_stream_window_overflow_retains_the_peer_reset() {
    let seen = measured(
        "[[h2_frames]]\ntype='window_update'\nstream_id=1\nincrement=2147483647\n",
        "000004 08 00 00000001 7fffffff",
        "000004 03 00 00000001 00000003",
    );
    assert_eq!(seen.outcome, Outcome::StreamReset);
    assert_eq!(
        seen.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::ResetStream {
            stream_id: 1,
            error_code: 3,
        }])
    );
}

#[test]
fn authored_initial_window_above_31_bits_retains_the_peer_goaway() {
    assert_flow_goaway(&measured(
        "[[h2_frames]]\ntype='settings'\npayload_hex='000480000000'\n",
        "000006 04 00 00000000 000480000000",
        FLOW_GOAWAY,
    ));
}

#[test]
fn authored_settings_induced_window_overflow_retains_the_peer_goaway() {
    assert_flow_goaway(&measured(
        "[[h2_frames]]\ntype='window_update'\nstream_id=1\nincrement=2147418112\n[[h2_frames]]\ntype='settings'\npayload_hex='000400010000'\n",
        "000004 08 00 00000001 7fff0000 000006 04 00 00000000 000400010000",
        FLOW_GOAWAY,
    ));
}

#[test]
fn authored_violation_cannot_fabricate_a_goaway_from_peer_eof() {
    let seen = measured(CONNECTION_OVERFLOW, CONNECTION_OVERFLOW_WIRE, "");
    assert_eq!(seen.h2_control_frames, Some(Vec::new()));
    assert_eq!(seen.socket_read_after, Some(SocketReadState::Eof));
    assert_ne!(seen.outcome, Outcome::StreamReset);
}

#[test]
fn legal_maximum_window_and_peer_response_remain_observable() {
    let seen = measured(
        "[[h2_frames]]\ntype='window_update'\nstream_id=0\nincrement=2147418112\n",
        "000004 08 00 00000000 7fff0000",
        "000001 01 05 00000001 88",
    );
    assert_eq!(seen.status, Some(200));
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.h2_control_frames, Some(Vec::new()));
}

#[test]
fn observing_literal_flow_violations_does_not_enable_multiple_streams() {
    let source = format!(
        "{HEAD}[[h2_frames]]\ntype='headers'\nstream_id=1\npayload_hex='{ANONYMOUS_GET_ROOT_HPACK}'\n[[h2_frames]]\ntype='data'\nstream_id=3\npayload_hex='78'\n"
    );
    // DATA on a stream no HEADERS opened is a literal idle-stream violation, not a second observed
    // stream: the observation stays on stream 1 and stream 3 is not read as an opened stream.
    let script = compile(&read(&block(&source))).expect("the literal violation compiles");
    assert_eq!(script.stream_id, 1);
    assert_eq!(script.opened, [1]);
}

#[test]
fn invalid_authored_credit_cannot_certify_peer_data_even_at_end_stream() {
    for (tail, tail_wire) in [
        (CONNECTION_OVERFLOW, CONNECTION_OVERFLOW_WIRE),
        (
            "[[h2_frames]]\ntype='settings'\npayload_hex='000480000000'\n",
            "000006 04 00 00000000 000480000000",
        ),
    ] {
        for data in ["000000 00 01 00000001", "000001 00 01 00000001 78"] {
            let reply = format!("000001 01 04 00000001 88 {data}");
            let error = exchanged(tail, tail_wire, &reply).expect_err("unknown receive credit cannot certify DATA");
            assert!(error.to_string().contains("unknown after an invalid authored grant"), "{error}");
        }
    }
}

#[test]
fn settings_stream_id_authored_nonzero_cannot_grant_receive_credit() {
    for stream in [1, 3, 2_147_483_647] {
        let tail = format!(
            "[[h2_frames]]\ntype='settings'\npayload_hex='000400000000'\n[[h2_frames]]\ntype='settings'\nstream_id={stream}\npayload_hex='00040000ffff'\n"
        );
        let wire = format!("000006 04 00 00000000 000400000000 000006 04 00 {stream:08x} 00040000ffff");
        let error = exchanged(&tail, &wire, "000001 01 04 00000001 88 000001 00 01 00000001 78")
            .expect_err("literal nonzero-stream SETTINGS cannot certify peer DATA credit");
        assert!(error.to_string().contains("flow-control"), "{error}");
    }
}

#[test]
fn settings_stream_id_authored_zero_grants_receive_credit() {
    let seen = measured(
        "[[h2_frames]]\ntype='settings'\npayload_hex='000400000000'\n[[h2_frames]]\ntype='settings'\nstream_id=0\npayload_hex='000400000001'\n",
        "000006 04 00 00000000 000400000000 000006 04 00 00000000 000400000001",
        "000001 01 04 00000001 88 000001 00 01 00000001 78",
    );
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.body, b"x");
}

fn peer_initial_window(stream_id: u32, value: u32) -> PeerFrame {
    let mut payload = vec![0, 4];
    payload.extend(value.to_be_bytes());
    PeerFrame {
        frame_type: SETTINGS,
        flags: 0,
        stream_id,
        payload,
    }
}

#[test]
fn settings_stream_id_received_nonzero_is_refused_without_granting_credit() {
    for stream in [1, 3, 2_147_483_647] {
        for ack in [false, true] {
            let script = anonymous_script();
            let mut receiver = Receiver::new(&script);
            let mut flow = flow::Flow::new(1);
            assert!(
                !receiver
                    .accept(peer_initial_window(0, 0), &script, &mut flow)
                    .expect("valid zero window")
            );
            let mut frame = peer_initial_window(stream, 1);
            if ack {
                frame.flags = ACK;
                frame.payload.clear();
            }
            let result = receiver.accept(frame, &script, &mut flow);
            assert!(result.is_err(), "nonzero peer SETTINGS stream {stream}, ACK={ack} must be refused");
            flow.received_update(1, MAX_STREAM_ID, false)
                .expect("refused SETTINGS must not alter the zero send window");
            assert!(
                flow.received_update(1, 1, false).is_err(),
                "the maximum remains a real bounded credit ledger"
            );
        }
    }
}

#[test]
fn settings_stream_id_received_zero_updates_actual_send_credit() {
    let script = anonymous_script();
    let mut receiver = Receiver::new(&script);
    let mut flow = flow::Flow::new(1);
    assert!(
        !receiver
            .accept(peer_initial_window(0, 0), &script, &mut flow)
            .expect("valid zero window")
    );
    assert!(
        !receiver
            .accept(peer_initial_window(0, 1), &script, &mut flow)
            .expect("valid one-byte grant")
    );
    flow.received_update(1, MAX_STREAM_ID - 1, false)
        .expect("the valid grant leaves exactly this much headroom");
    assert!(
        flow.received_update(1, 1, false).is_err(),
        "the valid SETTINGS grant must consume one byte of headroom"
    );
}

#[test]
fn settings_stream_id_received_zero_ack_preserves_send_credit() {
    let script = anonymous_script();
    let mut receiver = Receiver::new(&script);
    let mut flow = flow::Flow::new(1);
    assert!(
        !receiver
            .accept(peer_initial_window(0, 0), &script, &mut flow)
            .expect("valid zero window")
    );
    let ack = PeerFrame {
        frame_type: SETTINGS,
        flags: ACK,
        stream_id: 0,
        payload: Vec::new(),
    };
    assert!(!receiver.accept(ack, &script, &mut flow).expect("valid stream-zero ACK"));
    flow.received_update(1, MAX_STREAM_ID, false)
        .expect("ACK must leave the zero send window unchanged");
    assert!(
        flow.received_update(1, 1, false).is_err(),
        "the maximum remains a real bounded credit ledger"
    );
}

fn malformed_settings_payloads() -> [&'static str; 4] {
    ["000400000000ff", "ff", "0004000000", "0004000000000004000000"]
}

fn malformed_authored_settings_cannot_certify(data: &str) {
    for payload in malformed_settings_payloads() {
        let tail = format!("[[h2_frames]]\ntype='settings'\npayload_hex='{payload}'\n");
        let wire = format!("{:06x} 04 00 00000000 {payload}", payload.len() / 2);
        let reply = format!("000001 01 04 00000001 88 {data}");
        let error = exchanged(&tail, &wire, &reply).expect_err("malformed authored SETTINGS cannot establish peer DATA credit");
        assert!(error.to_string().contains("unknown after an invalid authored grant"), "{error}");
    }
}

#[test]
fn settings_length_authored_malformed_refuses_empty_end_stream_data() {
    malformed_authored_settings_cannot_certify("000000 00 01 00000001");
}

#[test]
fn settings_length_authored_malformed_refuses_nonempty_data() {
    malformed_authored_settings_cannot_certify("000001 00 01 00000001 78");
}

#[test]
fn settings_length_received_malformed_is_refused_before_changing_credit() {
    for payload in malformed_settings_payloads() {
        let script = anonymous_script();
        let mut receiver = Receiver::new(&script);
        let mut flow = flow::Flow::new(1);
        receiver
            .accept(peer_initial_window(0, 1), &script, &mut flow)
            .expect("valid one-byte window");
        let malformed = PeerFrame {
            frame_type: SETTINGS,
            flags: 0,
            stream_id: 0,
            payload: hex(payload),
        };
        assert!(
            receiver.accept(malformed, &script, &mut flow).is_err(),
            "malformed peer SETTINGS payload {payload} must be refused"
        );
        flow.received_update(1, MAX_STREAM_ID - 1, false)
            .expect("refused SETTINGS must preserve the one-byte window");
        assert!(
            flow.received_update(1, 1, false).is_err(),
            "malformed SETTINGS must not reduce existing credit"
        );
    }
}

#[test]
fn settings_length_empty_payload_preserves_valid_credit() {
    let seen = measured(
        "[[h2_frames]]\ntype='settings'\npayload_hex=''\n",
        "000000 04 00 00000000",
        "000001 01 04 00000001 88 000001 00 01 00000001 78",
    );
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.body, b"x");
    let script = anonymous_script();
    let mut receiver = Receiver::new(&script);
    let mut flow = flow::Flow::new(1);
    receiver
        .accept(peer_initial_window(0, 1), &script, &mut flow)
        .expect("valid one-byte window");
    let empty = PeerFrame {
        frame_type: SETTINGS,
        flags: 0,
        stream_id: 0,
        payload: Vec::new(),
    };
    assert!(!receiver.accept(empty, &script, &mut flow).expect("valid empty SETTINGS"));
    flow.received_update(1, MAX_STREAM_ID - 1, false)
        .expect("empty SETTINGS leaves the existing window unchanged");
    assert!(flow.received_update(1, 1, false).is_err(), "the existing window remains accounted for");
}

fn invalid_settings_ack_payloads() -> [&'static str; 4] {
    ["ff", "000400000000", "000400000002", "000100000001"]
}

#[test]
fn settings_ack_nonempty_payload_is_refused_without_changing_credit() {
    for payload in invalid_settings_ack_payloads() {
        let script = anonymous_script();
        let mut receiver = Receiver::new(&script);
        let mut flow = flow::Flow::new(1);
        receiver
            .accept(peer_initial_window(0, 1), &script, &mut flow)
            .expect("one-byte window");
        let frame = PeerFrame {
            frame_type: SETTINGS,
            flags: ACK,
            stream_id: 0,
            payload: hex(payload),
        };
        let error = receiver
            .accept(frame, &script, &mut flow)
            .expect_err("nonempty SETTINGS ACK must be refused");
        assert!(error.to_string().contains("SETTINGS ACK payload must be empty"), "{error}");
        flow.received_update(1, MAX_STREAM_ID - 1, false)
            .expect("rejected ACK must not raise stream credit");
        assert!(flow.received_update(1, 1, false).is_err(), "rejected ACK must not reduce stream credit");
    }
}

#[test]
fn settings_ack_nonempty_payload_cannot_precede_a_certified_wire_response() {
    for payload in invalid_settings_ack_payloads() {
        let reply = format!(
            "{:06x} 04 01 00000000 {payload} 000001 01 04 00000001 88 000001 00 01 00000001 78",
            payload.len() / 2
        );
        let error = exchanged("", "", &reply).expect_err("real peer malformed ACK must be refused before its response");
        assert!(error.to_string().contains("SETTINGS ACK payload must be empty"), "{error}");
    }
}

#[test]
fn settings_ack_empty_payload_preserves_credit_and_a_real_response() {
    let script = anonymous_script();
    let mut receiver = Receiver::new(&script);
    let mut flow = flow::Flow::new(1);
    receiver
        .accept(peer_initial_window(0, 1), &script, &mut flow)
        .expect("one-byte window");
    let frame = PeerFrame {
        frame_type: SETTINGS,
        flags: ACK,
        stream_id: 0,
        payload: Vec::new(),
    };
    assert!(!receiver.accept(frame, &script, &mut flow).expect("valid empty ACK"));
    flow.received_update(1, MAX_STREAM_ID - 1, false)
        .expect("empty ACK preserves existing credit");
    assert!(flow.received_update(1, 1, false).is_err(), "empty ACK preserves bounded credit");
    let seen = measured("", "", "000000 04 01 00000000 000001 01 04 00000001 88 000001 00 01 00000001 78");
    assert_eq!(seen.outcome, Outcome::Response);
    assert_eq!(seen.status, Some(200));
    assert_eq!(seen.body, b"x");
}

#[test]
fn settings_ack_authored_nonempty_payload_remains_literal() {
    for payload in ["ff", "000400000002"] {
        let tail = format!("[[h2_frames]]\ntype='settings'\nflags=['ack']\npayload_hex='{payload}'\n");
        let wire = format!("{:06x} 04 01 00000000 {payload}", payload.len() / 2);
        let seen = measured(&tail, &wire, "000001 01 05 00000001 88");
        assert_eq!(seen.outcome, Outcome::Response);
        assert_eq!(seen.status, Some(200));
    }
}
