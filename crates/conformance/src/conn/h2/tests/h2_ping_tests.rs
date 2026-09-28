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
//! Responsible for: authored PING frames, received PING acknowledgements, and the reset barrier —
//! the acknowledgement of a PING written after a client RST_STREAM, which is the one wire fact
//! showing the peer processed that reset.
//! NOT responsible for: judging a real server; the c-h2 corpus cases do that on production Hyper.
//! Upstream: `super::compile` and `super::execute`; downstream: the repository verification gate.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-6.7 — a PING without ACK is
//! answered by a PING with ACK carrying the same eight octets, and an ACK is never answered.

use super::*;
use crate::observation::ObservedH2ControlFrame;

const OPAQUE: &str = "0102030405060708";

fn script(frames: &str) -> Script {
    compile(&read(&block(&format!("{HEAD}{frames}")))).expect("the script compiles")
}

fn headers() -> String {
    format!(
        "[[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\"]\npayload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n"
    )
}

fn frame(kind: &str, fields: &str) -> String {
    format!("[[h2_frames]]\ntype = \"{kind}\"\n{fields}")
}

fn reset_then_ping(opaque: &str) -> Script {
    script(&format!(
        "{}{}{}",
        headers(),
        frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n"),
        frame("ping", &format!("payload_hex = \"{opaque}\"\n"))
    ))
}

fn written_length(script: &Script) -> usize {
    24 + script
        .envelopes
        .iter()
        .map(|envelope| FRAME_HEADER_LEN + envelope.payload.len())
        .sum::<usize>()
}

/// Runs `script` against a peer that reads every authored octet, answers with `frames`, and keeps
/// TCP open until the observer returns.
fn answered(script: &Script, frames: Vec<u8>, budget: Duration) -> Result<Observation, SutError> {
    let (release, held) = mpsc::channel();
    let (addr, peer) = peer(written_length(script), move |stream| {
        stream.write_all(&frames).expect("peer frames written");
        let _ = held.recv_timeout(Duration::from_secs(3));
    });
    let observed = execute(addr, script, budget);
    let _ = release.send(());
    peer.join().expect("peer completes");
    observed
}

fn head_200() -> Vec<u8> {
    hex("000001 01 04 00000001 88")
}

fn ack(opaque: &str) -> Vec<u8> {
    let mut bytes = hex("000008 06 01 00000000");
    bytes.extend(hex(opaque));
    bytes
}

#[test]
fn a_ping_defaults_to_stream_zero_and_keeps_its_ack_flag_and_payload() {
    let compiled = script(&format!(
        "{}{}{}",
        headers(),
        frame("ping", &format!("payload_hex = \"{OPAQUE}\"\n")),
        frame("ping", "flags = [\"ack\"]\nstream_id = 3\npayload_hex = \"01020304050607\"\n")
    ));
    let pings: Vec<_> = compiled.envelopes.iter().skip(1).map(Envelope::bytes).collect();
    assert_eq!(
        pings,
        [
            hex(&format!("000008 06 00 00000000 {OPAQUE}")),
            hex("000007 06 01 00000003 01020304050607")
        ]
    );
}

#[test]
fn a_ping_refuses_fields_it_would_not_send() {
    for (fields, expected) in [
        ("", "ping frame with no payload_hex"),
        (
            "flags = [\"end_stream\"]\npayload_hex = \"0102030405060708\"\n",
            "`end_stream`, which is not a ping flag",
        ),
        (
            "error_code = \"CANCEL\"\npayload_hex = \"0102030405060708\"\n",
            "error_code and increment belong to other",
        ),
        (
            "increment = 1\npayload_hex = \"0102030405060708\"\n",
            "error_code and increment belong to other",
        ),
    ] {
        let error = compile_error(&format!("{HEAD}{}{}", headers(), frame("ping", fields)));
        assert!(error.contains(expected), "{fields}: {error}");
    }
}

#[test]
fn only_a_ping_after_a_reset_of_the_selected_stream_is_a_barrier() {
    assert_eq!(reset_then_ping(OPAQUE).reset_barrier, Some(hex(OPAQUE)));
    let ping = frame("ping", &format!("payload_hex = \"{OPAQUE}\"\n"));
    for (label, frames) in [
        (
            "ping before the reset",
            format!("{}{ping}{}", headers(), frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n")),
        ),
        (
            "reset of another stream",
            format!("{}{}{ping}", headers(), frame("rst_stream", "stream_id = 3\nerror_code = \"CANCEL\"\n")),
        ),
        (
            "acknowledgement, not a probe",
            format!(
                "{}{}{}",
                headers(),
                frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n"),
                frame("ping", &format!("flags = [\"ack\"]\npayload_hex = \"{OPAQUE}\"\n"))
            ),
        ),
        (
            "seven opaque octets",
            format!(
                "{}{}{}",
                headers(),
                frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n"),
                frame("ping", "payload_hex = \"01020304050607\"\n")
            ),
        ),
        (
            "ping on a nonzero stream",
            format!(
                "{}{}{}",
                headers(),
                frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n"),
                frame("ping", &format!("stream_id = 1\npayload_hex = \"{OPAQUE}\"\n"))
            ),
        ),
    ] {
        assert_eq!(script(&frames).reset_barrier, None, "{label}");
    }
}

/// Negative — a raw PING is how a version-4 script spells PING, so it never makes a barrier, and a
/// reset too short to carry an error code is not a reset the peer could have processed.
#[test]
fn a_raw_ping_or_a_malformed_reset_is_not_a_barrier() {
    let raw = script(&format!(
        "{}{}{}",
        headers(),
        frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n"),
        frame("raw", &format!("payload_hex = \"000008060000000000{OPAQUE}\"\n"))
    ));
    assert_eq!(raw.reset_barrier, None);
    assert!(!raw.observes_pings);
    let short = script(&format!(
        "{}{}{}",
        headers(),
        frame("rst_stream", "stream_id = 1\npayload_hex = \"000008\"\n"),
        frame("ping", &format!("payload_hex = \"{OPAQUE}\"\n"))
    ));
    assert_eq!(short.reset_barrier, None);
}

/// Negative — a raw PING carrying the barrier's octets makes the acknowledgement ambiguous too.
#[test]
fn a_raw_ping_with_the_barrier_octets_is_refused() {
    let error = compile_error(&format!(
        "{HEAD}{}{}{}{}",
        headers(),
        frame("raw", &format!("payload_hex = \"000008060000000000{OPAQUE}\"\n")),
        frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n"),
        frame("ping", &format!("payload_hex = \"{OPAQUE}\"\n"))
    ));
    assert!(error.contains("could not say which one the peer answered"), "{error}");
}

/// Negative — a script without a typed PING (every version-4 script) records no acknowledgement,
/// so its exact control-frame list keeps its version-4 meaning.
#[test]
fn an_acknowledgement_is_not_recorded_for_a_script_without_a_typed_ping() {
    let raw_only = script(&format!(
        "{}{}",
        headers(),
        frame("raw", &format!("payload_hex = \"000008060000000000{OPAQUE}\"\n"))
    ));
    let mut frames = ack(OPAQUE);
    frames.extend(hex("000001 01 05 00000001 88"));
    let observed = answered(&raw_only, frames, Duration::from_secs(2)).expect("measured");
    assert_eq!(observed.outcome, Outcome::Response, "{observed:?}");
    assert_eq!(observed.h2_control_frames, Some(Vec::new()));
}

#[test]
fn a_barrier_whose_octets_an_earlier_ping_also_carries_is_refused() {
    let ping = frame("ping", &format!("payload_hex = \"{OPAQUE}\"\n"));
    let error = compile_error(&format!(
        "{HEAD}{}{ping}{}{ping}",
        headers(),
        frame("rst_stream", "stream_id = 1\nerror_code = \"CANCEL\"\n")
    ));
    assert!(error.contains("could not say which one the peer answered"), "{error}");
}

/// Positive — the barrier acknowledgement ends the observation as a client reset, keeping the head
/// that arrived before it.
#[test]
fn the_barrier_acknowledgement_ends_the_exchange_as_a_client_reset() {
    let mut frames = head_200();
    frames.extend(ack(OPAQUE));
    let observed = answered(&reset_then_ping(OPAQUE), frames, Duration::from_secs(2)).expect("measured");
    assert_eq!(observed.outcome, Outcome::ClientReset, "{observed:?}");
    assert_eq!(observed.status, Some(200));
    assert_eq!(observed.deadline_expiry, None);
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::PingAck {
            opaque_data: [1, 2, 3, 4, 5, 6, 7, 8]
        }])
    );
}

/// Negative — an acknowledgement of other octets proves nothing about the reset; the observer
/// keeps waiting, records what arrived, and reaches its deadline.
#[test]
fn an_acknowledgement_of_other_octets_is_recorded_but_is_not_the_barrier() {
    let observed = answered(&reset_then_ping(OPAQUE), ack("0807060504030201"), Duration::from_millis(300)).expect("measured");
    assert_eq!(observed.outcome, Outcome::Hang, "{observed:?}");
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::PingAck {
            opaque_data: [8, 7, 6, 5, 4, 3, 2, 1]
        }])
    );
}

/// Negative — without a client reset the same acknowledgement ends nothing.
#[test]
fn an_acknowledgement_without_a_client_reset_is_not_an_end() {
    let without_reset = script(&format!("{}{}", headers(), frame("ping", &format!("payload_hex = \"{OPAQUE}\"\n"))));
    let observed = answered(&without_reset, ack(OPAQUE), Duration::from_millis(300)).expect("measured");
    assert_eq!(observed.outcome, Outcome::Hang, "{observed:?}");
    assert_eq!(
        observed.h2_control_frames,
        Some(vec![ObservedH2ControlFrame::PingAck {
            opaque_data: [1, 2, 3, 4, 5, 6, 7, 8]
        }])
    );
}

/// Negative — a peer's own PING is read but not recorded as an acknowledgement.
#[test]
fn a_peer_ping_without_ack_is_not_recorded_as_an_acknowledgement() {
    let mut frames = hex(&format!("000008 06 00 00000000 {OPAQUE}"));
    frames.extend(hex("000001 01 05 00000001 88"));
    let with_ping = script(&format!("{}{}", headers(), frame("ping", &format!("payload_hex = \"{OPAQUE}\"\n"))));
    let observed = answered(&with_ping, frames, Duration::from_secs(2)).expect("measured");
    assert_eq!(observed.outcome, Outcome::Response, "{observed:?}");
    assert_eq!(observed.h2_control_frames, Some(Vec::new()));
}

/// Negative — an acknowledgement that is not eight octets on stream zero is refused, not recorded.
#[test]
fn a_malformed_acknowledgement_is_refused() {
    for frames in [hex("000007 06 01 00000000 01020304050607"), {
        let mut bytes = hex("000008 06 01 00000001");
        bytes.extend(hex(OPAQUE));
        bytes
    }] {
        let error = answered(&reset_then_ping(OPAQUE), frames, Duration::from_secs(2)).expect_err("refused");
        assert!(error.to_string().contains("eight octets on stream zero"), "{error}");
    }
}
