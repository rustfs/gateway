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

//! Responsible for: client-authored RST_STREAM, GOAWAY, PRIORITY and `raw` frames — their exact
//! envelopes, the declarations refused by name, and the octets a loopback peer actually receives.
//! NOT responsible for: judging what a real server does after them; the c-h2 corpus cases do that
//! against production Hyper.
//! Upstream: `super::compile` and `super::execute`; downstream: the repository verification gate.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-7 — error codes are 32-bit numbers
//! with registered names, and unknown codes must not trigger special behavior.

use super::*;

fn frame_after_headers(frame: &str) -> String {
    format!(
        "{HEAD}[[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\", \"end_stream\"]\n\
         payload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n[[h2_frames]]\n{frame}"
    )
}

/// The envelope the one authored control frame after the stream-1 HEADERS compiles to.
fn control(frame: &str) -> Envelope {
    let script = compile(&read(&block(&frame_after_headers(frame)))).expect("the control frame compiles");
    script.envelopes.last().cloned().expect("two envelopes")
}

fn control_error(frame: &str) -> String {
    compile_error(&frame_after_headers(frame))
}

fn literal(frame_type: u8, stream_id: u32, payload: &str) -> Envelope {
    Envelope {
        frame_type,
        flags: 0,
        stream_id,
        payload: hex(payload),
        delay_ms: 0,
    }
}

#[test]
fn rst_stream_encodes_a_registered_name_or_an_explicit_hex_code() {
    assert_eq!(
        control("type = \"rst_stream\"\nstream_id = 1\nerror_code = \"CANCEL\"\n"),
        literal(RST_STREAM, 1, "00000008")
    );
    assert_eq!(
        control("type = \"rst_stream\"\nstream_id = 7\nerror_code = \"HTTP_1_1_REQUIRED\"\n"),
        literal(RST_STREAM, 7, "0000000d")
    );
    assert_eq!(
        control("type = \"rst_stream\"\nstream_id = 1\nerror_code = \"0xdeadbeef\"\n"),
        literal(RST_STREAM, 1, "deadbeef"),
        "an unregistered code stays exactly the number the case wrote"
    );
    assert_eq!(
        control("type = \"rst_stream\"\nstream_id = 1\npayload_hex = \"000008\"\n"),
        literal(RST_STREAM, 1, "000008"),
        "a malformed length stays literal"
    );
}

#[test]
fn goaway_defaults_to_stream_zero_and_a_zero_last_stream_identifier() {
    assert_eq!(
        control("type = \"goaway\"\nerror_code = \"NO_ERROR\"\n"),
        literal(GOAWAY, 0, "00000000 00000000")
    );
    assert_eq!(
        control("type = \"goaway\"\nerror_code = \"ENHANCE_YOUR_CALM\"\n"),
        literal(GOAWAY, 0, "00000000 0000000b")
    );
    assert_eq!(
        control("type = \"goaway\"\nstream_id = 1\npayload_hex = \"00000000000000\"\n"),
        literal(GOAWAY, 1, "00000000000000"),
        "a nonzero stream and a seven-octet payload stay literal"
    );
}

#[test]
fn priority_and_raw_frames_are_written_literally() {
    assert_eq!(
        control("type = \"priority\"\nstream_id = 3\npayload_hex = \"0000000010\"\n"),
        literal(PRIORITY, 3, "0000000010")
    );
    let unknown = control("type = \"raw\"\npayload_hex = \"000004fa0100000000deadbeef\"\n");
    assert_eq!(unknown.bytes(), hex("000004fa0100000000deadbeef"));
    let reserved = control("type = \"raw\"\npayload_hex = \"0000080600800000010102030405060708\"\n");
    assert_eq!(
        reserved.bytes(),
        hex("000008060080000001 0102030405060708"),
        "the reserved stream-identifier bit is authored, not masked"
    );
}

#[test]
fn a_control_frame_on_another_stream_does_not_open_a_second_stream() {
    let script = compile(&read(&block(&format!(
        "{HEAD}[[h2_frames]]\ntype = \"priority\"\nstream_id = 3\npayload_hex = \"0000000010\"\n\
         [[h2_frames]]\ntype = \"rst_stream\"\nstream_id = 5\nerror_code = \"CANCEL\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\", \"end_stream\"]\n\
         payload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n"
    ))))
    .expect("control frames name streams without opening them");
    assert_eq!(script.stream_id, 1);
}

#[test]
fn an_error_code_spelling_outside_the_registry_is_refused() {
    for spelling in ["cancel", "Cancel", "8", "0x", "0x123456789", "0xzz", "CANCEL "] {
        let error = control_error(&format!("type = \"rst_stream\"\nstream_id = 1\nerror_code = \"{spelling}\"\n"));
        assert!(error.contains("section 7 error-code"), "{spelling}: {error}");
    }
}

#[test]
fn an_error_code_and_payload_together_or_neither_are_refused() {
    for kind in ["rst_stream", "goaway"] {
        let both = control_error(&format!(
            "type = \"{kind}\"\nstream_id = 1\nerror_code = \"CANCEL\"\npayload_hex = \"00000008\"\n"
        ));
        assert!(both.contains("both error_code and payload_hex"), "{kind}: {both}");
        let neither = control_error(&format!("type = \"{kind}\"\nstream_id = 1\n"));
        assert!(neither.contains("neither error_code nor payload_hex"), "{kind}: {neither}");
    }
}

#[test]
fn a_priority_frame_must_spell_its_payload_and_carries_no_error_code() {
    let missing = control_error("type = \"priority\"\nstream_id = 1\n");
    assert!(missing.contains("priority frame with no payload_hex"), "{missing}");
    let code = control_error("type = \"priority\"\nstream_id = 1\nerror_code = \"CANCEL\"\npayload_hex = \"0000000010\"\n");
    assert!(code.contains("error_code` belongs to rst_stream and goaway, not to priority"), "{code}");
}

#[test]
fn stream_bound_control_frames_require_a_31_bit_stream_id() {
    for frame in [
        "type = \"rst_stream\"\nerror_code = \"CANCEL\"\n",
        "type = \"priority\"\npayload_hex = \"0000000010\"\n",
    ] {
        let error = control_error(frame);
        assert!(error.contains("with no stream_id"), "{frame}: {error}");
    }
    let wide = control_error("type = \"goaway\"\nstream_id = 2147483648\nerror_code = \"NO_ERROR\"\n");
    assert!(wide.contains("is not a 31-bit stream identifier"), "{wide}");
}

#[test]
fn a_control_payload_beyond_the_24_bit_frame_length_is_refused() {
    for kind in ["rst_stream", "goaway", "priority"] {
        let frame = H2Frame {
            kind: kind.to_owned(),
            stream_id: Some(1),
            flags: Vec::new(),
            payload: vec![0; MAX_PAYLOAD + 1],
            payload_declared: true,
            error_code: None,
            increment: None,
            delay_ms: 0,
        };
        let error = super::super::envelope(0, &frame)
            .expect_err("the header cannot state this length")
            .to_string();
        assert!(error.contains("beyond the 24-bit frame length"), "{kind}: {error}");
        let fits = H2Frame {
            payload: vec![0; MAX_PAYLOAD],
            ..frame
        };
        assert!(
            super::super::envelope(0, &fits).is_ok(),
            "{kind}: the largest representable payload compiles"
        );
    }
}

#[test]
fn flags_and_increments_on_control_frames_are_refused() {
    for kind in ["rst_stream", "goaway", "priority"] {
        let flags = control_error(&format!(
            "type = \"{kind}\"\nstream_id = 1\nflags = [\"ack\"]\npayload_hex = \"0000000010\"\n"
        ));
        assert!(flags.contains("defines no flags this writer sets"), "{kind}: {flags}");
        let increment = control_error(&format!(
            "type = \"{kind}\"\nstream_id = 1\nincrement = 1\npayload_hex = \"0000000010\"\n"
        ));
        assert!(increment.contains("increment` belongs to window_update"), "{kind}: {increment}");
    }
}

#[test]
fn a_raw_frame_is_exactly_one_complete_untyped_frame() {
    for (frame, expected) in [
        ("type = \"raw\"\n", "raw frame with no payload_hex"),
        (
            "type = \"raw\"\nstream_id = 0\npayload_hex = \"000000fa0000000000\"\n",
            "stream_id and error_code would be ignored",
        ),
        (
            "type = \"raw\"\nerror_code = \"CANCEL\"\npayload_hex = \"000000fa0000000000\"\n",
            "stream_id and error_code would be ignored",
        ),
        (
            "type = \"raw\"\npayload_hex = \"000000fa00000000\"\n",
            "shorter than the nine-octet frame header",
        ),
        (
            "type = \"raw\"\npayload_hex = \"000002fa0000000000ff\"\n",
            "declares 2 payload octets but carries 1",
        ),
        (
            "type = \"raw\"\npayload_hex = \"000000fa0000000000ff\"\n",
            "declares 0 payload octets but carries 1",
        ),
    ] {
        let error = control_error(frame);
        assert!(error.contains(expected), "{frame}: {error}");
    }
    for typed in ["00", "01", "04", "08", "09"] {
        let error = control_error(&format!("type = \"raw\"\npayload_hex = \"000000{typed}0000000001\"\n"));
        assert!(
            error.contains(&format!("raw frame of type 0x{typed}, which has a typed form")),
            "{typed}: {error}"
        );
    }
}

#[test]
fn a_frame_type_the_schema_does_not_name_is_still_refused_by_name() {
    let error = control_error("type = \"push_promise\"\nstream_id = 1\n");
    assert!(error.contains("type = \"push_promise\"` is not executed"), "{error}");
}

/// Positive — the loopback peer receives the preface and every authored control frame octet for
/// octet, spelled out here rather than derived from the writer under test.
#[test]
fn the_peer_receives_authored_control_frames_exactly() {
    let script = compile(&read(&block(&format!(
        "{HEAD}[[h2_frames]]\ntype = \"settings\"\n\
         [[h2_frames]]\ntype = \"priority\"\nstream_id = 1\npayload_hex = \"0000000010\"\n\
         [[h2_frames]]\ntype = \"raw\"\npayload_hex = \"000001fa0300000000aa\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_stream\", \"end_headers\"]\n\
         payload_hex = \"{ANONYMOUS_GET_ROOT_HPACK}\"\n\
         [[h2_frames]]\ntype = \"rst_stream\"\nstream_id = 1\nerror_code = \"CANCEL\"\n\
         [[h2_frames]]\ntype = \"goaway\"\nerror_code = \"NO_ERROR\"\n"
    ))))
    .expect("the script compiles");
    let mut expected = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    expected.extend(hex("000000 04 00 00000000"));
    expected.extend(hex("000005 02 00 00000001 0000000010"));
    expected.extend(hex("000001 fa 03 00000000 aa"));
    expected.extend(hex("000013 01 05 00000001"));
    expected.extend(hex(ANONYMOUS_GET_ROOT_HPACK));
    expected.extend(hex("000004 03 00 00000001 00000008"));
    expected.extend(hex("000008 07 00 00000000 00000000 00000000"));
    let (addr, peer) = peer(expected.len(), |_| {});
    execute(addr, &script, Duration::from_secs(2)).expect("the hang-up is observed");
    assert_eq!(peer.join().expect("the peer exits"), expected);
}
