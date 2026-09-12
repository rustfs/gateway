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

//! Authored timing for cleartext external HTTP/1.1 request bodies.
//!
//! Responsible for: enforcing each data chunk's not-before delay, observing response bytes during
//! that wait, and stopping the unfinished request when an early response exists. Not responsible for:
//! TLS record interpretation, control chunks, response decoding, or endpoint setup. Upstream:
//! `super::external`; downstream: `crate::socket::Connection`.

use std::time::{Duration, Instant};

use super::BodyProgress;
use crate::inprocess::{ChunkStep, Wire};
use crate::socket::{Connection, PeerInput};
use crate::sut::SutError;

pub(super) fn validate_authored_steps(wire: &Wire, cleartext: bool, budget: Duration) -> Result<(), SutError> {
    let mut declared_delay = Duration::ZERO;
    for (index, step) in wire.steps.iter().enumerate() {
        match step {
            ChunkStep::Data(_, delay_ms) => {
                let delay = Duration::from_millis(*delay_ms);
                declared_delay = declared_delay.saturating_add(delay);
                if !cleartext && !delay.is_zero() {
                    return Err(SutError::Environment(format!(
                        "external HTTPS data step {index} declares a {delay_ms}ms delay, but encrypted socket readiness does not prove an HTTP response exists"
                    )));
                }
                if declared_delay > budget {
                    return Err(SutError::Environment(format!(
                        "external endpoint data step {index} exceeds the exchange timeout: {declared_delay:?} of declared delay is greater than the {budget:?} budget"
                    )));
                }
            }
            ChunkStep::Control { action, .. } => {
                return Err(SutError::Environment(format!(
                    "external endpoint `{action}` control is not implemented with concurrent response observation"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn write_authored_body(
    connection: &mut Connection,
    wire: &Wire,
    declared_length: u64,
    deadline: Instant,
) -> Result<BodyProgress, SutError> {
    let mut response_seen = false;
    for step in &wire.steps {
        let ChunkStep::Data(bytes, delay_ms) = step else {
            return Err(SutError::Environment(
                "an unsupported external request step passed preflight validation".to_owned(),
            ));
        };
        let delay = Duration::from_millis(*delay_ms);
        if !delay.is_zero() {
            let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(|| {
                SutError::Environment("the exchange exhausted its declared timeout before the next body chunk".to_owned())
            })?;
            if delay > remaining {
                return Err(SutError::Environment(
                    "the next external body delay exceeds the remaining exchange timeout".to_owned(),
                ));
            }
            match connection.wait_for_cleartext_response(delay)? {
                PeerInput::Ready => {
                    response_seen = true;
                    break;
                }
                PeerInput::Closed => break,
                PeerInput::TimedOut => {}
            }
        }
        write_before_deadline(connection, bytes, deadline)?;
        if connection.torn_down() {
            break;
        }
    }
    let sent = connection.body_written();
    let measured_at_response = response_seen;
    let notes = if measured_at_response {
        vec!["cleartext response bytes were observed while the next authored body chunk was delayed".to_owned()]
    } else {
        vec![
            "external endpoints expose no server-side demand observer; request body bytes sent when the response existed are unavailable"
                .to_owned(),
        ]
    };
    Ok(BodyProgress {
        sent_at_response: sent,
        measured_at_response,
        fully_sent: sent >= declared_length,
        torn_down: connection.torn_down(),
        notes,
    })
}

fn write_before_deadline(connection: &mut Connection, bytes: &[u8], deadline: Instant) -> Result<(), SutError> {
    if Instant::now() >= deadline {
        return Err(SutError::Environment(
            "the exchange exhausted its declared timeout before the next body chunk".to_owned(),
        ));
    }
    connection.write_body(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn delayed_wire(delay_ms: u64) -> Wire {
        Wire {
            method: "PUT".to_owned(),
            target: "/bucket/key".to_owned(),
            headers: Vec::new(),
            raw_head: None,
            h2_frames: Vec::new(),
            http_version: None,
            body: b"late".to_vec(),
            frames: Vec::new(),
            steps: vec![ChunkStep::Data(b"late".to_vec(), delay_ms)],
            sign: None,
        }
    }

    #[test]
    fn silent_peer_keeps_a_delayed_chunk_behind_its_not_before_instant() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("bound body wait");
            ready_tx.send(()).expect("announce accepted socket");
            let mut body = [0_u8; 4];
            stream.read_exact(&mut body).expect("read delayed body");
            (body, Instant::now())
        });
        let mut connection = Connection::open(address).expect("connect client");
        ready_rx.recv().expect("server accepted socket");
        let wire = delayed_wire(75);
        let started = Instant::now();

        let progress = write_authored_body(&mut connection, &wire, 4, started + Duration::from_secs(1)).expect("paced body");
        let (body, arrived) = server.join().expect("server exits");
        let arrival_delay = arrived.duration_since(started);

        assert!(arrival_delay >= Duration::from_millis(75));
        assert!(arrival_delay < Duration::from_millis(125), "arrival error must stay below 50ms");
        assert_eq!(body, *b"late");
        assert!(progress.fully_sent);
        assert!(!progress.measured_at_response);
    }

    #[test]
    fn nonzero_prefix_is_the_measured_progress_when_the_next_chunk_wait_sees_a_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("bound prefix wait");
            let mut prefix = [0_u8; 3];
            stream.read_exact(&mut prefix).expect("read first body chunk");
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .expect("write early response");
            stream
                .set_read_timeout(Some(Duration::from_millis(150)))
                .expect("bound tail observation");
            let mut tail = [0_u8; 1];
            let tail_read = match stream.read(&mut tail) {
                Ok(read) => read,
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => 0,
                Err(error) => panic!("observe request tail: {error}"),
            };
            (prefix, tail_read)
        });
        let mut connection = Connection::open(address).expect("connect client");
        let mut wire = delayed_wire(200);
        wire.body = b"onetwo".to_vec();
        wire.steps = vec![ChunkStep::Data(b"one".to_vec(), 0), ChunkStep::Data(b"two".to_vec(), 200)];

        let progress =
            write_authored_body(&mut connection, &wire, 6, Instant::now() + Duration::from_secs(1)).expect("paced body");
        let (prefix, tail_read) = server.join().expect("server exits");

        assert_eq!(prefix, *b"one");
        assert_eq!(tail_read, 0);
        assert_eq!(progress.sent_at_response, 3);
        assert!(progress.measured_at_response);
        assert!(!progress.fully_sent);
    }

    #[test]
    fn an_expired_deadline_writes_no_body_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("bound body observation");
            let mut byte = [0_u8; 1];
            match stream.read(&mut byte) {
                Ok(read) => read,
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => 0,
                Err(error) => panic!("observe expired write: {error}"),
            }
        });
        let mut connection = Connection::open(address).expect("connect client");

        let error = write_before_deadline(&mut connection, b"late", Instant::now()).expect_err("deadline prevents the write");
        let bytes_received = server.join().expect("server exits");

        assert!(error.to_string().contains("exhausted its declared timeout"));
        assert_eq!(bytes_received, 0);
        assert_eq!(connection.body_written(), 0);
    }
}
