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

//! Responsible for: one cleartext owner interleaving literal frame writes and measured peer reads.
//! NOT responsible for: TLS, automatic credit, or changing authored frame boundaries. Only the
//! observed stream's request progress is measured; other streams' DATA spends connection credit.
//! Upstream: the HTTP/2 executor; downstream: the socket, frame decoder, and two-scope flow ledger.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;

use super::*;

pub(super) struct Progress {
    pub(super) deadline_expiry: Option<crate::observation::DeadlineExpiry>,
    pub(super) at_response: Option<u64>,
    pub(super) body_complete: bool,
    pub(super) unfinished_script: bool,
}

pub(super) fn run(
    connection: &mut Connection,
    script: &Script,
    clock: &mut ExchangeClock,
    sleep: Option<&mut dyn FnMut(Duration)>,
) -> Result<(Response, Progress), SutError> {
    let socket = connection.cleartext_socket()?;
    socket
        .set_nonblocking(true)
        .map_err(|error| refused(format!("cannot start HTTP/2 duplex I/O: {error}")))?;
    let result = pump(socket, script, clock, sleep);
    // Restore blocking probes even on a protocol refusal; this connection has no other owner.
    let restored = socket
        .set_nonblocking(false)
        .map_err(|error| refused(format!("cannot finish HTTP/2 duplex I/O: {error}")));
    let result = result?;
    restored?;
    Ok(result)
}

fn pump(
    socket: &mut TcpStream,
    script: &Script,
    clock: &mut ExchangeClock,
    mut sleep: Option<&mut dyn FnMut(Duration)>,
) -> Result<(Response, Progress), SutError> {
    let mut flow = flow::Flow::new(script.stream_id);
    let mut reader = FrameReader::default();
    let mut receiver = Receiver::new(script);
    let mut writer = Writer::new();
    let mut at_response = None;
    let mut ended_body = false;
    let mut write_failed = false;
    let mut deadline_expiry = None;
    'exchange: loop {
        if Instant::now() >= clock.deadline {
            deadline_expiry = Some(crate::observation::DeadlineExpiry {
                deadline: clock.deadline,
                observed_at: Instant::now(),
                harness_wait: clock.harness_wait,
            });
            receiver.response.cut_short = Some(ReadFailure::TimedOut);
            break;
        }
        // Drain available input before every further write, including after an authored delay.
        // A later grant must not legalize DATA that was already waiting in the socket.
        loop {
            while let Some(frame) = reader.take() {
                let ended = receiver.accept(frame, script, &mut flow)?;
                if at_response.is_none() && (receiver.response.status.is_some() || ended) {
                    at_response = writer.body_written;
                }
                if ended {
                    break 'exchange;
                }
            }
            if Instant::now() >= clock.deadline {
                deadline_expiry = Some(crate::observation::DeadlineExpiry {
                    deadline: clock.deadline,
                    observed_at: Instant::now(),
                    harness_wait: clock.harness_wait,
                });
                receiver.response.cut_short = Some(ReadFailure::TimedOut);
                break 'exchange;
            }
            let mut bytes = [0; 4096];
            match socket.read(&mut bytes) {
                Ok(0) => {
                    receiver.response.cut_short = Some(if reader.buffered.is_empty() {
                        ReadFailure::ClosedBeforeHead
                    } else {
                        ReadFailure::Truncated
                    });
                    break 'exchange;
                }
                Ok(count) => reader.buffered.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => {
                    receiver.response.cut_short = Some(match error.kind() {
                        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => ReadFailure::Reset,
                        _ => ReadFailure::Malformed(error.to_string()),
                    });
                    break 'exchange;
                }
            }
        }
        if writer.offset == writer.bytes.len()
            && !write_failed
            && let Some(envelope) = script.envelopes.get(writer.index)
        {
            let delay = Duration::from_millis(envelope.delay_ms);
            if delay >= clock.remaining()? {
                return Err(refused(format!(
                    "`h2_frames[{}]` declares a {}ms delay beyond the remaining exchange timeout",
                    writer.index, envelope.delay_ms
                )));
            }
            writer.bytes = envelope.bytes();
            writer.offset = 0;
            writer.ready_at = Instant::now() + delay;
            if !delay.is_zero()
                && let Some(sleep) = sleep.as_deref_mut()
            {
                clock.paced(|| sleep(delay));
            }
            // In particular, observe input received during the wait before granting credit.
            continue;
        }
        let waiting = Instant::now() < writer.ready_at;
        let partial_peer_grant = !reader.buffered.is_empty()
            && script.envelopes.get(writer.index).is_some_and(|frame| {
                frame.frame_type == WINDOW_UPDATE || (frame.frame_type == SETTINGS && frame.flags & ACK == 0)
            });
        if !waiting && !partial_peer_grant && !write_failed && writer.offset < writer.bytes.len() {
            // A bounded syscall slice allows read progress even when the socket accepts a large frame.
            let end = (writer.offset + 16_384).min(writer.bytes.len());
            match socket.write(&writer.bytes[writer.offset..end]) {
                Ok(0) => write_failed = true,
                Ok(count) => {
                    if !writer.preface
                        && let Some(envelope) = script.envelopes.get(writer.index)
                        && envelope.frame_type == DATA
                    {
                        let before = writer.offset.saturating_sub(FRAME_HEADER_LEN);
                        let after = (writer.offset + count).saturating_sub(FRAME_HEADER_LEN);
                        flow.sent_data(after - before, envelope.stream_id);
                        // Authored padded DATA is literal, but its application-byte progress is unavailable.
                        // Another stream's DATA is not the observed request's body.
                        if envelope.stream_id == script.stream_id {
                            writer.body_written = writer
                                .body_written
                                .filter(|_| envelope.flags & PADDED == 0)
                                .and_then(|written| written.checked_add(u64::try_from(after - before).ok()?));
                        }
                    }
                    writer.offset += count;
                    if writer.offset == writer.bytes.len() {
                        if writer.preface {
                            writer.preface = false;
                        } else if let Some(envelope) = script.envelopes.get(writer.index) {
                            // Commit the grant before reading a peer response to the completed frame.
                            flow.sent(envelope);
                            ended_body |= matches!(envelope.frame_type, DATA | HEADERS)
                                && envelope.flags & END_STREAM != 0
                                && envelope.stream_id == script.stream_id;
                            writer.index += 1;
                        }
                    }
                    continue;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                // A write-side failure is not a receive-side observation. Keep reading actual frames.
                Err(_) => write_failed = true,
            }
        }
        let pause = clock
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(1));
        if waiting {
            clock.paced(|| std::thread::sleep(pause.min(writer.ready_at.saturating_duration_since(Instant::now()))));
        } else {
            std::thread::sleep(pause);
        }
    }
    let body_complete = ended_body
        && script
            .envelopes
            .iter()
            .skip(writer.index)
            .all(|frame| frame.frame_type != DATA || frame.stream_id != script.stream_id);
    let progress = Progress {
        deadline_expiry,
        at_response,
        body_complete,
        unfinished_script: writer.preface || writer.index < script.envelopes.len(),
    };
    Ok((receiver.response, progress))
}

struct Writer {
    bytes: Vec<u8>,
    offset: usize,
    preface: bool,
    index: usize,
    ready_at: Instant,
    body_written: Option<u64>,
}

impl Writer {
    fn new() -> Self {
        Self {
            bytes: PREFACE.to_vec(),
            offset: 0,
            preface: true,
            index: 0,
            ready_at: Instant::now(),
            body_written: Some(0),
        }
    }
}
