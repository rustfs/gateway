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

//! Responsible for: two-scope credit accounting from frames actually written and received.
//! NOT responsible for: pacing or normalizing authored DATA, generating credit, or socket I/O.
//! Upstream: the literal HTTP/2 writer and reader; downstream: measured receive-limit checks.

use super::{ACK, Envelope, INITIAL_CONNECTION_WINDOW, MAX_STREAM_ID, SETTINGS, SutError, WINDOW_UPDATE, refused};

pub(super) struct Flow {
    stream_id: u32,
    receive_connection: i64,
    receive_stream: i64,
    receive_initial: i64,
    receive_valid: bool,
    send_connection: i64,
    send_stream: i64,
    send_initial: i64,
}

impl Flow {
    pub(super) fn new(stream_id: u32) -> Self {
        let initial = i64::try_from(INITIAL_CONNECTION_WINDOW).unwrap_or(i64::MAX);
        Self {
            stream_id,
            receive_connection: initial,
            receive_stream: initial,
            receive_initial: initial,
            receive_valid: true,
            send_connection: initial,
            send_stream: initial,
            send_initial: initial,
        }
    }

    /// Called only after a complete authored frame is written. Literal DATA is never gated.
    /// Invalid authored credit leaves peer control frames observable, but cannot certify DATA.
    pub(super) fn sent(&mut self, frame: &Envelope) {
        if frame.frame_type == WINDOW_UPDATE {
            // Malformed length or zero remain literal protocol tests. They grant no usable credit.
            if let Ok(bytes) = <[u8; 4]>::try_from(frame.payload.as_slice()) {
                let increment = u32::from_be_bytes(bytes) & MAX_STREAM_ID;
                if increment != 0 {
                    let credit = if frame.stream_id == 0 {
                        &mut self.receive_connection
                    } else if frame.stream_id == self.stream_id {
                        &mut self.receive_stream
                    } else {
                        return;
                    };
                    if add(credit, increment).is_err() {
                        self.receive_valid = false;
                    }
                }
            }
        } else if frame.frame_type == SETTINGS
            && frame.flags & ACK == 0
            && (frame.stream_id != 0
                || Self::settings(&frame.payload, &mut self.receive_initial, &mut self.receive_stream).is_err())
        {
            self.receive_valid = false;
        }
    }

    /// DATA consumes send credit as its payload bytes are actually written, including padding; only
    /// the observed stream's own credit is tracked, connection credit is shared by every stream.
    pub(super) fn sent_data(&mut self, count: usize, stream: u32) {
        let count = i64::try_from(count).unwrap_or(i64::MAX);
        self.send_connection -= count;
        if stream == self.stream_id {
            self.send_stream -= count;
        }
    }

    pub(super) fn received_settings(&mut self, payload: &[u8], flags: u8) -> Result<(), SutError> {
        if flags & ACK == 0 {
            Self::settings(payload, &mut self.send_initial, &mut self.send_stream)?;
        } else if !payload.is_empty() {
            return Err(refused("SETTINGS ACK payload must be empty".to_owned()));
        }
        Ok(())
    }

    fn settings(payload: &[u8], initial: &mut i64, current: &mut i64) -> Result<(), SutError> {
        if !payload.len().is_multiple_of(6) {
            return Err(refused("SETTINGS payload length must be a multiple of six octets".to_owned()));
        }
        for field in payload.chunks_exact(6) {
            if field[0..2] == [0, 4] {
                let next = u32::from_be_bytes([field[2], field[3], field[4], field[5]]);
                if next > MAX_STREAM_ID {
                    return Err(refused("flow-control initial stream window exceeds 31 bits".to_owned()));
                }
                *current += i64::from(next) - *initial;
                *initial = i64::from(next);
                if *current > i64::from(MAX_STREAM_ID) {
                    return Err(refused("flow-control stream window overflow after SETTINGS".to_owned()));
                }
            }
        }
        Ok(())
    }

    /// `opened` names another stream the script opened: its credit is not tracked, so the grant
    /// is accepted without being accounted for.
    pub(super) fn received_update(&mut self, stream: u32, increment: u32, opened: bool) -> Result<(), SutError> {
        let credit = if stream == 0 {
            &mut self.send_connection
        } else if stream == self.stream_id {
            &mut self.send_stream
        } else if opened {
            return Ok(());
        } else {
            return Err(refused("WINDOW_UPDATE for an untracked stream cannot be accounted for".to_owned()));
        };
        add(credit, increment)
    }

    /// Another opened stream's DATA: it spends the shared connection window, whose limit still holds.
    pub(super) fn received_other_data(&mut self, count: usize) -> Result<(), SutError> {
        if !self.receive_valid {
            return Err(refused("flow-control DATA credit is unknown after an invalid authored grant".to_owned()));
        }
        let count = i64::try_from(count).unwrap_or(i64::MAX);
        if count > self.receive_connection {
            return Err(refused(
                "flow-control DATA payload exceeds received connection or stream credit".to_owned(),
            ));
        }
        self.receive_connection -= count;
        Ok(())
    }

    pub(super) fn received_data(&mut self, count: usize) -> Result<(), SutError> {
        if !self.receive_valid {
            return Err(refused("flow-control DATA credit is unknown after an invalid authored grant".to_owned()));
        }
        if count == 0 {
            return Ok(());
        }
        let count = i64::try_from(count).unwrap_or(i64::MAX);
        if count > self.receive_connection || count > self.receive_stream {
            return Err(refused(
                "flow-control DATA payload exceeds received connection or stream credit".to_owned(),
            ));
        }
        self.receive_connection -= count;
        self.receive_stream -= count;
        Ok(())
    }
}

fn add(credit: &mut i64, increment: u32) -> Result<(), SutError> {
    let next = *credit + i64::from(increment);
    if next > i64::from(MAX_STREAM_ID) {
        return Err(refused("flow-control WINDOW_UPDATE credit exceeds 31 bits".to_owned()));
    }
    *credit = next;
    Ok(())
}
