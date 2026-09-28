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

//! Responsible for: splitting the peer's octets into frames and folding each received frame into
//! the observation of the selected stream: its head, body and trailers through the HPACK decoder,
//! and the ordered control frames the observation records.
//! NOT responsible for: writing frames, credit arithmetic (`super::flow`), or classifying how the
//! exchange ended (`super::observe`).
//! Upstream: `super::duplex`. Downstream: `super::hpack`, `super::flow`.

use super::*;

/// One frame the peer sent.
#[derive(Debug)]
pub(super) struct PeerFrame {
    pub(super) frame_type: u8,
    pub(super) flags: u8,
    pub(super) stream_id: u32,
    pub(super) payload: Vec<u8>,
}

/// Splits the peer's octets into frames.
#[derive(Debug, Default)]
pub(super) struct FrameReader {
    pub(super) buffered: Vec<u8>,
}

impl FrameReader {
    pub(super) fn take(&mut self) -> Option<PeerFrame> {
        let header = self.buffered.get(..FRAME_HEADER_LEN)?;
        let [l0, l1, l2, frame_type, flags, s0, s1, s2, s3] = <[u8; FRAME_HEADER_LEN]>::try_from(header).ok()?;
        let end = FRAME_HEADER_LEN + usize::try_from(u32::from_be_bytes([0, l0, l1, l2])).ok()?;
        let payload = self.buffered.get(FRAME_HEADER_LEN..end)?.to_vec();
        self.buffered.drain(..end);
        Some(PeerFrame {
            frame_type,
            flags,
            stream_id: u32::from_be_bytes([s0, s1, s2, s3]) & MAX_STREAM_ID,
            payload,
        })
    }
}

/// The response on the script's stream, as far as it arrived.
#[derive(Debug, Default)]
pub(super) struct Response {
    pub(super) status: Option<u16>,
    pub(super) headers: Vec<(String, String)>,
    pub(super) trailers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
    /// Supported control frames actually received, including resets of other streams.
    pub(super) control_frames: Vec<ObservedH2ControlFrame>,
    /// Why reading stopped before the peer ended the stream, when it did.
    pub(super) cut_short: Option<ReadFailure>,
    /// The acknowledgement of the reset barrier PING arrived.
    pub(super) client_reset: bool,
}

pub(super) struct Receiver {
    pub(super) decoder: hpack::Decoder,
    pub(super) response: Response,
    /// An unfinished header block: its stream, the fragments so far, and whether it ends the stream.
    pub(super) open_block: Option<(u32, Vec<u8>, bool)>,
}

impl Receiver {
    pub(super) fn new(script: &Script) -> Self {
        Self {
            decoder: hpack::Decoder::new(script.header_table_size),
            response: Response::default(),
            open_block: None,
        }
    }

    /// Consumes one complete received frame; true means the selected exchange has ended.
    pub(super) fn accept(&mut self, frame: PeerFrame, script: &Script, flow: &mut flow::Flow) -> Result<bool, SutError> {
        let Self {
            decoder,
            response,
            open_block,
        } = self;
        if let Some((block_stream, mut fragment, ends_stream)) = open_block.take() {
            if frame.frame_type != CONTINUATION || frame.stream_id != block_stream {
                return Err(refused(format!(
                    "the peer sent {} on stream {} inside an unfinished header block, which RFC 9113 \
                     section 6.10 forbids",
                    type_name(frame.frame_type),
                    frame.stream_id
                )));
            }
            fragment.extend_from_slice(&frame.payload);
            if frame.flags & END_HEADERS == 0 {
                *open_block = Some((block_stream, fragment, ends_stream));
                return Ok(false);
            }
            if block_stream != script.stream_id {
                discard_block(decoder, &fragment)?;
                return Ok(false);
            }
            accept_block(response, decoder, &fragment)?;
            return Ok(ends_stream);
        }
        match frame.frame_type {
            // Connection management addressed to this client: read, and answered only when the case
            // authored an answer.
            SETTINGS => {
                if frame.stream_id != 0 {
                    return Err(refused("SETTINGS requires stream zero".to_owned()));
                }
                flow.received_settings(&frame.payload, frame.flags)?;
            }
            PING if frame.flags & ACK != 0 && script.observes_pings => {
                let opaque_data = <[u8; 8]>::try_from(frame.payload.as_slice())
                    .ok()
                    .filter(|_| frame.stream_id == 0)
                    .ok_or_else(|| refused("the peer's PING acknowledgement must be eight octets on stream zero".to_owned()))?;
                response.control_frames.push(ObservedH2ControlFrame::PingAck { opaque_data });
                if script.reset_barrier.as_deref() == Some(frame.payload.as_slice()) {
                    response.client_reset = true;
                    return Ok(true);
                }
            }
            // A peer's own PING is read and left unanswered, like SETTINGS; nothing here authors a reply.
            PING | PRIORITY => {}
            WINDOW_UPDATE => {
                let bytes = <[u8; 4]>::try_from(frame.payload.as_slice())
                    .map_err(|_| refused("WINDOW_UPDATE requires exactly four payload octets".to_owned()))?;
                let increment = u32::from_be_bytes(bytes) & MAX_STREAM_ID;
                if increment == 0 {
                    return Err(refused("WINDOW_UPDATE increment must not be zero".to_owned()));
                }
                flow.received_update(frame.stream_id, increment, script.opened.contains(&frame.stream_id))?;
                response.control_frames.push(ObservedH2ControlFrame::WindowUpdate {
                    stream_id: frame.stream_id,
                    increment,
                });
            }
            HEADERS if script.opened.contains(&frame.stream_id) => {
                let fragment = unpadded(&frame)?.to_vec();
                let ends_stream = frame.flags & END_STREAM != 0;
                if frame.flags & END_HEADERS == 0 {
                    *open_block = Some((frame.stream_id, fragment, ends_stream));
                    return Ok(false);
                }
                if frame.stream_id != script.stream_id {
                    discard_block(decoder, &fragment)?;
                    return Ok(false);
                }
                accept_block(response, decoder, &fragment)?;
                if ends_stream {
                    return Ok(true);
                }
            }
            // Another opened stream's body is not observed, but it spends the shared connection credit.
            DATA if frame.stream_id != script.stream_id && script.opened.contains(&frame.stream_id) => {
                unpadded(&frame)?;
                flow.received_other_data(frame.payload.len())?;
            }
            DATA if frame.stream_id == script.stream_id => {
                if response.status.is_none() {
                    return Err(refused(format!(
                        "the peer sent DATA on stream {} before a final response header block",
                        frame.stream_id
                    )));
                }
                flow.received_data(frame.payload.len())?;
                response.body.extend_from_slice(unpadded(&frame)?);
                if frame.flags & END_STREAM != 0 {
                    return Ok(true);
                }
            }
            RST_STREAM => {
                let code = <[u8; 4]>::try_from(frame.payload.as_slice())
                    .map_err(|_| refused("the peer sent RST_STREAM with a payload length other than four octets".to_owned()))?;
                if frame.stream_id == 0 {
                    return Err(refused("the peer sent RST_STREAM on connection stream zero".to_owned()));
                }
                response.control_frames.push(ObservedH2ControlFrame::ResetStream {
                    stream_id: frame.stream_id,
                    error_code: u32::from_be_bytes(code),
                });
                if frame.stream_id == script.stream_id {
                    return Ok(true);
                }
            }
            GOAWAY => {
                if frame.stream_id != 0 || frame.payload.len() < 8 {
                    return Err(refused("GOAWAY requires stream zero and at least eight payload octets".to_owned()));
                }
                let last_stream_id =
                    u32::from_be_bytes([frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3]]) & MAX_STREAM_ID;
                let error_code = u32::from_be_bytes([frame.payload[4], frame.payload[5], frame.payload[6], frame.payload[7]]);
                response.control_frames.push(ObservedH2ControlFrame::GoAway {
                    last_stream_id,
                    error_code,
                });
                // Existing streams can still complete. GOAWAY is not EOF, RST_STREAM, or a status.
                // Debug bytes after the numeric fields carry no assertion and are not retained.
            }
            other => {
                return Err(refused(format!(
                    "the peer sent {} on stream {}, which this reader does not interpret",
                    type_name(other),
                    frame.stream_id
                )));
            }
        }
        Ok(false)
    }
}

/// Decodes a complete header block into the response head, or into its trailers once a head exists.
pub(super) fn accept_block(response: &mut Response, decoder: &mut hpack::Decoder, block: &[u8]) -> Result<(), SutError> {
    let fields = decoder
        .decode(block)
        .map_err(|error| refused(format!("the peer's header block could not be decoded: {error}")))?;
    if response.status.is_some() {
        response.trailers.extend(fields);
        return Ok(());
    }
    let mut fields = fields.into_iter();
    let status = match fields.next() {
        Some((name, value)) if name == ":status" && value.len() == 3 => value.parse::<u16>().ok(),
        _ => None,
    }
    .filter(|status| (100..=599).contains(status))
    .ok_or_else(|| refused("the peer's response header block does not begin with a valid :status".to_owned()))?;
    // An interim response; the final one follows on the same stream.
    if status < 200 {
        return Ok(());
    }
    response.status = Some(status);
    response.headers = fields.collect();
    Ok(())
}

/// Decompresses another stream's header block for the shared dynamic table, and discards it.
pub(super) fn discard_block(decoder: &mut hpack::Decoder, block: &[u8]) -> Result<(), SutError> {
    decoder
        .decode(block)
        .map(drop)
        .map_err(|error| refused(format!("the peer's header block could not be decoded: {error}")))
}

/// A DATA or HEADERS payload without its padding and priority fields (RFC 9113 sections 6.1, 6.2).
pub(super) fn unpadded(frame: &PeerFrame) -> Result<&[u8], SutError> {
    let malformed = || {
        refused(format!(
            "the peer's {} frame on stream {} is shorter than its padding or priority fields",
            type_name(frame.frame_type),
            frame.stream_id
        ))
    };
    let mut payload = frame.payload.as_slice();
    let mut padding = 0_usize;
    if frame.flags & PADDED != 0 {
        let (&length, rest) = payload.split_first().ok_or_else(malformed)?;
        padding = usize::from(length);
        payload = rest;
    }
    if frame.frame_type == HEADERS && frame.flags & PRIORITY_FLAG != 0 {
        payload = payload.get(5..).ok_or_else(malformed)?;
    }
    payload
        .len()
        .checked_sub(padding)
        .and_then(|end| payload.get(..end))
        .ok_or_else(malformed)
}
