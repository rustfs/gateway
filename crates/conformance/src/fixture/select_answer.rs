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

//! The event stream the canonical fixture answers a select with.
//!
//! Responsible for: choosing between the production [`frame_records`] adapter and the two shapes
//! it does not write — a requested progress report with a keep-alive, and an in-band
//! `InvalidTextEncoding` error for a text scan that is not UTF-8 — and framing those by hand with
//! [`EventSequence`]. NOT responsible for: validating the request or scanning the object, which the
//! handler does first; or evaluating SQL, which no fixture does.
//! Upstream: the fixture's `select_object_content` handler. Downstream: `Resp::event_stream`.

use rustfs_gateway::dto;
use rustfs_gateway::{ByteStream, EventSequence, frame_records, progress_document, stats_document};

/// The answer to a validated select over the scanned bytes `selected`.
pub(super) fn answer(input: &dto::SelectObjectContentInput, selected: &[u8]) -> ByteStream {
    let progress = input
        .request_progress
        .as_ref()
        .and_then(|progress| progress.enabled)
        .unwrap_or(false);
    let text = input.input_serialization.csv.is_some() || input.input_serialization.json.is_some();
    let readable = if text {
        core::str::from_utf8(selected).map_or_else(|error| error.valid_up_to(), str::len)
    } else {
        selected.len()
    };
    if !progress && readable == selected.len() {
        // Framed lazily by the production adapter: one message per read, never the whole answer.
        let records = ByteStream::from_bytes(bytes::Bytes::copy_from_slice(selected));
        return frame_records(records);
    }
    ByteStream::from_bytes(bytes::Bytes::from(framed_select_by_hand(selected, readable, progress)))
}

/// A select answer framed with [`EventSequence`] for the two shapes [`frame_records`] does not write.
///
/// With `progress`, a `Cont` keep-alive leads and a `Progress` follows the records, both before the
/// accounting. When `readable` stops short of the scanned bytes, the readable prefix is sent and
/// the stream ends with an `InvalidTextEncoding` error frame: the status line has already said
/// `200`, so the failure can only travel in-band, and no `End` follows it. Every call below is
/// legal in the phase it is made from and within every ceiling; a refusal would be a framing bug,
/// answered with an in-band `InternalError` rather than a hung client.
fn framed_select_by_hand(selected: &[u8], readable: usize, progress: bool) -> Vec<u8> {
    let count = readable as u64;
    let mut frames = Vec::new();
    let mut sequence = EventSequence::new();
    let mut framed = || -> Result<(), rustfs_gateway::EventStreamError> {
        if progress {
            sequence.cont(&mut frames)?;
        }
        if readable > 0 || readable == selected.len() {
            sequence.records(selected.get(..readable).unwrap_or_default(), &mut frames)?;
        }
        if readable < selected.len() {
            return sequence.exception("InvalidTextEncoding", "The scanned object bytes are not valid UTF-8 text", &mut frames);
        }
        if progress {
            sequence.progress(&progress_document(count, count, count), &mut frames)?;
        }
        sequence.stats(&stats_document(count, count, count), &mut frames)?;
        sequence.end(&mut frames)
    };
    if framed().is_err() && !sequence.is_terminated() {
        let _ = sequence.exception("InternalError", "The select answer could not be framed", &mut frames);
    }
    frames
}
