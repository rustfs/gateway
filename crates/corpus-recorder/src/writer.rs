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

//! Responsible for: the bounded hand-off from the request path to one writer thread, and the
//! writer thread itself — which builds each corpus entry, runs the corpus crate's fail-closed
//! redaction gate on it, and appends only an admitted entry to the JSONL file.
//! Not responsible for: observing requests (`layer`, `body`) or deciding what is a secret
//! (`rustfs_gateway_corpus::redact`, reused rather than reimplemented).
//! Upstream: `body::Capture`, when its last holder drops.
//! Downstream: the output JSONL file, read by `corpus ingest`.
//!
//! Nothing here ever blocks a request. A full queue is a counted, dropped record — the entry is
//! lost, the request is not slowed — and nothing reaches the disk before the gate admits it.

use std::fs::File;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};

use rustfs_gateway_corpus::base64;
use rustfs_gateway_corpus::redact;
use rustfs_gateway_corpus::schema::{self, Capture, Chunk, Entry, Response, Sut};

/// Everything observed about one request, before it is an entry.
pub(crate) struct RawRecord {
    pub(crate) op: &'static str,
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    /// The whole request body as the inner service received it, or `None` when the whole body
    /// was not observed.
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) response: Option<ResponseHead>,
}

/// A response status and its header pairs.
pub(crate) type ResponseHead = (u16, Vec<(String, String)>);

/// What a recorder has done so far. Every request the layer saw lands in exactly one of the
/// outcome counters once its record is finished.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecorderStats {
    /// Entries admitted by the redaction gate and appended to the output.
    pub recorded: u64,
    /// Entries the redaction gate refused after sanitizing. Nothing of them was written.
    pub refused: u64,
    /// Records dropped because the writer queue was full.
    pub dropped_queue_full: u64,
    /// Requests the route table could not name an operation for; passed through unrecorded.
    pub unrouted: u64,
    /// Requests whose head was not representable as text; passed through unrecorded.
    pub unrepresentable_head: u64,
    /// Requests whose whole body was not observed: it exceeded a cap, or the inner service
    /// stopped reading before its end. Written without a body when the head declares none, and
    /// not written at all when it declares one, since that entry would claim a body nobody
    /// measured.
    pub body_not_recorded: u64,
    /// Admitted entries that failed to reach the file.
    pub write_errors: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    recorded: AtomicU64,
    refused: AtomicU64,
    dropped_queue_full: AtomicU64,
    pub(crate) unrouted: AtomicU64,
    pub(crate) unrepresentable_head: AtomicU64,
    pub(crate) body_not_recorded: AtomicU64,
    write_errors: AtomicU64,
}

impl Counters {
    pub(crate) fn read(&self) -> RecorderStats {
        RecorderStats {
            recorded: self.recorded.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed),
            unrouted: self.unrouted.load(Ordering::Relaxed),
            unrepresentable_head: self.unrepresentable_head.load(Ordering::Relaxed),
            body_not_recorded: self.body_not_recorded.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
        }
    }
}

/// The request-path end of the writer: a bounded queue, the counters, and the in-flight budget.
pub(crate) struct Sink {
    sender: SyncSender<RawRecord>,
    pub(crate) counters: Arc<Counters>,
    pub(crate) max_body_bytes: usize,
    max_in_flight_bytes: usize,
    in_flight_bytes: AtomicUsize,
}

impl Sink {
    /// Starts the writer thread over `file` and returns the request-path end.
    pub(crate) fn start(
        file: File,
        src: String,
        sut: Sut,
        queue_capacity: usize,
        max_body_bytes: usize,
        max_in_flight_bytes: usize,
    ) -> std::io::Result<Arc<Self>> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
        let counters = Arc::new(Counters::default());
        let thread_counters = Arc::clone(&counters);
        std::thread::Builder::new()
            .name("corpus-recorder".to_owned())
            .spawn(move || run(receiver, file, &src, sut, &thread_counters))?;
        Ok(Arc::new(Self {
            sender,
            counters,
            max_body_bytes,
            max_in_flight_bytes,
            in_flight_bytes: AtomicUsize::new(0),
        }))
    }

    /// Reserves `bytes` of the shared in-flight budget, or refuses without reserving anything.
    pub(crate) fn reserve(&self, bytes: usize) -> bool {
        let mut current = self.in_flight_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes).filter(|next| *next <= self.max_in_flight_bytes) else {
                return false;
            };
            match self
                .in_flight_bytes
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Returns `bytes` to the shared in-flight budget.
    pub(crate) fn release(&self, bytes: usize) {
        self.in_flight_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// Hands a finished record to the writer without waiting. A full queue drops the record and
    /// counts it: the request has already been served and must not be slowed by recording.
    pub(crate) fn submit(&self, record: RawRecord) {
        match self.sender.try_send(record) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.counters.dropped_queue_full.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn run(receiver: Receiver<RawRecord>, mut file: File, src: &str, sut: Sut, counters: &Counters) {
    while let Ok(record) = receiver.recv() {
        let mut entry = entry_of(record, src, sut, &today());
        let _ = redact::sanitize(&mut entry);
        if redact::admit(&entry).is_err() {
            // The refusal names where the credential material was, and so is never logged here.
            counters.refused.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let line = schema::render_jsonl(std::slice::from_ref(&entry));
        match file.write_all(line.as_bytes()).and_then(|()| file.flush()) {
            Ok(()) => counters.recorded.fetch_add(1, Ordering::Relaxed),
            Err(_) => counters.write_errors.fetch_add(1, Ordering::Relaxed),
        };
    }
}

/// Builds the corpus entry for one record. The body becomes a single data chunk without a
/// delay: a passive tap sees when the service pulled bytes, not when the client sent them, so
/// it claims neither frame boundaries nor timing.
pub(crate) fn entry_of(record: RawRecord, src: &str, sut: Sut, recorded: &str) -> Entry {
    let chunks = record.body.filter(|body| !body.is_empty()).map(|body| {
        vec![Chunk::Data {
            bytes_b64: base64::encode(&body),
            delay_ms: None,
        }]
    });
    Entry {
        v: schema::CORPUS_SCHEMA_VERSION,
        op: record.op.to_owned(),
        src: src.to_owned(),
        recorded: recorded.to_owned(),
        capture: Capture::HeadFull,
        sut,
        method: record.method,
        target: record.target,
        headers: record.headers,
        chunks,
        resp: record.response.map(|(status, headers)| Response {
            status,
            headers,
            body_b64: None,
        }),
        redacted: Vec::new(),
    }
}

/// Today's UTC date as `YYYY-MM-DD`, read from the one wall clock the gateway allows.
fn today() -> String {
    let seconds = rustfs_gateway::RequestNow::capture().unix_seconds().max(0);
    civil_date(seconds.unsigned_abs() / 86_400)
}

/// The proleptic Gregorian date `days` after 1970-01-01 (Howard Hinnant's civil-from-days).
pub(crate) fn civil_date(days: u64) -> String {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::civil_date;

    #[test]
    fn civil_dates_cross_leap_years_and_the_epoch() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_724), "2026-09-28");
    }
}
