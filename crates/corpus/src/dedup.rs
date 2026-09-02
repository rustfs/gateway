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

//! Responsible for: the value-free request fingerprint, per-operation bucketing, and the
//! retention rule that keeps a bucket under its cap without discarding rare shapes.
//! Not responsible for: proving an entry safe (`redact`), writing files (`store`), or
//! converting to a conformance case (`case`).
//! Upstream: `schema::Entry` values already admitted by `redact`.
//! Downstream: `store` and the `corpus` binary.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;

use sha2::Digest;
use sha2::Sha256;

use crate::base64;
use crate::schema::{Chunk, Entry};

/// Default number of entries retained per operation bucket.
pub const DEFAULT_BUCKET_CAP: usize = 200;

/// How a request framed its payload. Bucketing records this because client diversity does
/// not imply signing diversity: four SDKs can all send a plain `x-amz-content-sha256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Framing {
    /// No aws-chunked framing at all.
    Plain,
    /// A streaming payload mode or the `aws-chunked` content coding, without a trailer.
    AwsChunked,
    /// aws-chunked framing that also declares `x-amz-trailer`.
    AwsChunkedTrailer,
}

impl Framing {
    /// Classify one entry.
    pub fn of(entry: &Entry) -> Self {
        if !entry.has_chunk_framing() {
            Self::Plain
        } else if entry.has_trailer() {
            Self::AwsChunkedTrailer
        } else {
            Self::AwsChunked
        }
    }

    /// The manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::AwsChunked => "aws-chunked",
            Self::AwsChunkedTrailer => "aws-chunked+trailer",
        }
    }
}

/// The order-of-magnitude bucket of a payload length.
///
/// A length is structure, not a value: a zero-byte PUT and a 9 MB PUT exercise different
/// code, while 5,000,001 and 5,000,002 bytes do not.
fn length_class(length: usize) -> u32 {
    usize::BITS - length.leading_zeros()
}

/// The value-free fingerprint of a request, as lowercase hex SHA-256.
///
/// What goes in is shape: the operation, the method, how many path segments there were,
/// which query parameters and headers were present, and the framing of the body. What
/// stays out is every value — bucket names, keys, upload ids, dates, signatures and
/// payload bytes. Hashing values would make each randomly named test bucket a new entry
/// and defeat deduplication entirely, which is the failure this function exists to avoid.
pub fn fingerprint(entry: &Entry) -> String {
    let mut hasher = Sha256::new();
    let mut field = |label: &str, value: &str| {
        hasher.update(label.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(value.as_bytes());
        hasher.update(b"\x1e");
    };

    field("op", &entry.op);
    field("method", &entry.method);
    field(
        "capture",
        if entry.capture == crate::schema::Capture::HeadFull {
            "full"
        } else {
            "partial"
        },
    );

    let path = entry.path();
    let segments = path.split('/').filter(|segment| !segment.is_empty()).count();
    field("path_segments", &segments.to_string());
    field("path_trailing_slash", if path.ends_with('/') { "1" } else { "0" });

    let query_names: BTreeSet<String> = entry
        .query()
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').map_or(part, |(name, _)| name).to_ascii_lowercase())
        .collect();
    field("query_names", &query_names.into_iter().collect::<Vec<_>>().join(","));

    let header_names: BTreeSet<String> = entry.headers.iter().map(|(name, _)| name.to_ascii_lowercase()).collect();
    field("header_names", &header_names.into_iter().collect::<Vec<_>>().join(","));

    field("framing", Framing::of(entry).as_str());

    let mut body = String::new();
    if let Some(chunks) = &entry.chunks {
        for chunk in chunks {
            match chunk {
                Chunk::Data { bytes_b64, delay_ms } => {
                    let length = base64::decode(bytes_b64).map_or(bytes_b64.len(), |bytes| bytes.len());
                    body.push_str(&format!("d{}:{};", length_class(length), delay_ms.unwrap_or(0)));
                }
                Chunk::Control {
                    action,
                    delay_ms,
                    duration_ms,
                } => {
                    body.push_str(&format!("c{action}:{}:{};", delay_ms.unwrap_or(0), duration_ms.unwrap_or(0)));
                }
            }
        }
    }
    field("body", &body);
    field("status", &entry.resp.as_ref().map_or_else(String::new, |resp| resp.status.to_string()));

    base64::to_hex(&hasher.finalize())
}

/// The directory a bucket is stored under.
///
/// A closed table with an explicit `other` fallback: an operation nobody classified lands
/// somewhere visible rather than being dropped or silently renamed.
pub fn family_of(op: &str) -> &'static str {
    // Ordered: the first match wins, so `Buckets` must be tried before `Bucket` and every
    // multipart spelling before either. A table whose rows commute would be a table whose
    // classification depends on iteration order.
    const TABLE: &[(&str, &str)] = &[
        ("MultipartUpload", "multipart"),
        ("Part", "multipart"),
        ("Buckets", "service"),
        ("Bucket", "bucket"),
        ("Object", "object"),
    ];
    for (needle, family) in TABLE {
        if op.contains(needle) {
            return family;
        }
    }
    "other"
}

/// One operation's retained entries.
#[derive(Debug, Clone)]
pub struct Bucket {
    /// The AWS operation name.
    pub op: String,
    /// The family directory this bucket is stored under.
    pub family: &'static str,
    /// Retained entries, in first-seen order within each retention pass.
    pub entries: Vec<Entry>,
    /// How many distinct fingerprints this operation produced before the cap applied.
    pub unique: usize,
    /// How many unique entries were dropped because the bucket was full.
    pub over_cap: usize,
}

impl Bucket {
    /// Retained entries carrying aws-chunked framing.
    pub fn chunked(&self) -> usize {
        self.entries.iter().filter(|entry| entry.has_chunk_framing()).count()
    }

    /// Retained entries declaring a trailing-header set.
    pub fn trailers(&self) -> usize {
        self.entries.iter().filter(|entry| entry.has_trailer()).count()
    }

    /// The bucket's file path relative to the corpus root.
    pub fn relative_path(&self) -> String {
        format!("{}/{}.jsonl", self.family, self.op)
    }
}

/// What one bucketing pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DedupReport {
    /// Entries offered.
    pub seen: usize,
    /// Entries retained.
    pub retained: usize,
    /// Entries dropped because an identical fingerprint was already retained.
    pub duplicates: usize,
    /// Entries dropped because their bucket was already at its cap.
    pub over_cap: usize,
}

/// The sorted, deduplicated set of header names on an entry.
fn header_class(entry: &Entry) -> Vec<String> {
    let mut names: Vec<String> = entry.headers.iter().map(|(name, _)| name.to_ascii_lowercase()).collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Deduplicate by fingerprint, bucket by operation, and cap each bucket.
///
/// Retention is three-pass and deterministic, coarsest class first. Pass one keeps the
/// first entry of each **framing** class; pass two the first of each
/// `(framing, header-name set)` class; pass three fills whatever capacity is left in
/// first-seen order.
///
/// The order is the whole point. Header-set diversity is cheap — every request with a
/// different `x-amz-meta-*` key is a new header set — and framing diversity is not: across
/// 346 real four-client requests only restic's minio-go emitted a streaming payload mode
/// at all. Ranking header diversity first lets fifty cosmetic variations evict the one
/// entry that carries chunk framing, which is the coverage this corpus exists to hold.
pub fn bucketize(entries: Vec<Entry>, cap: usize) -> (Vec<Bucket>, DedupReport) {
    let mut report = DedupReport {
        seen: entries.len(),
        ..DedupReport::default()
    };
    let mut grouped: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
    let mut seen_fingerprints: HashSet<String> = HashSet::new();

    for entry in entries {
        if seen_fingerprints.insert(fingerprint(&entry)) {
            grouped.entry(entry.op.clone()).or_default().push(entry);
        } else {
            report.duplicates += 1;
        }
    }

    let mut buckets = Vec::new();
    for (op, unique_entries) in grouped {
        let unique = unique_entries.len();
        let mut retained: Vec<Entry> = Vec::new();
        let mut taken = vec![false; unique_entries.len()];
        let mut framing_classes: HashSet<Framing> = HashSet::new();
        let mut header_classes: HashSet<(Framing, Vec<String>)> = HashSet::new();

        for pass in 0..3u8 {
            for (index, entry) in unique_entries.iter().enumerate() {
                if retained.len() >= cap {
                    break;
                }
                if taken[index] {
                    continue;
                }
                let wanted = match pass {
                    0 => framing_classes.insert(Framing::of(entry)),
                    1 => header_classes.insert((Framing::of(entry), header_class(entry))),
                    _ => true,
                };
                if wanted {
                    // Recorded whichever pass took it, so a later pass cannot spend
                    // capacity on a class an earlier one already covered.
                    framing_classes.insert(Framing::of(entry));
                    header_classes.insert((Framing::of(entry), header_class(entry)));
                    retained.push(entry.clone());
                    taken[index] = true;
                }
            }
        }

        let over_cap = unique - retained.len();
        report.retained += retained.len();
        report.over_cap += over_cap;
        buckets.push(Bucket {
            family: family_of(&op),
            op,
            entries: retained,
            unique,
            over_cap,
        });
    }

    (buckets, report)
}
