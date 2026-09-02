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

//! Responsible for: the on-disk corpus layout, the generated `MANIFEST.toml`, the closed
//! provenance allowlist, the size ceilings, and the whole-corpus verification pass.
//! Not responsible for: deciding what is safe (`redact`) or what is a duplicate (`dedup`).
//! Upstream: buckets from `dedup`, entries from `schema`.
//! Downstream: the `corpus` binary and `scripts/check_corpus_*.sh`.
//!
//! Verification deliberately re-renders the manifest and compares it byte for byte with
//! the file on disk instead of parsing it. A generated artefact that is only ever parsed
//! can drift from its generator in every field the parser ignores; one that is regenerated
//! cannot drift at all, and the comparison needs no second implementation to be trusted.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::Digest;
use sha2::Sha256;

use crate::base64;
use crate::dedup::Bucket;
use crate::redact;
use crate::schema::{self, Entry};

/// The manifest file name, relative to the corpus root.
pub const MANIFEST_FILE: &str = "MANIFEST.toml";

/// Size the corpus is designed to stay under, in bytes.
pub const SOFT_SIZE_LIMIT_BYTES: u64 = 20 * 1024 * 1024;

/// Size the corpus may never exceed, in bytes.
pub const HARD_SIZE_LIMIT_BYTES: u64 = 50 * 1024 * 1024;

/// Provenance prefixes the corpus accepts, and whether the prefix must be followed by a
/// pinned revision.
///
/// Zero production traffic is a hard constraint, and this is where it is enforced: a
/// source is admissible only if it names one of these synthetic suites. There is
/// deliberately no wildcard and no "other" row — an unrecognised source is a refusal, so
/// adding a recording source is a reviewed edit to this table rather than a spelling.
pub const SOURCE_ALLOWLIST: &[(&str, bool)] = &[
    ("client-matrix:", true),
    ("fuzz:", false),
    // Hand-authored in this repository. Separate from `handwritten:s3s-issues` because the
    // two have different review obligations: an issue-derived entry has to be traceable to
    // the issue it came from, and one written here does not exist anywhere else.
    ("handwritten:gateway", false),
    ("handwritten:s3s-issues", false),
    ("mint@", false),
    ("minio-interop@", false),
    ("s3-tests@", false),
];

/// Whether `src` names an allowed synthetic recording source.
pub fn check_source(src: &str) -> Result<(), String> {
    for (prefix, needs_revision) in SOURCE_ALLOWLIST {
        let matched = if prefix.ends_with([':', '@']) {
            src.starts_with(prefix)
        } else {
            src == *prefix
        };
        if !matched {
            continue;
        }
        if *needs_revision && !src[prefix.len()..].contains('@') {
            return Err(format!("source `{src}` names no pinned revision after `@`"));
        }
        return Ok(());
    }
    Err(format!(
        "source `{src}` is not in the allowlist; the corpus admits synthetic test suites only, never production traffic"
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    base64::to_hex(&hasher.finalize())
}

/// Render the manifest for a set of buckets whose files hold `rendered` bytes.
///
/// The manifest is the corpus's version record: schema version, per-bucket counts with a
/// content hash, and the provenance census. It is generated, never hand-edited.
pub fn render_manifest(buckets: &[Bucket]) -> String {
    let mut sources: BTreeMap<&str, usize> = BTreeMap::new();
    let mut total_entries = 0usize;
    let mut total_bytes = 0usize;
    let mut rows = String::new();

    let mut ordered: Vec<&Bucket> = buckets.iter().filter(|bucket| !bucket.entries.is_empty()).collect();
    ordered.sort_by_key(|bucket| bucket.relative_path());

    for bucket in &ordered {
        let body = schema::render_jsonl(&bucket.entries);
        total_entries += bucket.entries.len();
        total_bytes += body.len();
        for entry in &bucket.entries {
            *sources.entry(entry.src.as_str()).or_default() += 1;
        }
        rows.push_str(&format!(
            "\n[[bucket]]\npath = \"{}\"\nop = \"{}\"\nfamily = \"{}\"\nentries = {}\nchunked = {}\ntrailers = {}\nbytes = {}\nsha256 = \"{}\"\n",
            bucket.relative_path(),
            bucket.op,
            bucket.family,
            bucket.entries.len(),
            bucket.chunked(),
            bucket.trailers(),
            body.len(),
            sha256_hex(body.as_bytes()),
        ));
    }

    let mut out = String::new();
    out.push_str("# @generated by `cargo run -p rustfs-gateway-corpus --bin corpus -- ingest`; do not edit.\n");
    out.push_str("# Regenerate and review in an explicit pull request: a corpus change changes every\n");
    out.push_str("# differential result computed from it, so it is never an automatic commit.\n");
    out.push_str(&format!("schema_version = {}\n", schema::CORPUS_SCHEMA_VERSION));
    out.push_str(&format!("buckets = {}\n", ordered.len()));
    out.push_str(&format!("entries = {total_entries}\n"));
    out.push_str(&format!("bytes = {total_bytes}\n"));
    out.push_str(&format!(
        "chunk_framed_entries = {}\n",
        ordered.iter().map(|bucket| bucket.chunked()).sum::<usize>()
    ));
    out.push_str(&rows);
    for (src, count) in sources {
        out.push_str(&format!("\n[[source]]\nid = \"{src}\"\nentries = {count}\n"));
    }
    out
}

/// Write every non-empty bucket plus the manifest under `root`, replacing what is there.
pub fn write(root: &Path, buckets: &[Bucket]) -> io::Result<()> {
    for bucket in buckets {
        if bucket.entries.is_empty() {
            continue;
        }
        let path = root.join(bucket.relative_path());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, schema::render_jsonl(&bucket.entries))?;
    }
    fs::create_dir_all(root)?;
    fs::write(root.join(MANIFEST_FILE), render_manifest(buckets))
}

/// Every `*.jsonl` file under `root`, sorted by relative path.
pub fn bucket_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(listing) = fs::read_dir(&directory) else {
            continue;
        };
        for item in listing {
            let path = item?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "jsonl") {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// What a verification pass measured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Bucket files read.
    pub buckets: usize,
    /// Entries loaded.
    pub entries: usize,
    /// Entries carrying aws-chunked framing.
    pub chunk_framed: usize,
    /// Distinct provenance sources.
    pub sources: usize,
    /// Total bytes under the corpus root.
    pub bytes: u64,
}

/// Load, admit and cross-check the whole corpus under `root`.
///
/// Returns every violation rather than the first, because a corpus with three problems
/// costs three verification cycles when the reporter stops at one. An empty corpus is
/// reported as such by the caller; it is not a violation here.
pub fn verify(root: &Path) -> Result<VerifyReport, Vec<String>> {
    let mut violations = Vec::new();
    let mut report = VerifyReport::default();
    let mut buckets: Vec<Bucket> = Vec::new();

    let files = match bucket_files(root) {
        Ok(files) => files,
        Err(error) => return Err(vec![format!("cannot enumerate {}: {error}", root.display())]),
    };

    let mut sources: BTreeMap<String, usize> = BTreeMap::new();
    for path in &files {
        let display = path.strip_prefix(root).unwrap_or(path).display().to_string();
        report.buckets += 1;
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                violations.push(format!("{display}: cannot read: {error}"));
                continue;
            }
        };
        report.bytes += text.len() as u64;
        let entries = match schema::load_jsonl(&text) {
            Ok(entries) => entries,
            Err(error) => {
                violations.push(format!("{display}:{error}"));
                continue;
            }
        };
        let expected_op = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        for (index, entry) in entries.iter().enumerate() {
            let line = index + 1;
            if entry.op != expected_op {
                violations.push(format!("{display}:{line}: entry op `{}` does not match the file name", entry.op));
            }
            if let Err(reason) = check_source(&entry.src) {
                violations.push(format!("{display}:{line}: {reason}"));
            }
            if let Err(refusal) = redact::admit(entry) {
                for finding in refusal.findings {
                    violations.push(format!("{display}:{line}: {finding}"));
                }
            }
            *sources.entry(entry.src.clone()).or_default() += 1;
            if entry.has_chunk_framing() {
                report.chunk_framed += 1;
            }
        }
        report.entries += entries.len();
        buckets.push(Bucket {
            family: crate::dedup::family_of(&expected_op),
            op: expected_op,
            entries,
            unique: 0,
            over_cap: 0,
        });
    }
    report.sources = sources.len();

    let manifest_path = root.join(MANIFEST_FILE);
    let expected = render_manifest(&buckets);
    match fs::read_to_string(&manifest_path) {
        Ok(actual) if actual == expected => {}
        Ok(_) => violations.push(format!(
            "{MANIFEST_FILE} does not match the corpus on disk; regenerate it with `corpus ingest`"
        )),
        Err(error) => violations.push(format!("{MANIFEST_FILE}: cannot read: {error}")),
    }
    report.bytes += expected.len() as u64;

    if report.bytes > HARD_SIZE_LIMIT_BYTES {
        violations.push(format!(
            "corpus is {} bytes, over the {HARD_SIZE_LIMIT_BYTES}-byte hard ceiling; lower the per-bucket cap or move the full capture to a CI artifact",
            report.bytes
        ));
    }

    if violations.is_empty() { Ok(report) } else { Err(violations) }
}

/// Every duplicate-free entry currently stored under `root`.
pub fn load_all(root: &Path) -> Result<Vec<Entry>, String> {
    let mut all = Vec::new();
    for path in bucket_files(root).map_err(|error| format!("cannot enumerate {}: {error}", root.display()))? {
        let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let entries = schema::load_jsonl(&text).map_err(|error| format!("{}:{error}", path.display()))?;
        all.extend(entries);
    }
    Ok(all)
}
