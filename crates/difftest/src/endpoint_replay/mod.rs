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

//! Out-of-process HTTP/1.1 replay of `decode_diff` and `encode_diff` fuzz corpora against a live
//! RustFS candidate `--endpoint` (rustfs/backlog#2781).
//!
//! Responsible for: parsing the replay command line, loading and deduplicating raw libFuzzer
//! corpus/seed files, translating each `decode_diff` or `encode_diff` corpus entry into real TCP
//! HTTP/1.1 exchanges against the live candidate, detecting candidate crashes, hangs, malformed
//! HTTP/XML answers, and unexpected 5xx responses, checking endpoint liveness, and writing
//! redacted crash artifacts for failed inputs.
//! NOT responsible for: in-process differential comparison (`decode.rs`, `encode.rs`), libFuzzer
//! generation (`fuzz/fuzz_targets/*.rs`), or raw TCP framing (`http_client.rs`).
//! Upstream: `fuzz.rs`, `sign.rs`, `endpoint_replay/http_client.rs`.
//! Downstream: `src/bin/fuzz-endpoint-replay.rs`, `.github/workflows/fuzz-nightly.yml`.

mod encode;
mod http_client;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustfs_gateway::{MonotonicClock, SystemMonotonic};
use sha2::{Digest as _, Sha256};

use self::encode::replay_encode_diff;
use self::http_client::{HttpResponse, preview_body, send_http_request};
use crate::corpus::PRESIGN_PARAMETERS;
use crate::fuzz::request_of;
use crate::request::RawRequest;
use crate::sign::signed_with;

pub use self::http_client::Endpoint;

/// Every corpus input was replayed over HTTP and the live candidate survived cleanly.
pub const EXIT_PASSED: u8 = 0;
/// At least one input crashed, hung, returned an unexpected 5xx, or broke HTTP/XML framing.
pub const EXIT_FAILURE: u8 = 1;
/// Invalid CLI arguments, missing/empty corpus, or an unreachable endpoint before replay started.
pub const EXIT_ENVIRONMENT: u8 = 2;

const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_REGION: &str = "us-east-1";
const DEFAULT_BUCKET: &str = "fuzz-encode-diff";

const USAGE: &str = "usage: fuzz-endpoint-replay --endpoint http://HOST[:PORT] \
    --target (decode_diff|encode_diff) --corpus-dir DIR [--corpus-dir DIR ...] \
    [--access-key KEY --secret-key SECRET] [--region REGION] [--bucket NAME] \
    [--artifacts-dir DIR] [--timeout-ms MS] [--health-path PATH] [--max-inputs N]";

/// Which fuzz target's corpus format is replayed against the live endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Raw HTTP-like request inputs parsed by [`crate::fuzz::request_of`].
    DecodeDiff,
    /// NUL-delimited listing/head answer inputs parsed by [`crate::fuzz::outputs_of`].
    EncodeDiff,
}

impl Target {
    /// Parses a target name (`decode_diff` or `encode_diff`).
    ///
    /// # Errors
    ///
    /// An unknown target name.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "decode_diff" => Ok(Self::DecodeDiff),
            "encode_diff" => Ok(Self::EncodeDiff),
            other => Err(format!("unknown --target {other:?}; expected decode_diff or encode_diff")),
        }
    }

    /// The canonical fuzz target name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DecodeDiff => "decode_diff",
            Self::EncodeDiff => "encode_diff",
        }
    }
}

/// Optional SigV4 credentials used to sign replayed requests against the live candidate.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Access key id.
    pub access_key: String,
    secret_key: String,
    /// Signing region.
    pub region: String,
}

impl Credentials {
    /// Creates signing credentials for the replay endpoint.
    #[must_use]
    pub fn new(access_key: impl Into<String>, secret_key: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            region: region.into(),
        }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("region", &self.region)
            .finish()
    }
}

/// Parsed command-line options for [`run`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Base `http://host[:port]` URL of the external candidate under test.
    pub endpoint: String,
    /// Corpus format to replay.
    pub target: Target,
    /// Directories searched recursively for corpus/seed files.
    pub corpus_dirs: Vec<PathBuf>,
    /// Optional SigV4 credentials for authenticated replay requests.
    pub credentials: Option<Credentials>,
    /// Scratch bucket name used by `encode_diff` replay.
    pub bucket: String,
    /// Optional directory where crashing inputs and redacted diagnostics are written.
    pub artifacts_dir: Option<PathBuf>,
    /// Per-request TCP connect, read, and write timeout.
    pub timeout: Duration,
    /// Optional health-check path (such as `/health/ready`) probed before and after replay.
    pub health_path: Option<String>,
    /// Optional upper bound on unique corpus inputs replayed.
    pub max_inputs: Option<usize>,
}

impl Options {
    /// Parses command-line arguments after the program name.
    ///
    /// # Errors
    ///
    /// A usage diagnostic when required options are absent or malformed.
    pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut endpoint = None;
        let mut target = None;
        let mut corpus_dirs = Vec::new();
        let mut access_key = None;
        let mut secret_key = None;
        let mut region = DEFAULT_REGION.to_owned();
        let mut bucket = DEFAULT_BUCKET.to_owned();
        let mut artifacts_dir = None;
        let mut timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);
        let mut health_path = None;
        let mut max_inputs = None;

        let mut args = arguments.into_iter();
        while let Some(arg) = args.next() {
            let mut next_value = |flag: &str| args.next().ok_or_else(|| format!("{flag} needs a value\n{USAGE}"));
            match arg.as_str() {
                "--endpoint" => endpoint = Some(next_value("--endpoint")?),
                "--target" => {
                    let raw = next_value("--target")?;
                    target = Some(Target::parse(&raw).map_err(|error| format!("{error}\n{USAGE}"))?);
                }
                "--corpus-dir" => corpus_dirs.push(PathBuf::from(next_value("--corpus-dir")?)),
                "--access-key" => access_key = Some(next_value("--access-key")?),
                "--secret-key" => secret_key = Some(next_value("--secret-key")?),
                "--region" => region = next_value("--region")?,
                "--bucket" => bucket = next_value("--bucket")?,
                "--artifacts-dir" => artifacts_dir = Some(PathBuf::from(next_value("--artifacts-dir")?)),
                "--timeout-ms" => {
                    let raw = next_value("--timeout-ms")?;
                    let ms: u64 = raw
                        .parse()
                        .map_err(|_| format!("--timeout-ms {raw:?} is not a positive millisecond count\n{USAGE}"))?;
                    if ms == 0 {
                        return Err(format!("--timeout-ms must be greater than zero\n{USAGE}"));
                    }
                    timeout = Duration::from_millis(ms);
                }
                "--health-path" => {
                    let path = next_value("--health-path")?;
                    if !path.starts_with('/') {
                        return Err(format!("--health-path {path:?} must start with '/'\n{USAGE}"));
                    }
                    health_path = Some(path);
                }
                "--max-inputs" => {
                    let raw = next_value("--max-inputs")?;
                    let count: usize = raw
                        .parse()
                        .map_err(|_| format!("--max-inputs {raw:?} is not a positive count\n{USAGE}"))?;
                    if count == 0 {
                        return Err(format!("--max-inputs must be greater than zero\n{USAGE}"));
                    }
                    max_inputs = Some(count);
                }
                other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
            }
        }

        let endpoint = endpoint.ok_or_else(|| format!("--endpoint is required\n{USAGE}"))?;
        let target = target.ok_or_else(|| format!("--target is required\n{USAGE}"))?;
        if corpus_dirs.is_empty() {
            return Err(format!("at least one --corpus-dir is required\n{USAGE}"));
        }
        let credentials = match (access_key, secret_key) {
            (Some(access), Some(secret)) => {
                if access.is_empty() || secret.is_empty() {
                    return Err(format!("--access-key and --secret-key must be non-empty\n{USAGE}"));
                }
                Some(Credentials::new(access, secret, region))
            }
            (None, None) => None,
            _ => return Err(format!("--access-key and --secret-key must be supplied together\n{USAGE}")),
        };
        if bucket.is_empty() || bucket.contains('/') || bucket.contains('?') {
            return Err(format!("--bucket {bucket:?} must be a single bucket name\n{USAGE}"));
        }

        Ok(Self {
            endpoint,
            target,
            corpus_dirs,
            credentials,
            bucket,
            artifacts_dir,
            timeout,
            health_path,
            max_inputs,
        })
    }
}

/// One replay failure recorded against the live endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayFailure {
    /// Corpus file label (or `<post-run-health>` for a post-run liveness failure).
    pub input: String,
    /// Human-readable description of the crash, hang, 5xx, or framing violation.
    pub reason: String,
    /// Path where the failing input bytes were saved, when `--artifacts-dir` was set.
    pub artifact_path: Option<PathBuf>,
}

/// Aggregate counters and failure records from one endpoint replay run.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Total regular corpus files discovered across all `--corpus-dir` paths.
    pub files_seen: usize,
    /// Unique corpus inputs after SHA-256 deduplication (and optional `--max-inputs`).
    pub unique_inputs: usize,
    /// Unique corpus inputs actually replayed over HTTP against the endpoint.
    pub replayed: usize,
    /// Unique corpus inputs skipped (for example bytes rejected by `fuzz::request_of`).
    pub skipped: usize,
    /// Total HTTP requests transmitted to the endpoint.
    pub requests_sent: usize,
    /// Histogram of observed HTTP status codes.
    pub statuses: BTreeMap<u16, usize>,
    /// Failure records.
    pub failures: Vec<ReplayFailure>,
    /// Whether the endpoint stopped answering health checks after a failure.
    pub endpoint_died: bool,
    /// Total monotonic duration of the replay.
    pub elapsed: Duration,
}

impl Report {
    /// Computes the exit status and formatted multi-line report.
    #[must_use]
    pub fn conclude(&self, target: Target, endpoint: &str) -> (u8, String) {
        let mut text = String::new();
        let _ = writeln!(
            text,
            "fuzz-endpoint-replay ({} -> {}): {} file(s), {} unique, {} replayed, {} skipped, {} request(s), {} failure(s), in {:.1}s",
            target.as_str(),
            endpoint,
            self.files_seen,
            self.unique_inputs,
            self.replayed,
            self.skipped,
            self.requests_sent,
            self.failures.len(),
            self.elapsed.as_secs_f64()
        );
        if !self.statuses.is_empty() {
            let summary: Vec<String> = self
                .statuses
                .iter()
                .map(|(status, count)| format!("{status}={count}"))
                .collect();
            let _ = writeln!(text, "  statuses: {}", summary.join(" "));
        }
        for failure in &self.failures {
            match &failure.artifact_path {
                Some(path) => {
                    let _ = writeln!(text, "FAILURE {}: {} (artifact: {})", failure.input, failure.reason, path.display());
                }
                None => {
                    let _ = writeln!(text, "FAILURE {}: {}", failure.input, failure.reason);
                }
            }
        }
        if self.endpoint_died {
            let _ = writeln!(text, "ENDPOINT DIED: candidate stopped answering health checks during replay");
        }
        if self.replayed == 0 && self.failures.is_empty() {
            let _ = writeln!(text, "ENVIRONMENT: zero corpus inputs were replayed; an empty run is not a pass");
            return (EXIT_ENVIRONMENT, text);
        }
        if !self.failures.is_empty() || self.endpoint_died {
            return (EXIT_FAILURE, text);
        }
        (EXIT_PASSED, text)
    }
}

struct CorpusEntry {
    label: String,
    bytes: Vec<u8>,
}

fn load_corpus(dirs: &[PathBuf], max_inputs: Option<usize>) -> Result<(usize, Vec<CorpusEntry>), String> {
    let mut paths = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            return Err(format!("corpus directory {} does not exist", dir.display()));
        }
        collect_files(dir, &mut paths)?;
    }
    paths.sort();
    let files_seen = paths.len();
    let mut seen_hashes = BTreeSet::new();
    let mut entries = Vec::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(|error| format!("cannot read corpus file {}: {error}", path.display()))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if !seen_hashes.insert(digest) {
            continue;
        }
        entries.push(CorpusEntry {
            label: path.display().to_string(),
            bytes,
        });
        if max_inputs.is_some_and(|limit| entries.len() >= limit) {
            break;
        }
    }
    if entries.is_empty() {
        return Err("no corpus files found across the configured --corpus-dir directories".to_owned());
    }
    Ok((files_seen, entries))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|error| format!("cannot list {}: {error}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot read entry in {}: {error}", dir.display()))?
        .into_iter()
        .map(|entry| entry.path())
        .collect();
    children.sort();
    for path in children {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('.'))
        {
            continue;
        }
        let metadata = fs::metadata(&path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        if metadata.is_dir() {
            collect_files(&path, out)?;
        } else if metadata.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Runs the configured out-of-process corpus replay against `options.endpoint`.
///
/// # Errors
///
/// Environment errors before replay can measure anything (malformed endpoint, missing/empty
/// corpus directories, or an endpoint that fails its initial health check).
pub fn run(options: &Options) -> Result<Report, String> {
    let endpoint = Endpoint::parse(&options.endpoint)?;
    let (files_seen, entries) = load_corpus(&options.corpus_dirs, options.max_inputs)?;
    if let Some(dir) = &options.artifacts_dir {
        fs::create_dir_all(dir).map_err(|error| format!("cannot create artifacts dir {}: {error}", dir.display()))?;
    }
    if let Some(health_path) = &options.health_path {
        check_health(&endpoint, health_path, options.timeout)
            .map_err(|error| format!("endpoint failed initial health check {health_path}: {error}"))?;
    }

    let clock = SystemMonotonic::new();
    let started = clock.monotonic();
    let mut report = Report {
        files_seen,
        unique_inputs: entries.len(),
        ..Report::default()
    };

    match options.target {
        Target::DecodeDiff => replay_decode_diff(options, &endpoint, &entries, &mut report)?,
        Target::EncodeDiff => replay_encode_diff(options, &endpoint, &entries, &mut report)?,
    }

    if !report.endpoint_died
        && let Some(health_path) = &options.health_path
        && let Err(error) = check_health(&endpoint, health_path, options.timeout)
    {
        report.endpoint_died = true;
        record_failure(
            &mut report,
            options.artifacts_dir.as_deref(),
            options.target,
            "<post-run-health>",
            b"",
            &format!("post-run health check {health_path} failed: {error}"),
        );
    }

    report.elapsed = Duration::from_millis(clock.monotonic().saturating_millis_since(started));
    Ok(report)
}

fn replay_decode_diff(
    options: &Options,
    endpoint: &Endpoint,
    entries: &[CorpusEntry],
    report: &mut Report,
) -> Result<(), String> {
    if let Some(credentials) = &options.credentials {
        ensure_bucket(endpoint, "bkt", Some(credentials), options.timeout)?;
    }
    for entry in entries {
        let Some(mut request) = request_of(&entry.bytes) else {
            report.skipped += 1;
            continue;
        };
        report.replayed += 1;
        ensure_host(&mut request, &endpoint.authority);
        if let Some(credentials) = &options.credentials
            && !carries_auth(&request)
            && let Ok(signed_req) = signed_with(&request, &credentials.access_key, &credentials.secret_key, &credentials.region)
        {
            request = signed_req;
        }
        report.requests_sent += 1;
        match send_http_request(endpoint, &request, options.timeout) {
            Ok(response) => {
                *report.statuses.entry(response.status).or_default() += 1;
                if response.status >= 500 && response.status != 501 {
                    let detail = format!(
                        "{} {} returned unexpected HTTP {}: {}",
                        request.method,
                        request.target,
                        response.status,
                        preview_body(&response.body)
                    );
                    record_failure(
                        report,
                        options.artifacts_dir.as_deref(),
                        Target::DecodeDiff,
                        &entry.label,
                        &entry.bytes,
                        &detail,
                    );
                    if maybe_mark_dead(options, endpoint, report) {
                        break;
                    }
                }
            }
            Err(error) => {
                let detail = format!("{} {} failed over HTTP: {error}", request.method, request.target);
                record_failure(
                    report,
                    options.artifacts_dir.as_deref(),
                    Target::DecodeDiff,
                    &entry.label,
                    &entry.bytes,
                    &detail,
                );
                if maybe_mark_dead(options, endpoint, report) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn send_checked(
    endpoint: &Endpoint,
    request: RawRequest,
    credentials: Option<&Credentials>,
    timeout: Duration,
    report: &mut Report,
    label: &str,
) -> Result<HttpResponse, String> {
    report.requests_sent += 1;
    let response = send_signed_if_configured(endpoint, request, credentials, timeout)
        .map_err(|error| format!("{label} failed over HTTP: {error}"))?;
    *report.statuses.entry(response.status).or_default() += 1;
    if response.status >= 500 {
        return Err(format!(
            "{label} returned unexpected HTTP {}: {}",
            response.status,
            preview_body(&response.body)
        ));
    }
    Ok(response)
}

fn ensure_bucket(endpoint: &Endpoint, bucket: &str, credentials: Option<&Credentials>, timeout: Duration) -> Result<(), String> {
    let response = send_signed_if_configured(endpoint, RawRequest::put(&format!("/{bucket}"), b""), credentials, timeout)
        .map_err(|error| format!("cannot prepare scratch bucket {bucket:?}: {error}"))?;
    if response.status >= 500 {
        return Err(format!(
            "preparing scratch bucket {bucket:?} returned HTTP {}: {}",
            response.status,
            preview_body(&response.body)
        ));
    }
    Ok(())
}

fn send_signed_if_configured(
    endpoint: &Endpoint,
    mut request: RawRequest,
    credentials: Option<&Credentials>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    ensure_host(&mut request, &endpoint.authority);
    if let Some(credentials) = credentials {
        request = signed_with(&request, &credentials.access_key, &credentials.secret_key, &credentials.region)?;
    }
    send_http_request(endpoint, &request, timeout)
}

fn check_health(endpoint: &Endpoint, health_path: &str, timeout: Duration) -> Result<(), String> {
    let mut request = RawRequest::get(health_path);
    ensure_host(&mut request, &endpoint.authority);
    let response = send_http_request(endpoint, &request, timeout)?;
    if response.status == 200 {
        Ok(())
    } else {
        Err(format!("expected HTTP 200, got {}", response.status))
    }
}

fn maybe_mark_dead(options: &Options, endpoint: &Endpoint, report: &mut Report) -> bool {
    let Some(health_path) = &options.health_path else {
        return false;
    };
    if check_health(endpoint, health_path, options.timeout).is_err() {
        report.endpoint_died = true;
        return true;
    }
    false
}

fn ensure_host(request: &mut RawRequest, authority: &str) {
    if !request.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        request.headers.push(("host".to_owned(), authority.as_bytes().to_vec()));
    }
}

fn carries_auth(request: &RawRequest) -> bool {
    if request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    {
        return true;
    }
    let Some((_, query)) = request.target.split_once('?') else {
        return false;
    };
    query.split('&').filter(|pair| !pair.is_empty()).any(|pair| {
        let key = pair.split_once('=').map_or(pair, |(name, _)| name);
        PRESIGN_PARAMETERS.contains(&key) || key == "AWSAccessKeyId" || key == "Signature"
    })
}

fn record_failure(
    report: &mut Report,
    artifacts_dir: Option<&Path>,
    target: Target,
    label: &str,
    raw_input: &[u8],
    reason: &str,
) {
    let artifact_path =
        artifacts_dir.and_then(|dir| write_artifact(dir, target, report.failures.len() + 1, label, raw_input, reason).ok());
    report.failures.push(ReplayFailure {
        input: label.to_owned(),
        reason: reason.to_owned(),
        artifact_path,
    });
}

fn write_artifact(
    dir: &Path,
    target: Target,
    ordinal: usize,
    label: &str,
    raw_input: &[u8],
    reason: &str,
) -> io::Result<PathBuf> {
    let sanitized: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let suffix = if sanitized.len() > 80 {
        &sanitized[sanitized.len() - 80..]
    } else {
        &sanitized
    };
    let stem = format!("crash-{ordinal:04}-{suffix}");
    let input_path = dir.join(format!("{stem}.input"));
    let report_path = dir.join(format!("{stem}.report.txt"));
    fs::write(&input_path, raw_input)?;
    let diagnostic = format!(
        "target: {}\ninput: {}\nbytes: {}\nreason: {}\n",
        target.as_str(),
        label,
        raw_input.len(),
        reason
    );
    fs::write(report_path, diagnostic)?;
    Ok(input_path)
}

/// Entry point for the `fuzz-endpoint-replay` binary: parse CLI, run replay, print report, exit.
#[must_use]
pub fn main() -> u8 {
    let options = match Options::parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(usage) => {
            eprintln!("{usage}");
            return EXIT_ENVIRONMENT;
        }
    };
    match run(&options) {
        Ok(report) => {
            let (status, text) = report.conclude(options.target, &options.endpoint);
            print!("{text}");
            status
        }
        Err(error) => {
            eprintln!("ENVIRONMENT: {error}");
            EXIT_ENVIRONMENT
        }
    }
}
