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

//! Responsible for: the runtime line of defence — the recorder's configuration and the
//! refusal to construct it unless recording was asked for explicitly **and** every configured
//! credential is a known test credential.
//! Not responsible for: recording (`layer`, `body`), or redaction (`writer`, which runs the
//! corpus crate's gate).
//! Upstream: the host's startup code, which must propagate a refusal and not start serving.
//! Downstream: `layer::CorpusRecorderLayer::new_checked`.

use std::fmt;
use std::io;
use std::path::PathBuf;

use rustfs_gateway_corpus::schema::Sut;
use rustfs_gateway_corpus::store;

/// The environment variable that must be exactly `1` for a recorder to be constructed.
pub const RECORD_ENV: &str = "RUSTFS_CORPUS_RECORD";

/// Access keys that exist only in test configurations of this project and of RustFS.
///
/// A recorder refuses to start unless **every** access key the host is configured with is on
/// this list, so a test build pointed at a real deployment's credentials cannot record it. The
/// list is closed on purpose: adding a test identity is a reviewed edit here, never a runtime
/// setting, because anything a runtime setting can widen is exactly what an operator can widen by
/// accident. `rustfsadmin`, the shipped default credential, is deliberately absent — a server
/// still on its default credential is far more likely to be a real one than a test fixture.
pub const TEST_ACCESS_KEYS: &[&str] = &[
    // RustFS `e2e-s3tests.yml`, `mint.yml` and `minio-interop.yml` workflow identities.
    "rustfsadmin-ci",
    "rustfsalt",
    // This repository's client matrix (`ci/compat/run_matrix.sh`).
    "compatmatrixkey",
    // This repository's Ceph s3-tests identities (`ci/s3tests/run.sh`).
    "AKIAGATEWAYMAIN00000",
    "AKIAGATEWAYALT000000",
    "AKIAGATEWAYTENANT000",
    "AKIAGATEWAYIAMROOT00",
    "AKIAGATEWAYIAMALT000",
];

/// Default cap on the request body bytes kept for one entry. A larger body is not truncated:
/// the entry is written without a body, because a prefix recorded as a whole body is false.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default cap on body bytes held across every request still in flight.
pub const DEFAULT_MAX_IN_FLIGHT_BYTES: usize = 64 * 1024 * 1024;

/// Default number of finished records that may wait for the writer thread.
pub const DEFAULT_QUEUE_CAPACITY: usize = 256;

/// Everything a recorder needs to be constructed.
#[derive(Clone, Debug)]
pub struct RecorderConfig {
    /// The JSONL file to append entries to. Created if absent.
    pub output: PathBuf,
    /// Provenance of the traffic, e.g. `s3-tests@5522d1c`. Checked against the corpus source
    /// allowlist at construction, so an unknown source refuses startup rather than refusing
    /// every entry later.
    pub src: String,
    /// What is answering the requests. `Sut::RustfsServer` for the RustFS server.
    pub sut: Sut,
    /// Every access key the host is configured to accept. All of them must be on
    /// [`TEST_ACCESS_KEYS`].
    pub access_keys: Vec<String>,
    /// Per-entry body cap in bytes.
    pub max_body_bytes: usize,
    /// Cap on body bytes buffered across all in-flight requests.
    pub max_in_flight_bytes: usize,
    /// Capacity of the queue in front of the writer thread.
    pub queue_capacity: usize,
}

impl RecorderConfig {
    /// A configuration with the default caps.
    pub fn new(output: impl Into<PathBuf>, src: impl Into<String>, sut: Sut, access_keys: Vec<String>) -> Self {
        Self {
            output: output.into(),
            src: src.into(),
            sut,
            access_keys,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_in_flight_bytes: DEFAULT_MAX_IN_FLIGHT_BYTES,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        }
    }
}

/// Why a recorder refused to be constructed. The host must treat every variant as a reason not
/// to start serving.
#[derive(Debug)]
pub enum RecorderRefused {
    /// [`RECORD_ENV`] is unset or holds anything other than `1`.
    NotEnabled,
    /// No access key was configured, so there is nothing to prove to be a test credential.
    NoAccessKeys,
    /// The access key at this position of `access_keys` is not a test credential. The key itself
    /// is not repeated: this error is written to a startup log.
    CredentialNotAllowlisted {
        /// Zero-based position in `RecorderConfig::access_keys`.
        position: usize,
    },
    /// The provenance source is not on the corpus allowlist.
    UnknownSource(String),
    /// A cap is zero, which would record nothing while claiming to record.
    ZeroCap(&'static str),
    /// The output file could not be opened for appending.
    Output(io::Error),
}

impl fmt::Display for RecorderRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnabled => write!(
                f,
                "corpus recorder refused to start: {RECORD_ENV} is not set to 1; this build records every request, \
                 so it will not serve without that explicit opt-in"
            ),
            Self::NoAccessKeys => f.write_str("corpus recorder refused to start: no configured access key to check"),
            Self::CredentialNotAllowlisted { position } => write!(
                f,
                "corpus recorder refused to start: configured access key #{position} is not a test credential; \
                 recording is only allowed against the test identities in TEST_ACCESS_KEYS"
            ),
            Self::UnknownSource(reason) => write!(f, "corpus recorder refused to start: {reason}"),
            Self::ZeroCap(name) => write!(f, "corpus recorder refused to start: `{name}` must be greater than zero"),
            Self::Output(error) => write!(f, "corpus recorder refused to start: cannot open the output file: {error}"),
        }
    }
}

impl std::error::Error for RecorderRefused {}

/// Every check that does not touch the filesystem, in the order a reader would expect.
pub(crate) fn check(config: &RecorderConfig, env: &dyn Fn(&str) -> Option<String>) -> Result<(), RecorderRefused> {
    if env(RECORD_ENV).as_deref() != Some("1") {
        return Err(RecorderRefused::NotEnabled);
    }
    if config.access_keys.is_empty() {
        return Err(RecorderRefused::NoAccessKeys);
    }
    if let Some(position) = config
        .access_keys
        .iter()
        .position(|key| !TEST_ACCESS_KEYS.contains(&key.as_str()))
    {
        return Err(RecorderRefused::CredentialNotAllowlisted { position });
    }
    store::check_source(&config.src).map_err(RecorderRefused::UnknownSource)?;
    for (name, value) in [
        ("max_body_bytes", config.max_body_bytes),
        ("max_in_flight_bytes", config.max_in_flight_bytes),
        ("queue_capacity", config.queue_capacity),
    ] {
        if value == 0 {
            return Err(RecorderRefused::ZeroCap(name));
        }
    }
    Ok(())
}
