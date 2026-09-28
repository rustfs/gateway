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

//! Optional corpus recording for the system under test (rustfs/backlog#1763).
//!
//! Responsible for: turning `--corpus-record <file> --corpus-src <src>` into a checked
//! `CorpusRecorderLayer` over every configured identity, or into nothing at all when the flags are
//! absent — and refusing the flags outright in a build without the `corpus-record` feature.
//! NOT responsible for: what is recorded or redacted (`rustfs-gateway-corpus-recorder`), or the
//! refusal rules themselves (`RUSTFS_CORPUS_RECORD=1` and the test-credential allowlist), which the
//! recorder applies and this launcher only propagates as a startup failure.
//! Upstream: `crate::main`, which mounts the returned layer outermost with `option_layer`.
//! Downstream: the JSONL file `corpus ingest` reads.

use std::io;

use crate::Options;

/// The layer `main` mounts: the recorder in a build with the feature, nothing without it.
#[cfg(feature = "corpus-record")]
pub(crate) type Recorder = rustfs_gateway_corpus_recorder::CorpusRecorderLayer;
/// The layer `main` mounts: the recorder in a build with the feature, nothing without it.
#[cfg(not(feature = "corpus-record"))]
pub(crate) type Recorder = tower::layer::util::Identity;

/// The recorder the command line asks for, or `None` when it asks for none.
///
/// # Errors
///
/// The recorder's own refusal — recording not enabled, a configured access key that is not a test
/// credential, an unknown source, an unopenable file — or, in a build without the feature, the
/// flag itself. Every one of them stops the launcher before it binds a port.
#[cfg(feature = "corpus-record")]
pub(crate) fn recorder(options: &Options) -> Result<Option<Recorder>, io::Error> {
    use rustfs_gateway_corpus_recorder::{CorpusRecorderLayer, RecorderConfig, Sut};

    let Some(recording) = options.corpus.as_ref() else {
        return Ok(None);
    };
    let access_keys = options.accounts.all().map(|account| account.access_key.clone()).collect();
    let config = RecorderConfig::new(&recording.output, &recording.src, Sut::GatewayFsReference, access_keys);
    CorpusRecorderLayer::new_checked(config)
        .map(Some)
        .map_err(|refused| io::Error::new(io::ErrorKind::PermissionDenied, refused.to_string()))
}

/// The recorder the command line asks for, or `None` when it asks for none.
///
/// # Errors
///
/// A recording flag in a build that cannot record.
#[cfg(not(feature = "corpus-record"))]
pub(crate) fn recorder(options: &Options) -> Result<Option<Recorder>, io::Error> {
    match options.corpus.as_ref() {
        None => Ok(None),
        Some(recording) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "cannot record `{}` traffic into {}: this compat-sut was built without `--features corpus-record`",
                recording.src,
                recording.output.display()
            ),
        )),
    }
}

/// The shutdown line for a recorder, when there is one.
#[cfg(feature = "corpus-record")]
pub(crate) fn report(recorder: Option<&Recorder>) -> Option<String> {
    recorder.map(|layer| {
        let stats = layer.stats();
        format!(
            "compat-sut corpus recorded={} refused={} dropped={} unrouted={} unrepresentable={} body_not_recorded={} write_errors={}",
            stats.recorded,
            stats.refused,
            stats.dropped_queue_full,
            stats.unrouted,
            stats.unrepresentable_head,
            stats.body_not_recorded,
            stats.write_errors,
        )
    })
}

/// The shutdown line for a recorder, when there is one.
#[cfg(not(feature = "corpus-record"))]
pub(crate) fn report(_recorder: Option<&Recorder>) -> Option<String> {
    None
}
