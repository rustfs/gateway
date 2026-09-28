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

//! Responsible for: the crate surface — and for the crate being **empty** unless the
//! `corpus-record` feature is on, which is the compile-time line of defence.
//! Not responsible for: anything a production build does. Without the feature this crate
//! compiles no item at all, so there is nothing of it to link.
//! Upstream: a host's tower stack (the RustFS server, or `compat-sut`) in a test build.
//! Downstream: the corpus JSONL file that `corpus ingest` reads.
//!
//! See the README for the three lines of defence and the exact integration steps.

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "corpus-record")]
mod body;
#[cfg(feature = "corpus-record")]
mod classify;
#[cfg(feature = "corpus-record")]
mod config;
#[cfg(feature = "corpus-record")]
mod layer;
#[cfg(feature = "corpus-record")]
mod writer;

#[cfg(feature = "corpus-record")]
pub use crate::body::TapBody;
#[cfg(feature = "corpus-record")]
pub use crate::config::{
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_IN_FLIGHT_BYTES, DEFAULT_QUEUE_CAPACITY, RECORD_ENV, RecorderConfig, RecorderRefused,
    TEST_ACCESS_KEYS,
};
#[cfg(feature = "corpus-record")]
pub use crate::layer::{CorpusRecorderLayer, CorpusRecorderService, ResponseFuture};
#[cfg(feature = "corpus-record")]
pub use crate::writer::RecorderStats;
#[cfg(feature = "corpus-record")]
pub use rustfs_gateway_corpus::schema::Sut;
