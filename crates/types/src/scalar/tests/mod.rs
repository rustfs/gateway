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

//! Unit tests for the scalar vocabulary, one module per type.
//!
//! Responsible for: the boundary and negative cases each scalar promises, mirrored one-to-one on
//! the conformance case identifiers quoted in each test name, plus property-based round trips.
//! NOT responsible for: end-to-end wire behaviour, which the conformance suite runs against a
//! server rather than against these functions.
//! Upstream: the modules under test. Downstream: nothing.

mod base64_tests;
mod checksum_tests;
mod error_tests;
mod etag_tests;
mod name_tests;
mod naming_tests;
mod range_tests;
mod rustfs_addressing_tests;
mod rustfs_key_floor_tests;
mod rustfs_slash_tests;
mod timestamp_corpus_tests;
mod timestamp_tests;
mod upload_id_tests;
