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

//! Consolidated integration-test entry point for `http`.
//!
//! Responsible for: registering every `http` integration-test source in one Cargo target.
//! NOT responsible for: test behavior or repository automation implementation.
//! Upstream: the `http` integration-test modules. Downstream: Cargo's test harness.

#[path = "accepted_transport_extensions.rs"]
mod accepted_transport_extensions;
#[path = "allocation_budget.rs"]
mod allocation_budget;
#[path = "boundary_guards.rs"]
mod boundary_guards;
#[path = "checksum_arbitration.rs"]
mod checksum_arbitration;
#[path = "checksum_empty_headers.rs"]
mod checksum_empty_headers;
#[path = "checksum_unknown_algorithms.rs"]
mod checksum_unknown_algorithms;
#[path = "chunked_decode_replay.rs"]
mod chunked_decode_replay;
#[path = "form_allocations.rs"]
mod form_allocations;
#[path = "form_grammar.rs"]
mod form_grammar;
#[path = "form_legacy_edges.rs"]
mod form_legacy_edges;
#[path = "form_limits.rs"]
mod form_limits;
#[path = "framing_smuggling.rs"]
mod framing_smuggling;
#[path = "header_accept_replay.rs"]
mod header_accept_replay;
#[path = "header_and_query.rs"]
mod header_and_query;
#[path = "host_ambiguity.rs"]
mod host_ambiguity;
#[path = "ingest_chunk_rss.rs"]
mod ingest_chunk_rss;
#[path = "ingest_chunk_rules.rs"]
mod ingest_chunk_rules;
#[path = "ingest_framing.rs"]
mod ingest_framing;
#[path = "ingest_known_answer.rs"]
mod ingest_known_answer;
#[path = "ingest_perf_gates.rs"]
mod ingest_perf_gates;
#[path = "ingest_verify.rs"]
mod ingest_verify;
#[path = "reject_wording.rs"]
mod reject_wording;
#[path = "support/mod.rs"]
mod support;
