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
//! Responsible for: the read-only guard on authored HTTP/2 scripts while external fixtures are
//! active — the method is the one the authored header block encodes, not `request.method`.
//! NOT responsible for: fixture lifecycle or HTTP/2 execution.
//! Upstream: `super::ExternalFixtures::ensure_read_only`; downstream: the verification gate.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::ExternalFixtures;
use crate::inprocess::{InProcess, Wire};

/// `:method` as a literal without indexing on static name 2, then `:scheme http`, `:path /` and an
/// `:authority` literal.
fn block(method: &str) -> String {
    let hex: String = method.bytes().map(|byte| format!("{byte:02x}")).collect();
    format!("02{:02x}{hex}8684410e73332e6578616d706c652e636f6d", method.len())
}

fn read(source: &str) -> Wire {
    InProcess::new(std::path::PathBuf::from("."))
        .read_wire(&crate::toml::parse(source).expect("valid TOML"))
        .expect("the request is read")
}

fn wire(declared: &str, block: &str) -> Wire {
    let source = format!(
        "method = \"{declared}\"\ntarget = \"/\"\nhttp_version = \"h2\"\n\
         [[h2_frames]]\ntype = \"settings\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\", \"end_stream\"]\npayload_hex = \"{block}\"\n"
    );
    InProcess::new(std::path::PathBuf::from("."))
        .read_wire(&crate::toml::parse(&source).expect("valid TOML"))
        .expect("the request is read")
}

fn active() -> ExternalFixtures {
    let mut fixtures = ExternalFixtures::new(true);
    fixtures.active_case = Some("c-h2-9999".to_owned());
    fixtures
}

#[test]
fn an_authored_read_only_method_is_allowed() {
    for method in ["GET", "HEAD", "OPTIONS"] {
        active()
            .ensure_read_only("c-h2-9999", &wire("GET", &block(method)))
            .unwrap_or_else(|error| panic!("{method}: {error}"));
    }
}

#[test]
fn an_authored_mutating_method_is_refused_whatever_request_method_says() {
    for method in ["PUT", "DELETE", "POST"] {
        let error = active()
            .ensure_read_only("c-h2-9999", &wire("GET", &block(method)))
            .expect_err("the authored block mutates");
        assert!(error.to_string().contains(&format!("not {method}")), "{method}: {error}");
    }
}

#[test]
fn an_undecodable_authored_block_is_refused() {
    let error = active()
        .ensure_read_only("c-h2-9999", &wire("GET", "ff"))
        .expect_err("an undecodable block is unclassified");
    assert!(error.to_string().contains("an unclassified authored HTTP/2 script"), "{error}");
}

#[test]
fn a_later_stream_with_a_mutating_method_is_refused() {
    let source = format!(
        "method = \"GET\"\ntarget = \"/\"\nhttp_version = \"h2\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\", \"end_stream\"]\npayload_hex = \"{}\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 3\nflags = [\"end_headers\", \"end_stream\"]\npayload_hex = \"{}\"\n",
        block("GET"),
        block("PUT")
    );
    let wire = InProcess::new(std::path::PathBuf::from("."))
        .read_wire(&crate::toml::parse(&source).expect("valid TOML"))
        .expect("read");
    let error = active().ensure_read_only("c-h2-9999", &wire).expect_err("stream 3 mutates");
    assert!(error.to_string().contains("not PUT"), "{error}");
}

#[test]
fn without_active_fixtures_nothing_is_decoded() {
    ExternalFixtures::new(true)
        .ensure_read_only("c-h2-9999", &wire("GET", "ff"))
        .expect("no fixture is at stake");
}

/// Negative — a PUT split across a padded, prioritised HEADERS and its CONTINUATION is refused: the
/// guard strips padding and priority fields and joins the fragments like the peer.
#[test]
fn a_mutating_method_split_across_continuation_is_refused() {
    // HEADERS: pad length 2, priority fields, the first two octets of the PUT literal, 2 padding
    // octets. CONTINUATION: the rest of the block.
    let rest = &block("PUT")[4..];
    let wire = read(
        &format!(
            "method = \"GET\"\ntarget = \"/\"\nhttp_version = \"h2\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"padded\", \"priority\", \"end_stream\"]\n\
         payload_hex = \"0200000000100203\" \n\
         [[h2_frames]]\ntype = \"continuation\"\nstream_id = 1\nflags = [\"end_headers\"]\npayload_hex = \"{rest}\"\n"
        )
        .replace("\"0200000000100203\" ", "\"02000000001002030000\""),
    );
    let error = active()
        .ensure_read_only("c-h2-9999", &wire)
        .expect_err("the joined block is a PUT");
    assert!(error.to_string().contains("not PUT"), "{error}");
}

/// Positive — a `:method` taken from the dynamic table a previous block filled is resolved, so the
/// guard keeps one decoder across blocks as the peer does.
#[test]
fn a_method_indexed_from_an_earlier_block_is_resolved() {
    // Stream 1 inserts `:method GET` (literal with incremental indexing, dynamic index 62);
    // stream 3 names it by index 0xbe.
    let first = format!("4203474554{}", &block("GET")[10..]);
    let second = format!("be{}", &block("GET")[10..]);
    let wire = read(&format!(
        "method = \"GET\"\ntarget = \"/\"\nhttp_version = \"h2\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\", \"end_stream\"]\npayload_hex = \"{first}\"\n\
         [[h2_frames]]\ntype = \"headers\"\nstream_id = 3\nflags = [\"end_headers\", \"end_stream\"]\npayload_hex = \"{second}\"\n"
    ));
    active()
        .ensure_read_only("c-h2-9999", &wire)
        .expect("both blocks decode to GET");
}

/// Negative — a dynamic-table size update to 4,097 octets, beyond the default 4,096, cannot be decoded
/// the way the peer would, so the script is unclassified.
#[test]
fn a_table_size_update_beyond_the_default_is_unclassified() {
    let error = active()
        .ensure_read_only("c-h2-9999", &wire("GET", &format!("3fe21f{}", block("GET"))))
        .expect_err("the guard cannot follow a larger table");
    assert!(error.to_string().contains("an unclassified authored HTTP/2 script ("), "{error}");
}
