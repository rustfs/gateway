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

//! The error code to HTTP status emitter.
//!
//! Responsible for: proving the three renderings are the authority and only the authority — that a
//! row becomes exactly one constant and one lookup entry, that a status the emitter has no
//! `StatusCode` name for stops the build, that a code no row declares cannot reach a generated
//! call site, and that the published Markdown and JSON carry every row with the status the
//! authority gave it.
//! NOT responsible for: the authority's own shape, which `rustfs-gateway-model` refuses at load.
//! Upstream: [`crate::emit::error_status`]. Downstream: the codegen test gate.

use rustfs_gateway_model::ErrorStatus;
use rustfs_gateway_model::json::{self, Value};

use crate::emit::error_status::{Constants, render, render_json, render_markdown};

/// The rendered document, read back the way a consumer would read it.
///
/// Substring assertions over the rendered bytes would pass on a document whose line wrapping
/// moved and fail on one whose meaning did not, which is the wrong sensitivity in both directions.
fn parsed(rendered: &str) -> Value {
    json::parse(rendered).expect("the emitted document is JSON")
}

/// One reverse-index bucket, as a list of code names.
fn index<'a>(document: &'a Value, name: &str, key: &str) -> Vec<&'a str> {
    document
        .get(name)
        .and_then(|index| index.get(key))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{name}[{key}] is absent"))
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

fn row(name: &str, constant: &str, status: u16, server_fault: bool) -> ErrorStatus {
    ErrorStatus {
        name: name.to_owned(),
        constant: constant.to_owned(),
        status,
        server_fault,
        note: Vec::new(),
    }
}

#[test]
fn n_a_status_with_no_status_code_name_stops_the_build() {
    // The alternative is a numeric literal, which compiles and produces a status no reader can
    // match against `StatusCode::NOT_FOUND`. Failing is the point.
    let error = render(&[row("Teapot", "TEAPOT", 418, false)]).expect_err("418 has no name in the emitter");
    assert!(error.contains("418"), "{error}");
    assert!(error.contains("bare number"), "{error}");
}

#[test]
fn n_a_code_with_no_row_cannot_reach_a_generated_call_site() {
    // `missing_error` names a code in the IR. If the authority does not declare it, the generated
    // decoder would have to look it up in the request path, where there is no status to find.
    let codes = Constants::new(&[row("InvalidArgument", "INVALID_ARGUMENT", 400, false)]);
    let error = codes
        .path("SomethingNobodyDeclared")
        .expect_err("an undeclared code has no constant");
    assert!(error.contains("SomethingNobodyDeclared"), "{error}");
    assert!(error.contains("error-status.toml"), "{error}");
}

#[test]
fn a_declared_code_resolves_to_its_constant() {
    let codes = Constants::new(&[row("MissingContentLength", "MISSING_CONTENT_LENGTH", 411, false)]);
    assert_eq!(
        codes.path("MissingContentLength").expect("a declared code resolves"),
        "ErrorCode::MISSING_CONTENT_LENGTH"
    );
}

#[test]
fn every_row_becomes_one_constant_and_one_lookup_entry() {
    let rendered = render(&[
        row("NoSuchKey", "NO_SUCH_KEY", 404, false),
        row("InternalError", "INTERNAL_ERROR", 500, true),
    ])
    .expect("a well-formed authority renders");

    assert_eq!(rendered.matches("pub const NO_SUCH_KEY: Self = Self {").count(), 1);
    assert_eq!(rendered.matches("pub const INTERNAL_ERROR: Self = Self {").count(), 1);
    assert_eq!(rendered.matches(r#"("NoSuchKey", StatusCode::NOT_FOUND),"#).count(), 1);
    assert_eq!(
        rendered
            .matches(r#"("InternalError", StatusCode::INTERNAL_SERVER_ERROR),"#)
            .count(),
        1
    );
    // No type is minted here: the including module owns `ErrorCode`, so `grep` traces every name
    // in the tree back to a hand-written declaration.
    assert!(!rendered.contains("pub struct"), "the generated table must not mint a type");
    assert!(!rendered.contains("pub enum"), "the generated table must not mint a type");
}

#[test]
fn a_note_becomes_rustdoc_under_the_status_line() {
    let mut declared = row("NotFound", "NOT_FOUND", 404, false);
    declared.note = vec!["What HEAD answers with.".to_owned(), "A second line.".to_owned()];
    let rendered = render(&[declared]).expect("renders");
    assert!(rendered.contains("    /// `NotFound`, HTTP `404`.\n    ///\n"), "{rendered}");
    assert!(
        rendered.contains("    /// What HEAD answers with.\n    /// A second line.\n"),
        "{rendered}"
    );
}

#[test]
fn the_pinned_authority_declares_every_code_its_operations_can_produce() {
    // The whole point of the slice: an operation that names a code the authority does not declare
    // used to produce a plausible-looking 400. Now it cannot be generated at all.
    let artifacts = super::codegen_tests::artifacts();
    for ir in &artifacts.operations {
        for code in &ir.errors.codes {
            artifacts
                .error_codes
                .path(code)
                .unwrap_or_else(|error| panic!("{} names a code with no status row: {error}", ir.operation));
        }
        if let Some(code) = &ir.errors.not_configured {
            artifacts
                .error_codes
                .path(code)
                .unwrap_or_else(|error| panic!("{} names an unconfigured code with no status row: {error}", ir.operation));
        }
    }
}

#[test]
fn n_the_markdown_refuses_the_status_the_rust_table_refuses() {
    // Two renderings that accept different tables are two authorities. The Markdown has no
    // `StatusCode` constant to emit, so nothing about rendering it forces the refusal — which is
    // exactly why it is asserted rather than assumed.
    let error = render_markdown(&[row("Teapot", "TEAPOT", 418, false)]).expect_err("418 has no name");
    assert!(error.contains("418"), "{error}");
}

#[test]
fn n_the_markdown_note_cannot_end_its_cell_early() {
    // A note is prose from the overlay and a `|` in it would close the table cell, silently
    // turning the rest of the sentence into two more columns.
    let mut declared = row("NoSuchKey", "NO_SUCH_KEY", 404, false);
    declared.note = vec!["Either a|b".to_owned()];
    let rendered = render_markdown(&[declared]).expect("renders");
    assert!(rendered.contains(r"Either a\|b"), "{rendered}");
}

#[test]
fn n_a_code_absent_from_the_authority_is_absent_from_both_documents() {
    let rows = [row("NoSuchKey", "NO_SUCH_KEY", 404, false)];
    let markdown = render_markdown(&rows).expect("renders");
    let json = render_json(&rows);
    assert!(!markdown.contains("InternalError"), "{markdown}");
    assert!(!json.contains("InternalError"), "{json}");
}

#[test]
fn every_row_reaches_both_published_documents_with_its_own_status() {
    // Three bands, chosen so that status order and alphabetical order disagree: alphabetically
    // this reads "client, redirect, server", which is the census a sort would produce and is not
    // the order a reader follows.
    let rows = [
        row("NoSuchKey", "NO_SUCH_KEY", 404, false),
        row("InternalError", "INTERNAL_ERROR", 500, true),
        row("PermanentRedirect", "PERMANENT_REDIRECT", 301, false),
    ];
    let markdown = render_markdown(&rows).expect("renders");
    assert!(markdown.contains("| `NoSuchKey` | 404 | `ErrorCode::NO_SUCH_KEY` |"), "{markdown}");
    assert!(markdown.contains("| `InternalError` | 500 | `ErrorCode::INTERNAL_ERROR` |"), "{markdown}");
    assert!(markdown.contains("3 codes: 1 redirect, 1 client, 1 server."), "{markdown}");

    let json = parsed(&render_json(&rows));
    let entry = json
        .get("codes")
        .and_then(|codes| codes.get("NoSuchKey"))
        .expect("NoSuchKey has an entry");
    assert_eq!(
        entry
            .as_object()
            .map(|members| members.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>()),
        Some(vec!["constant", "status", "server_fault"]),
        "the field order is the document's contract"
    );
    assert_eq!(entry.get("constant").and_then(Value::as_str), Some("NO_SUCH_KEY"));
    assert_eq!(index(&json, "by_status", "404"), vec!["NoSuchKey"]);
    assert_eq!(index(&json, "by_server_fault", "true"), vec!["InternalError"]);
    assert_eq!(index(&json, "by_constant", "NO_SUCH_KEY"), vec!["NoSuchKey"]);
}

#[test]
fn the_5xx_allowlist_is_the_5xx_band_in_both_documents() {
    // The set an SDK retries. A 4xx that reaches it is an outage that was a client's mistake, and
    // a 5xx that escapes it is a retry the client never makes. Asserted over the pinned authority
    // rather than a fixture, because the rows are what ship.
    let overlay = rustfs_gateway_model::Overlay::load(&super::codegen_tests::root().join("model/overlays"))
        .expect("the pinned overlays load");
    let rows = &overlay.error_status;
    assert!(rows.len() > 100, "the pinned authority is the whole table, saw {}", rows.len());

    let json = parsed(&render_json(rows));
    let markdown = render_markdown(rows).expect("the pinned authority renders");
    let allowlist = markdown
        .split("## The 5xx allowlist")
        .nth(1)
        .and_then(|section| section.split("## By status").next())
        .expect("the allowlist section exists")
        .to_owned();

    for declared in rows {
        let cell = format!("| `{}` | {} | `ErrorCode::{}` |", declared.name, declared.status, declared.constant);
        assert!(markdown.contains(&cell), "{} is absent from the Markdown table", declared.name);
        let entry = json
            .get("codes")
            .and_then(|codes| codes.get(&declared.name))
            .unwrap_or_else(|| panic!("{} is absent from the JSON", declared.name));
        assert_eq!(entry.get("constant").and_then(Value::as_str), Some(declared.constant.as_str()));
        assert_eq!(entry.get("status"), Some(&Value::Int(i64::from(declared.status))));
        assert_eq!(entry.get("server_fault"), Some(&Value::Bool(declared.server_fault)));
        assert!(
            index(&json, "by_status", &declared.status.to_string()).contains(&declared.name.as_str()),
            "{} is missing from by_status[{}]",
            declared.name,
            declared.status
        );
        assert_eq!(
            allowlist.contains(&cell),
            declared.status >= 500,
            "{} appears in the 5xx allowlist section iff it is answered in the 5xx band",
            declared.name
        );
    }
}
