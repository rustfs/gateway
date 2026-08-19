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
//! Responsible for: proving the rendered table is the authority and only the authority — that a
//! row becomes exactly one constant and one lookup entry, that a status the emitter has no
//! `StatusCode` name for stops the build, and that a code no row declares cannot reach a generated
//! call site.
//! NOT responsible for: the authority's own shape, which `rustfs-gateway-model` refuses at load.
//! Upstream: [`crate::emit::error_status`]. Downstream: the codegen test gate.

use rustfs_gateway_model::ErrorStatus;

use crate::emit::error_status::{Constants, render};

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
