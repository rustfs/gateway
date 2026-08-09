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

//! What the tolerances the model does not state actually generate.
//!
//! Responsible for: the tolerance resolution rules, that a declared tolerance reaches the decoder
//! of the member that carries it and no others, and that the emitted assignment is not wrapped in
//! a second `Some`.
//! NOT responsible for: what the tolerance does to a request, which is `rustfs-gateway-core`'s
//! `tests/tolerant_conditions.rs`.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.
//!
//! 3 positive / 6 negative. The negatives are the ones that matter: a tolerance that fails to
//! resolve leaves the member strict, which looks exactly like a decoder doing its job and is a
//! refusal the RFC forbids.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_model::ir::{Binding, Evidence, Field, Quirk, TimestampFormat, Type};

use crate::emit::codec::tolerance::{self, TOLERANCE_KIND, Tolerance};

fn field(name: &str, ty: Type, binding: Binding, quirks: &[&str]) -> Field {
    Field {
        name: name.to_owned(),
        wire_name: Some(name.to_lowercase()),
        required: false,
        binding,
        ty,
        hot: false,
        default: None,
        omit_when: None,
        missing_error: None,
        quirk_refs: quirks.iter().map(|q| (*q).to_owned()).collect(),
    }
}

fn quirk(id: &str, kind: &str) -> Quirk {
    Quirk {
        id: id.to_owned(),
        kind: kind.to_owned(),
        target: "Fixture.Member".to_owned(),
        summary: "a fixture quirk, long enough to satisfy the schema".to_owned(),
        evidence: vec![Evidence {
            kind: "observed".to_owned(),
            reference: "fixture".to_owned(),
            summary: "a fixture evidence entry, long enough".to_owned(),
        }],
        cases: vec!["c-fixture-0001".to_owned()],
    }
}

fn date(quirks: &[&str]) -> Field {
    field("IfModifiedSince", Type::Timestamp(TimestampFormat::HttpDate), Binding::Header, quirks)
}

/// Negative — a member with no quirk is read strictly, which is the default the whole surface
/// depends on.
#[test]
fn a_field_with_no_quirk_is_not_tolerated() {
    let resolved = tolerance::of(&date(&[]), &[], "Fixture").expect("resolves");
    assert_eq!(resolved, None, "an ordinary timestamp keeps the refusing conversion");
}

/// Negative — a quirk of another kind on the same member declares nothing.
///
/// `q-timestamp-0005` sits on timestamp members already; if kind were not consulted it would turn
/// every one of them tolerant.
#[test]
fn a_quirk_of_another_kind_declares_no_tolerance() {
    let quirks = vec![quirk("q-timestamp-0005", "timestamp_format")];
    let resolved = tolerance::of(&date(&["q-timestamp-0005"]), &quirks, "Fixture").expect("resolves");
    assert_eq!(resolved, None, "only `{TOLERANCE_KIND}` declares a tolerance");
}

/// Negative — a `header_tolerance` quirk with no row in the table fails the run.
///
/// The alternative is a quirk that claims a tolerance nothing performs: the overlay says the
/// header is ignored, the generated code refuses it, and only a conformance case notices.
#[test]
fn an_unknown_tolerance_quirk_fails_the_run() {
    let quirks = vec![quirk("q-cond-9999", TOLERANCE_KIND)];
    let error = tolerance::of(&date(&["q-cond-9999"]), &quirks, "GetObject").expect_err("no row for this id");
    assert!(error.contains("q-cond-9999"), "{error}");
    assert!(error.contains("tolerance.rs"), "{error}");
}

/// Negative — a tolerance attached to a member whose type it has no reading for fails the run.
#[test]
fn a_tolerance_on_the_wrong_type_fails_the_run() {
    let quirks = vec![quirk("q-cond-0050", TOLERANCE_KIND)];
    let wrong = field("IfMatch", Type::String, Binding::Header, &["q-cond-0050"]);
    let error = tolerance::of(&wrong, &quirks, "GetObject").expect_err("a string is not a date");
    assert!(error.contains("header-bound timestamp"), "{error}");
}

/// Negative — a tolerance attached to a timestamp that is not header-bound fails the run.
///
/// RFC 9110 says to ignore a *header* whose date cannot be read. It says nothing about a query
/// parameter, and a query timestamp silently dropped is a filter the caller asked for and did not
/// get.
#[test]
fn a_tolerance_on_the_wrong_binding_fails_the_run() {
    let quirks = vec![quirk("q-cond-0050", TOLERANCE_KIND)];
    let wrong = field(
        "ResponseExpires",
        Type::Timestamp(TimestampFormat::HttpDate),
        Binding::Query,
        &["q-cond-0050"],
    );
    let error = tolerance::of(&wrong, &quirks, "GetObject").expect_err("a query value is not a conditional header");
    assert!(error.contains("header-bound timestamp"), "{error}");
}

/// Negative — the emitted call produces the stored `Option` itself, so `decode` must not wrap it.
///
/// Asserted over the text because that is where the `if-range` defect would come back: an
/// expression yielding `Timestamp` here would be wrapped in `Some` by the caller and the dropped
/// condition would become indistinguishable from an absent header again.
#[test]
fn the_emitted_call_already_yields_the_stored_option() {
    let call = Tolerance::DateCondition
        .call(&Type::Timestamp(TimestampFormat::HttpDate))
        .expect("a header-bound timestamp has a reading");
    assert!(call.ends_with(".honoured()"), "{call}");
    assert!(!call.contains('?'), "a tolerated read is never a refusal: {call}");
    assert!(!call.starts_with("Some("), "{call}");
}

/// Positive — the declared tolerance reaches the member that carries it.
#[test]
fn the_declared_tolerance_reaches_its_member() {
    let quirks = vec![quirk("q-cond-0050", TOLERANCE_KIND)];
    let resolved = tolerance::of(&date(&["q-cond-0050"]), &quirks, "GetObject").expect("resolves");
    assert_eq!(resolved, Some(Tolerance::DateCondition));
}

/// Positive — the reading carries the format the binding declares rather than assuming one.
#[test]
fn the_reading_carries_the_declared_format() {
    let http = Tolerance::DateCondition
        .call(&Type::Timestamp(TimestampFormat::HttpDate))
        .expect("a reading");
    assert!(http.contains("TimestampFormat::HttpDate"), "{http}");
    let iso = Tolerance::DateCondition
        .call(&Type::Timestamp(TimestampFormat::Iso8601))
        .expect("a reading");
    assert!(iso.contains("TimestampFormat::Iso8601"), "{iso}");
}

/// Positive — the generated object-family decoders read the two date conditions tolerantly and the
/// two entity-tag conditions strictly.
///
/// The end of the chain: overlay to table to emitter to file. Asserted over the emitted text of
/// the real model rather than a fixture, because every step between the quirk and the file is a
/// place the reference can be dropped without any test above noticing.
#[test]
fn the_object_family_reads_its_dates_tolerantly() {
    let artifacts = super::codegen_tests::artifacts();
    for operation in ["get_object", "head_object"] {
        let path = format!("codec/ops/{operation}.rs");
        let text = artifacts
            .files
            .iter()
            .find(|(name, _)| name.to_string_lossy().ends_with(&path))
            .map(|(_, body)| body.clone())
            .unwrap_or_else(|| panic!("{path} is generated"));
        for header in ["if-modified-since", "if-unmodified-since"] {
            let line = text
                .lines()
                .find(|line| line.contains(&format!("request.header(\"{header}\")")))
                .unwrap_or_else(|| panic!("{path} binds {header}"));
            let assignment = text
                .lines()
                .skip_while(|candidate| *candidate != line)
                .nth(2)
                .unwrap_or_else(|| panic!("{path} assigns {header}"));
            assert!(assignment.contains("date_condition"), "{path} {header}: {assignment}");
            assert!(!assignment.contains('?'), "{path} {header} still refuses: {assignment}");
        }
        assert!(
            text.contains("value::etag_form(raw, \"IfMatch\")?"),
            "{path}: the entity-tag condition must stay strict"
        );
    }
}
