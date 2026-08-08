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

//! The conventions the frozen schema cannot express.
//!
//! Responsible for: everything `conformance/README.md` states as a rule but JSON Schema cannot
//! check — that an identifier agrees with its directory and file name, that a golden exists, that
//! every `${capture.*}` has a producer earlier in the same case, that a tag is in the documented
//! vocabulary, and that a value the runner could compute was not written into the file by hand.
//! Rules that make a case unusable deny; rules that describe drift warn, because a warning that
//! fails the build gets suppressed and a suppressed rule teaches nothing.
//! NOT responsible for: schema validation (`crate::schema`) or execution (`crate::runner`).
//! Upstream: `crate::corpus`, `crate::interpolate`. Downstream: `crate::runner`.

use crate::corpus::{Case, Corpus};
use crate::diagnostic::Diagnostic;
use crate::interpolate;
use crate::schema::SCHEMA_VERSION;
use crate::value::Value;
use std::collections::BTreeSet;

/// The documented tag vocabulary. New values are added here and in `conformance/README.md`
/// together; naming a new domain is deliberately not a schema change.
pub const TAG_VOCABULARY: &[&str] = &[
    "streaming",
    "chunked",
    "trailer",
    "signature",
    "sigv4",
    "sigv2",
    "presigned",
    "xml",
    "wire-bytes",
    "etag",
    "routing",
    "vhost",
    "conditional",
    "preconditions",
    "list",
    "pagination",
    "multipart",
    "checksum",
    "range",
    "encoding",
    "cors",
    "preflight",
    "encryption",
    "sse",
    "lifecycle",
    "replication",
    "bucketconfig",
    "region",
    "security",
    "dos",
    "timing",
    "connection",
    "event-stream",
    "tls",
    "h2",
    "error-shape",
    "known-divergence",
    "tagging",
    "object-lock",
    "restore",
    "select",
    "acl",
    "naming",
    "slow",
];

/// Request headers whose value is a digest of the request body.
///
/// A digest written into a case file is a digest nobody recomputes when the body changes, which
/// is why `conformance/cases/README.md` lists a hand-written hash as grounds for rejection. The
/// schema has no expression form for a computed value, so this can only be a warning today.
const COMPUTED_HEADERS: &[&str] = &["content-md5", "x-amz-content-sha256"];

/// Runs every convention check over the corpus, appending findings to each case.
pub fn lint(corpus: &mut Corpus) {
    let goldens: Vec<String> = corpus
        .cases()
        .iter()
        .flat_map(collect_goldens)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let missing: BTreeSet<String> = goldens
        .into_iter()
        .filter(|relative| corpus.read_relative(relative).is_err())
        .collect();
    for case in corpus.cases_mut() {
        let mut found = Vec::new();
        check_identity(case, &mut found);
        check_goldens(case, &missing, &mut found);
        check_interpolation(case, &mut found);
        check_tags(case, &mut found);
        check_assertion_strength(case, &mut found);
        check_hand_computed_values(case, &mut found);
        case.diagnostics.extend(found);
    }
}

/// The corpus-wide requirement that negative cases outnumber positive ones.
///
/// Reported once for the whole suite rather than per case, because no single case can be at fault
/// for it.
#[must_use]
pub fn polarity_balance(corpus: &Corpus) -> (usize, usize) {
    let mut positive = 0;
    let mut negative = 0;
    for case in corpus.cases() {
        match case.polarity() {
            Some("positive") => positive += 1,
            Some("negative") => negative += 1,
            _ => {}
        }
    }
    (negative, positive)
}

fn collect_goldens(case: &Case) -> Vec<String> {
    let mut out = Vec::new();
    for exchange in case.exchanges() {
        if let Some(relative) = exchange
            .expect
            .and_then(|expect| expect.read("expect.body"))
            .and_then(|body| body.read("bodyExpectation.golden"))
            .and_then(Value::as_str)
        {
            out.push(relative.to_owned());
        }
    }
    out
}

fn check_identity(case: &Case, out: &mut Vec<Diagnostic>) {
    let Some(document) = case.document.as_ref() else { return };
    let Some(meta) = document.read("case") else { return };
    let Some(id) = meta.read("caseMeta.id").and_then(Value::as_str) else { return };
    let stem = case
        .path
        .file_stem()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if id != stem {
        out.push(Diagnostic::deny(
            "lint/id-file-name",
            "/case/id",
            format!("the file is named `{stem}.toml` but the case calls itself `{id}`; identifiers are permanent and cited by evidence"),
        ));
    }
    let domain_segment = id
        .strip_prefix("c-")
        .and_then(|rest| rest.rsplit_once('-'))
        .map(|(domain, _)| domain);
    if let Some(domain) = domain_segment
        && domain != case.domain
    {
        out.push(Diagnostic::deny(
            "lint/id-domain",
            "/case/id",
            format!("the file lives in `{}/` but its identifier names the domain `{domain}`", case.domain),
        ));
    }
    match meta.read("caseMeta.schema_version").and_then(Value::as_integer) {
        Some(version) if version == SCHEMA_VERSION => {}
        Some(version) => out.push(Diagnostic::deny(
            "lint/schema-version",
            "/case/schema_version",
            format!("this case is schema version {version}; this runner implements {SCHEMA_VERSION}. Update the runner — never skip the case and never ignore fields it does not understand"),
        )),
        None => out.push(Diagnostic::deny(
            "lint/schema-version",
            "/case/schema_version",
            "no schema_version; a case whose version is unknown cannot be trusted to mean what it appears to mean",
        )),
    }
    if case.quirks().is_empty() {
        out.push(Diagnostic::warn(
            "lint/quirks-empty",
            "/case/quirks",
            "no quirk is referenced, so the mutation gate has nothing to hold this case against; \
             an empty list is only legitimate while model/overlays/ has no matching entry",
        ));
    }
}

fn check_goldens(case: &Case, missing: &BTreeSet<String>, out: &mut Vec<Diagnostic>) {
    for exchange in case.exchanges() {
        let Some(expect) = exchange.expect else { continue };
        let Some(relative) = expect.path("body/golden").and_then(Value::as_str) else { continue };
        if missing.contains(relative) {
            out.push(Diagnostic::deny(
                "lint/golden-missing",
                &format!("{}/expect/body/golden", exchange.pointer),
                format!("golden `{relative}` does not exist in the corpus"),
            ));
        }
    }
}

fn check_interpolation(case: &Case, out: &mut Vec<Diagnostic>) {
    let Some(document) = case.document.as_ref() else { return };
    let mut available: BTreeSet<String> = BTreeSet::new();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    if let Some(setup) = document.read("setup") {
        for name in setup_captures(setup) {
            available.insert(name.clone());
            declared.insert(name);
        }
    }
    let mut used: BTreeSet<String> = BTreeSet::new();
    for exchange in case.exchanges() {
        let Some(request) = exchange.request else { continue };
        let mut strings = Vec::new();
        collect_strings(request, &mut strings);
        for text in &strings {
            for form in interpolate::unsupported_forms(text) {
                out.push(Diagnostic::deny(
                    "lint/interpolation-unsupported",
                    &format!("{}/request", exchange.pointer),
                    format!(
                        "`${{{form}}}` is not a capture reference. Schema version 1 has only \
                         `${{capture.<name>}}`; a computed value needs a schema change, not a \
                         runner-local expression language"
                    ),
                ));
            }
            for name in interpolate::referenced_captures(text) {
                used.insert(name.clone());
                if !available.contains(&name) {
                    out.push(Diagnostic::deny(
                        "lint/capture-unresolved",
                        &format!("{}/request", exchange.pointer),
                        format!(
                            "`${{capture.{name}}}` has no producer at this point; a capture must come \
                             from `setup` or from `expect.capture` on an earlier exchange"
                        ),
                    ));
                }
            }
        }
        if let Some(Value::Table(entries)) = exchange.expect.and_then(|expect| expect.read("expect.capture")) {
            for (name, _) in entries {
                available.insert(name.clone());
                declared.insert(name.clone());
            }
        }
    }
    for name in declared.difference(&used) {
        out.push(Diagnostic::warn(
            "lint/capture-unused",
            "/",
            format!("`{name}` is captured but never interpolated; a capture nothing reads asserts nothing"),
        ));
    }
    check_redaction_of_known_values(case, &used, out);
}

/// Redacting a value the case itself supplies deletes an assertion.
fn check_redaction_of_known_values(case: &Case, used: &BTreeSet<String>, out: &mut Vec<Diagnostic>) {
    if used.is_empty() {
        return;
    }
    for exchange in case.exchanges() {
        let Some(expect) = exchange.expect else { continue };
        let Some(body) = expect.read("expect.body") else { continue };
        for element in body.read_strings("bodyExpectation.redact").unwrap_or_default() {
            // `ContinuationToken` echoes back the token the request sent, and that token came from
            // a capture, so its value is known and could be asserted.
            if element.ends_with("ContinuationToken") && !element.starts_with("Next") {
                out.push(Diagnostic::warn(
                    "lint/redact-deterministic",
                    &format!("{}/expect/body/redact", exchange.pointer),
                    format!(
                        "<{element}> echoes a value this case already interpolated from a capture, so it \
                         is deterministic; redacting it quietly deletes the assertion that the server \
                         echoed the token it was given"
                    ),
                ));
            }
        }
    }
}

fn setup_captures(setup: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(Value::Array(uploads)) = setup.read("setup.multipart_uploads") {
        for upload in uploads {
            if let Some(name) = upload
                .read("setup.multipart_uploads[].capture_upload_id_as")
                .and_then(Value::as_str)
            {
                out.push(name.to_owned());
            }
            if let Some(Value::Array(parts)) = upload.read("setup.multipart_uploads[].parts") {
                for part in parts {
                    if let Some(name) = part
                        .read("setup.multipart_uploads[].parts[].capture_etag_as")
                        .and_then(Value::as_str)
                    {
                        out.push(name.to_owned());
                    }
                }
            }
        }
    }
    out
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        Value::Table(entries) => {
            for (_, item) in entries {
                collect_strings(item, out);
            }
        }
        _ => {}
    }
}

fn check_tags(case: &Case, out: &mut Vec<Diagnostic>) {
    for tag in case.tags() {
        if !TAG_VOCABULARY.contains(&tag) {
            out.push(Diagnostic::warn(
                "lint/tag-vocabulary",
                "/case/tags",
                format!(
                    "`{tag}` is not in the documented tag vocabulary; add it to conformance/README.md \
                     and to TAG_VOCABULARY in the same change, or use an existing tag"
                ),
            ));
        }
    }
}

fn check_assertion_strength(case: &Case, out: &mut Vec<Diagnostic>) {
    for exchange in case.exchanges() {
        let Some(expect) = exchange.expect else { continue };
        // Written out rather than looped over a list of names: one source location may claim one
        // schema key, because a loop over a name list is exactly how `crate::keys` would be made
        // to report full coverage while reading nothing. The array is built eagerly so that
        // short-circuiting cannot hide a key from the ledger either.
        let asserts_more_than_status = [
            expect.read("expect.body").is_some(),
            expect.read("expect.headers_present").is_some(),
            expect.read("expect.headers_exact").is_some(),
            expect.read("expect.headers_absent").is_some(),
            expect.read("expect.error").is_some(),
            expect.read("expect.events").is_some(),
        ]
        .iter()
        .any(|found| *found);
        if expect.read("expect.status").is_some() && !asserts_more_than_status {
            out.push(Diagnostic::warn(
                "lint/status-only",
                &format!("{}/expect", exchange.pointer),
                "this exchange asserts only a status code; a suite that checks status stays green \
                 through a rewrite that changes element order, drops the xmlns or alters the \
                 Content-Type",
            ));
        }
        // A body containing a server-generated instant cannot be compared byte for byte unless the
        // clock the target observes is pinned.
        let body = expect.read("expect.body");
        let exact = body.and_then(|body| body.read("bodyExpectation.exact_utf8"));
        let pins_bytes = exact.is_some() || body.and_then(|body| body.read("bodyExpectation.golden")).is_some();
        let embeds_instant = exact
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("<LastModified>") || text.contains("<Expires>"));
        let clock_pinned = case
            .document
            .as_ref()
            .and_then(|doc| doc.read("clock"))
            .and_then(|clock| clock.read("clock.fixed"))
            .is_some();
        if pins_bytes && embeds_instant && !clock_pinned {
            out.push(Diagnostic::warn(
                "lint/timestamp-without-clock",
                &format!("{}/expect/body", exchange.pointer),
                "the expected body embeds a timestamp but `[clock] fixed` is not set, so this case \
                 cannot be deterministic",
            ));
        }
    }
}

fn check_hand_computed_values(case: &Case, out: &mut Vec<Diagnostic>) {
    for exchange in case.exchanges() {
        let Some(request) = exchange.request else { continue };
        let Some(Value::Table(headers)) = request.read("requestSpec.headers") else { continue };
        for (name, _) in headers {
            let lowered = name.to_ascii_lowercase();
            let is_digest = COMPUTED_HEADERS.contains(&lowered.as_str())
                || (lowered.starts_with("x-amz-checksum-") && request.read("requestSpec.body").is_some());
            if is_digest {
                out.push(Diagnostic::warn(
                    "lint/hand-computed-digest",
                    &format!("{}/request/headers/{name}", exchange.pointer),
                    format!(
                        "`{name}` is a digest of the request body written into the case by hand; \
                         nothing recomputes it when the body changes. Schema version 1 has no \
                         expression form for a computed value, so this needs a schema change before \
                         it can be fixed"
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::Corpus;
    use crate::diagnostic::Severity;

    fn linted() -> Corpus {
        let root = Corpus::discover_root().expect("the repository corpus");
        let mut corpus = Corpus::load(&root).expect("the corpus loads");
        lint(&mut corpus);
        corpus
    }

    #[test]
    fn the_repository_corpus_has_no_denied_convention_violation() {
        let corpus = linted();
        let denied: Vec<String> = corpus
            .cases()
            .iter()
            .flat_map(|case| {
                case.diagnostics
                    .iter()
                    .filter(|d| d.severity == Severity::Deny)
                    .map(move |d| format!("{}: {d}", case.relative))
            })
            .collect();
        assert!(denied.is_empty(), "convention violations:\n{}", denied.join("\n"));
    }

    #[test]
    fn negative_cases_outnumber_positive_ones() {
        let (negative, positive) = polarity_balance(&linted());
        assert!(negative >= positive, "{negative} negative versus {positive} positive");
    }

    #[test]
    fn every_case_declares_a_rationale_and_evidence() {
        let corpus = linted();
        for case in corpus.cases() {
            // `get`, not `read`: `caseMeta.rationale` is declared inert in `crate::keys`, and a
            // test recording it would contradict that declaration.
            let rationale = case.document.as_ref().and_then(|doc| doc.path("case/rationale"));
            assert!(rationale.is_some(), "{} has no rationale", case.relative);
            let evidence = case
                .document
                .as_ref()
                .and_then(|doc| doc.path("case/evidence"))
                .and_then(Value::as_array)
                .map(<[Value]>::len)
                .unwrap_or(0);
            assert!(evidence > 0, "{} has no evidence", case.relative);
        }
    }

    #[test]
    fn a_case_whose_identifier_disagrees_with_its_file_is_denied() {
        let root = Corpus::discover_root().expect("the repository corpus");
        let mut corpus = Corpus::load(&root).expect("the corpus loads");
        let case = &mut corpus.cases_mut()[0];
        if let Some(document) = case.document.as_mut()
            && let Some(meta) = document.get_mut("case")
        {
            meta.insert("id", Value::String("c-etag-9999".to_owned()));
        }
        lint(&mut corpus);
        let found = corpus.cases()[0].diagnostics.iter().any(|d| d.rule == "lint/id-file-name");
        assert!(found, "{:?}", corpus.cases()[0].diagnostics);
    }

    #[test]
    fn an_unresolved_capture_reference_is_denied() {
        let root = Corpus::discover_root().expect("the repository corpus");
        let mut corpus = Corpus::load(&root).expect("the corpus loads");
        for case in corpus.cases_mut() {
            if case.id != "c-cond-0001" {
                continue;
            }
            if let Some(document) = case.document.as_mut()
                && let Some(request) = document.get_mut("request")
            {
                request.insert("target", Value::String("/b/${capture.nothing}".to_owned()));
            }
        }
        lint(&mut corpus);
        let case = corpus
            .cases()
            .iter()
            .find(|case| case.id == "c-cond-0001")
            .expect("c-cond-0001");
        assert!(
            case.diagnostics.iter().any(|d| d.rule == "lint/capture-unresolved"),
            "{:?}",
            case.diagnostics
        );
    }

    #[test]
    fn a_computed_interpolation_form_is_denied_rather_than_invented() {
        let root = Corpus::discover_root().expect("the repository corpus");
        let mut corpus = Corpus::load(&root).expect("the corpus loads");
        for case in corpus.cases_mut() {
            if case.id != "c-cond-0001" {
                continue;
            }
            if let Some(document) = case.document.as_mut()
                && let Some(request) = document.get_mut("request")
            {
                request.insert("target", Value::String("/b/${md5(body)}".to_owned()));
            }
        }
        lint(&mut corpus);
        let case = corpus
            .cases()
            .iter()
            .find(|case| case.id == "c-cond-0001")
            .expect("c-cond-0001");
        assert!(
            case.diagnostics.iter().any(|d| d.rule == "lint/interpolation-unsupported"),
            "{:?}",
            case.diagnostics
        );
    }
}
