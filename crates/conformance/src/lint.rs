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
//! every `${capture.*}` in either half of an exchange has a producer earlier in the same case and
//! sits where substitution can reach it, that a tag is in the documented vocabulary, and that a
//! value the runner could compute was not written into the file by hand.
//! Rules that make a case unusable deny; rules that describe drift warn, because a warning that
//! fails the build gets suppressed and a suppressed rule teaches nothing.
//! NOT responsible for: schema validation (`crate::schema`) or execution (`crate::runner`).
//! Upstream: `crate::corpus`, `crate::interpolate`. Downstream: `crate::runner`.

use crate::corpus::{Case, Corpus, Exchange};
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
    // The standard object attributes a write sets and a read returns: content type,
    // encoding, language, disposition, cache control and the opaque Expires string.
    "object-attributes",
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
        check_stale_digests(case, &mut found);
        check_committed_fault(case, &mut found);
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

/// The operations whose response head goes out before the outcome is known.
///
/// AWS documents each of these three as able to answer `200` and then report a failure in the body,
/// and `generated/error_codes.rs` carries the same three as `ERROR_AFTER_200`, lowered from the
/// model. The two lists are held equal by a test rather than by a comment, because a fourth
/// operation gaining the property in the model and not here would let a case declare a fault at a
/// point that operation never reaches — and a fault at a point nothing reaches is an assertion that
/// cannot fail.
pub const COMMITS_HEAD_EARLY: &[&str] = &["CompleteMultipartUpload", "CopyObject", "UploadPartCopy"];

/// The `setup.fault.at` points that exist only below a committed head.
///
/// Both of them: a continuation that reports a failure, and a continuation that reports nothing.
/// Listed rather than matched one at a time, because the operation check below is the same check
/// for both and a second `at` value added without a row here would silently stop being checked —
/// which is how a case ends up declaring a scenario its target cannot produce.
const POINTS_BELOW_THE_COMMIT: &[&str] = &["after_commit", "no_progress_after_commit"];

/// A fault declared after a commit must name an operation that commits.
///
/// The points named by [`POINTS_BELOW_THE_COMMIT`] exist only for an operation that sends its head
/// before it knows the outcome. For any other, the failure would be discovered while a status was
/// still choosable and delivered as an ordinary refusal — the case would run, it would be given the
/// refusal it did not ask for, and whether it noticed would depend on what else it happened to
/// assert. This denies instead: a case whose scenario cannot occur is unusable, not merely drifting.
fn check_committed_fault(case: &Case, out: &mut Vec<Diagnostic>) {
    let Some(document) = case.document.as_ref() else { return };
    // Two statements, not one chain: the key ledger records the *source location* of each read, and
    // one location claiming two keys is how this audit would be made vacuous.
    let Some(setup) = document.read("setup") else { return };
    let Some(fault) = setup.read("setup.fault") else { return };
    let at = fault.read("setup.fault.at").and_then(Value::as_str).unwrap_or_default();
    if !POINTS_BELOW_THE_COMMIT.contains(&at) {
        return;
    }
    let operation = fault
        .read("setup.fault.operation")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !COMMITS_HEAD_EARLY.contains(&operation) {
        out.push(Diagnostic::deny(
            "lint/fault-after-commit",
            "/setup/fault/operation",
            format!(
                "`{operation}` does not commit its response head before it knows the outcome, so there \
                 is no point in it at which `{at}` could happen; the operations that do are {}",
                COMMITS_HEAD_EARLY.join(", ")
            ),
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
        // Both halves of an exchange are interpolated by the runner, so both are checked here, and
        // both are checked *before* this exchange's own captures are declared available: an
        // expectation is judged before its captures are collected, so it can only name a value an
        // earlier exchange bound. Scanning the request alone was the gap that let
        // `not_contains_utf8 = ["${capture.x}"]` reach a comparison as eleven literal characters.
        for (half, value) in [("request", exchange.request), ("expect", exchange.expect)] {
            let Some(value) = value else { continue };
            // A field *name* is never substituted — the runner refuses one that tries — so a
            // reference written there is caught at load time rather than at the moment the case
            // would otherwise have run with it silently in place.
            for key in reference_bearing_keys(value) {
                out.push(Diagnostic::deny(
                    "lint/interpolation-in-field-name",
                    &format!("{}/{half}", exchange.pointer),
                    format!(
                        "`{key}` uses `${{...}}` in a field name. Substitution applies to values only; \
                         a header name or a capture name is written out in full"
                    ),
                ));
            }
            let mut strings = Vec::new();
            collect_strings(value, &mut strings);
            for text in &strings {
                for form in interpolate::unsupported_forms(text) {
                    out.push(Diagnostic::deny(
                        "lint/interpolation-unsupported",
                        &format!("{}/{half}", exchange.pointer),
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
                            &format!("{}/{half}", exchange.pointer),
                            format!(
                                "`${{capture.{name}}}` has no producer at this point; a capture must come \
                                 from `setup` or from `expect.capture` on an earlier exchange"
                            ),
                        ));
                    }
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

/// Every table key anywhere under `value` that carries a `${...}`.
///
/// `collect_strings` walks values, which is what substitution acts on. This walks the other half of
/// each table, which is what substitution deliberately does not act on — and therefore the half
/// where a reference would sit unresolved and unreported.
fn reference_bearing_keys(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            Value::Table(entries) => {
                for (key, item) in entries {
                    if key.contains("${") {
                        out.push(key.clone());
                    }
                    walk(item, out);
                }
            }
            _ => {}
        }
    }
    walk(value, &mut out);
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

/// Refuses a case whose `Content-MD5` is not the digest of the body it is written beside.
///
/// [`check_hand_computed_values`] says a hand-written digest is one nobody recomputes when the body
/// changes. This is the half of that statement that can be enforced today: the value cannot be
/// *computed* from the case, but it can be *checked* against it, and a stale one is now a broken
/// case rather than a warning. The gateway verifies the header against the body it received, so a
/// case carrying a stale digest no longer tests what its title says — it tests `BadDigest`.
///
/// Three restrictions, each of which skips rather than guesses:
///
/// * only a literal `utf8` or `hex` payload. A `file` or a generated `size`/`fill` body is not
///   reconstructible here, and a body carrying a `${capture}` is not known until the case runs.
/// * only `content-md5`. `x-amz-content-sha256` takes the signing sentinels (`UNSIGNED-PAYLOAD`
///   and the streaming spellings) as often as it takes a hash, and the checksum headers cover
///   several algorithms; neither is one comparison.
/// * a case that *expects* `BadDigest` or `InvalidDigest` is stating the disagreement on purpose,
///   and is left alone. `c-mpu-0044` is the one that was already doing this.
fn check_stale_digests(case: &Case, out: &mut Vec<Diagnostic>) {
    for exchange in case.exchanges() {
        let Some(request) = exchange.request else { continue };
        let Some(Value::Table(headers)) = request.read("requestSpec.headers") else { continue };
        let Some(declared) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-md5"))
            .and_then(|(_, value)| value.as_str())
        else {
            continue;
        };
        if deliberate_digest_failure(&exchange) {
            continue;
        }
        let Some(body) = literal_body(request) else { continue };
        let actual = crate::fixture::encode_base64(&crate::md5::digest(&body));
        if declared == actual {
            continue;
        }
        out.push(Diagnostic::deny(
            "lint/stale-digest",
            &format!("{}/request/headers/content-md5", exchange.pointer),
            format!(
                "`content-md5` is not the digest of this exchange's body, so the request under \
                 test is refused as `BadDigest` before it reaches what the case is about. The \
                 digest of the body as written is `{actual}`"
            ),
        ));
    }
}

/// The body of one request, when it is written out literally and holds no interpolation.
fn literal_body(request: &Value) -> Option<Vec<u8>> {
    let payload = request.read("requestSpec.body")?;
    if let Some(text) = payload.read("payload.utf8").and_then(Value::as_str) {
        return (!text.contains("${")).then(|| text.as_bytes().to_vec());
    }
    let hex = payload.read("payload.hex").and_then(Value::as_str)?;
    if hex.contains("${") || !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(*pair.first()?).to_digit(16)?;
            let low = char::from(*pair.get(1)?).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// Whether this exchange expects the digest refusal, which is how a case says the mismatch is the
/// point rather than an accident.
fn deliberate_digest_failure(exchange: &Exchange<'_>) -> bool {
    exchange
        .expect
        .and_then(|expect| expect.read("expect.error"))
        .and_then(|error| error.read("expect.error.code"))
        .and_then(Value::as_str)
        .is_some_and(|code| code == "BadDigest" || code == "InvalidDigest")
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
mod tests;
