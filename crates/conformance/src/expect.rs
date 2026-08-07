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

//! The expectation engine: one `[expect]` block judged against one [`Observation`].
//!
//! Responsible for: every assertion the frozen schema can express, evaluated independently so that
//! one failure does not hide the next — a case that fails on status must still report that its
//! `Content-Type` was wrong too. Byte-exactness is the first-class comparison; the `xml` block is
//! an additive diagnostic and never replaces it.
//! NOT responsible for: performing the exchange (`crate::sut`), interpolation (`crate::interpolate`),
//! or deciding what a failure means for the run (`crate::report`).
//! Upstream: `crate::observation`, `crate::xml`, `crate::sha256`. Downstream: `crate::runner`.

use std::borrow::Cow;

use crate::diagnostic::Diagnostic;
use crate::interpolate::Captures;
use crate::observation::Observation;
use crate::sha256;
use crate::value::Value;
use crate::xml;

/// Headers the transport itself manages, excluded from `headers_exact`.
///
/// Listed in `conformance/README.md`. A case that cares about one of these asserts it explicitly
/// through `headers_present`.
pub const HOP_BY_HOP: &[&str] = &["connection", "keep-alive", "transfer-encoding", "date"];

/// Supplies the byte-exact bodies a case references by path.
pub trait GoldenSource {
    /// Reads a corpus-relative golden file.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when the file cannot be read.
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String>;
}

/// The result of judging one exchange.
#[derive(Debug, Clone, Default)]
pub struct Judgement {
    /// Every assertion that failed, in evaluation order.
    pub diagnostics: Vec<Diagnostic>,
    /// Values bound by `expect.capture`, for later exchanges to interpolate.
    pub captures: Captures,
}

impl Judgement {
    /// Whether every assertion held.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

/// Judges `expect` against `observed`.
///
/// `pointer` is the JSON pointer prefix of the expectation inside the case document, so a failure
/// names the field the author wrote rather than an assertion number.
#[must_use]
pub fn judge(expect: &Value, observed: &Observation, pointer: &str, goldens: &dyn GoldenSource) -> Judgement {
    let mut judgement = Judgement::default();
    let out = &mut judgement.diagnostics;

    check_kind(expect, observed, pointer, out);
    check_status(expect, observed, pointer, out);
    check_error(expect, observed, pointer, out);
    check_headers(expect, observed, pointer, out);
    check_trailers(expect, observed, pointer, out);
    check_body(expect, observed, pointer, goldens, out);
    check_counters(expect, observed, pointer, out);
    check_timing(expect, observed, pointer, out);
    check_connection(expect, observed, pointer, out);
    check_events(expect, observed, pointer, out);
    judgement.captures = collect_captures(expect, observed, pointer, out);
    judgement
}

fn check_kind(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    if let Some(kind) = expect.read("expect.kind").and_then(Value::as_str)
        && kind != observed.outcome.as_kind()
    {
        out.push(Diagnostic::deny(
            "expect/kind",
            &format!("{pointer}/kind"),
            format!("expected the exchange to end as `{kind}`, it ended as `{}`", observed.outcome.as_kind()),
        ));
    }
    if let Some(expected) = expect.read("expect.stream_termination").and_then(Value::as_str) {
        let actual = observed.stream_termination.map(|value| value.as_str());
        if actual != Some(expected) {
            out.push(Diagnostic::deny(
                "expect/stream_termination",
                &format!("{pointer}/stream_termination"),
                format!("expected `{expected}`, observed `{}`", actual.unwrap_or("nothing")),
            ));
        }
    }
    if let Some(expected) = expect.read("expect.http_version").and_then(Value::as_str)
        && observed.http_version.as_deref() != Some(expected)
    {
        out.push(Diagnostic::deny(
            "expect/http_version",
            &format!("{pointer}/http_version"),
            format!(
                "expected `{expected}`, observed `{}`",
                observed.http_version.as_deref().unwrap_or("nothing")
            ),
        ));
    }
}

fn check_status(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(expected) = expect.read("expect.status").and_then(Value::as_integer) else { return };
    match observed.status {
        Some(actual) if i64::from(actual) == expected => {}
        Some(actual) => out.push(Diagnostic::deny(
            "expect/status",
            &format!("{pointer}/status"),
            format!("expected status {expected}, observed {actual}"),
        )),
        None => out.push(Diagnostic::deny(
            "expect/status",
            &format!("{pointer}/status"),
            format!("expected status {expected}, but no response head arrived"),
        )),
    }
}

fn check_error(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(error) = expect.read("expect.error") else { return };
    let body = observed.body_text();
    if let Some(expected) = error.read("expect.error.code").and_then(Value::as_str) {
        match xml::first_element_text(&body, "Code") {
            Some(actual) if actual == expected => {}
            Some(actual) => out.push(Diagnostic::deny(
                "expect/error.code",
                &format!("{pointer}/error/code"),
                format!("expected <Code>{expected}</Code>, the body carried <Code>{actual}</Code>"),
            )),
            None => out.push(Diagnostic::deny(
                "expect/error.code",
                &format!("{pointer}/error/code"),
                format!("expected <Code>{expected}</Code>, the body carried no <Code> element at all"),
            )),
        }
    }
    if let Some(expected) = error.read("expect.error.resource").and_then(Value::as_str) {
        let actual = xml::first_element_text(&body, "Resource");
        if actual.as_deref() != Some(expected) {
            out.push(Diagnostic::deny(
                "expect/error.resource",
                &format!("{pointer}/error/resource"),
                format!("expected <Resource>{expected}</Resource>, observed {:?}", actual.unwrap_or_default()),
            ));
        }
    }
    // Written out rather than looped over a list of field names: `crate::keys` allows one source
    // location to claim one schema key, precisely so that a loop over a name list cannot be used to
    // report coverage of keys nothing reads.
    let message = error.read("expect.error.message_present").and_then(Value::as_bool);
    let request_id = error.read("expect.error.request_id_present").and_then(Value::as_bool);
    check_presence(message, &body, "Message", "message_present", pointer, out);
    check_presence(request_id, &body, "RequestId", "request_id_present", pointer, out);
}

/// One `<Element> is present and non-empty` assertion.
fn check_presence(required: Option<bool>, body: &str, element: &str, field: &str, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(required) = required else { return };
    let present = xml::first_element_text(body, element).is_some_and(|text| !text.trim().is_empty());
    if present != required {
        out.push(Diagnostic::deny(
            &format!("expect/error.{field}"),
            &format!("{pointer}/error/{field}"),
            format!("expected <{element}> to be {}, it was {}", presence(required), presence(present)),
        ));
    }
}

fn presence(present: bool) -> &'static str {
    if present { "present and non-empty" } else { "absent" }
}

fn check_headers(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let byte_exact = expect
        .read("expect.header_name_bytes_exact")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let name_eq = |left: &str, right: &str| {
        if byte_exact {
            left == right
        } else {
            left.eq_ignore_ascii_case(right)
        }
    };

    if let Some(Value::Table(required)) = expect.read("expect.headers_present") {
        for (name, wanted) in required {
            let observed_values: Vec<&str> = observed
                .headers
                .iter()
                .filter(|(key, _)| name_eq(key, name))
                .map(|(_, value)| value.as_str())
                .collect();
            for expected in expected_values(wanted) {
                let hit = if expected == "*" {
                    !observed_values.is_empty()
                } else {
                    observed_values.contains(&expected)
                };
                if !hit {
                    out.push(Diagnostic::deny(
                        "expect/headers_present",
                        &format!("{pointer}/headers_present/{name}"),
                        format!(
                            "expected `{name}: {expected}`, observed {}",
                            if observed_values.is_empty() {
                                "no such header".to_owned()
                            } else {
                                format!("`{}`", observed_values.join("`, `"))
                            }
                        ),
                    ));
                }
            }
        }
    }

    if let Some(Value::Array(forbidden)) = expect.read("expect.headers_absent") {
        for name in forbidden.iter().filter_map(Value::as_str) {
            if let Some((key, value)) = observed.headers.iter().find(|(key, _)| name_eq(key, name)) {
                out.push(Diagnostic::deny(
                    "expect/headers_absent",
                    &format!("{pointer}/headers_absent"),
                    format!("`{name}` must not be present; the response carried `{key}: {value}`"),
                ));
            }
        }
    }

    if let Some(Value::Table(exact)) = expect.read("expect.headers_exact") {
        for (name, _) in observed
            .headers
            .iter()
            .filter(|(key, _)| !HOP_BY_HOP.iter().any(|hop| key.eq_ignore_ascii_case(hop)))
        {
            if !exact.iter().any(|(expected_name, _)| name_eq(expected_name, name)) {
                out.push(Diagnostic::deny(
                    "expect/headers_exact",
                    &format!("{pointer}/headers_exact"),
                    format!("`{name}` is on the wire but not in the complete header set the case declares"),
                ));
            }
        }
        for (name, wanted) in exact {
            let observed_values: Vec<&str> = observed
                .headers
                .iter()
                .filter(|(key, _)| name_eq(key, name))
                .map(|(_, value)| value.as_str())
                .collect();
            for expected in expected_values(wanted) {
                let hit = if expected == "*" {
                    !observed_values.is_empty()
                } else {
                    observed_values.contains(&expected)
                };
                if !hit {
                    out.push(Diagnostic::deny(
                        "expect/headers_exact",
                        &format!("{pointer}/headers_exact/{name}"),
                        format!("expected `{name}: {expected}`, observed {observed_values:?}"),
                    ));
                }
            }
        }
    }

    if let Some(Value::Array(order)) = expect.read("expect.header_order") {
        let wanted: Vec<&str> = order.iter().filter_map(Value::as_str).collect();
        let positions: Vec<Option<usize>> = wanted
            .iter()
            .map(|name| observed.headers.iter().position(|(key, _)| name_eq(key, name)))
            .collect();
        let mut previous: Option<usize> = None;
        for (name, position) in wanted.iter().zip(&positions) {
            match position {
                None => out.push(Diagnostic::deny(
                    "expect/header_order",
                    &format!("{pointer}/header_order"),
                    format!("`{name}` is named in header_order but is not on the wire"),
                )),
                Some(index) => {
                    if previous.is_some_and(|earlier| *index < earlier) {
                        out.push(Diagnostic::deny(
                            "expect/header_order",
                            &format!("{pointer}/header_order"),
                            format!("`{name}` appears earlier on the wire than the declared order allows"),
                        ));
                    }
                    previous = Some(*index);
                }
            }
        }
    }
}

fn check_trailers(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    if let Some(Value::Table(required)) = expect.read("expect.trailers_present") {
        for (name, wanted) in required {
            let values: Vec<&str> = observed
                .trailers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect();
            for expected in expected_values(wanted) {
                let hit = if expected == "*" {
                    !values.is_empty()
                } else {
                    values.contains(&expected)
                };
                if !hit {
                    out.push(Diagnostic::deny(
                        "expect/trailers_present",
                        &format!("{pointer}/trailers_present/{name}"),
                        format!("expected trailer `{name}: {expected}`, observed {values:?}"),
                    ));
                }
            }
        }
    }
    if let Some(Value::Array(forbidden)) = expect.read("expect.trailers_absent") {
        for name in forbidden.iter().filter_map(Value::as_str) {
            if observed.trailers.iter().any(|(key, _)| key.eq_ignore_ascii_case(name)) {
                out.push(Diagnostic::deny(
                    "expect/trailers_absent",
                    &format!("{pointer}/trailers_absent"),
                    format!("trailer `{name}` must not be present"),
                ));
            }
        }
    }
}

fn expected_values(value: &Value) -> Vec<&str> {
    match value {
        Value::String(text) => vec![text.as_str()],
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn check_body(expect: &Value, observed: &Observation, pointer: &str, goldens: &dyn GoldenSource, out: &mut Vec<Diagnostic>) {
    let Some(body) = expect.read("expect.body") else { return };
    let at = format!("{pointer}/body");
    let raw_text = observed.body_text();
    let redactions: Vec<&str> = body.read_strings("bodyExpectation.redact").unwrap_or_default();

    if let Some(expected) = body.read("bodyExpectation.exact_utf8").and_then(Value::as_str) {
        compare_exact(expected.as_bytes(), &observed.body, &redactions, &at, "exact_utf8", out);
    }
    if let Some(expected) = body.read("bodyExpectation.exact_hex").and_then(Value::as_str) {
        match decode_hex(expected) {
            Some(bytes) => compare_exact(&bytes, &observed.body, &redactions, &at, "exact_hex", out),
            None => out.push(Diagnostic::deny("expect/body.exact_hex", &at, "the expectation is not valid hex")),
        }
    }
    if let Some(relative) = body.read("bodyExpectation.golden").and_then(Value::as_str) {
        match goldens.read_golden(relative) {
            // One trailing newline is stripped because editors and CI add it; every other byte is
            // significant.
            Ok(bytes) => {
                let trimmed = strip_one_trailing_newline(&bytes);
                compare_exact(trimmed, &observed.body, &redactions, &at, "golden", out);
            }
            Err(reason) => out.push(Diagnostic::deny(
                "expect/body.golden",
                &at,
                format!("golden `{relative}` could not be read: {reason}"),
            )),
        }
    }
    if let Some(expected) = body.read("bodyExpectation.sha256").and_then(Value::as_str) {
        let actual = sha256::hex_digest(&observed.body);
        if actual != expected {
            out.push(Diagnostic::deny(
                "expect/body.sha256",
                &at,
                format!("expected sha256 {expected}, observed {actual} over {} bytes", observed.body.len()),
            ));
        }
    }
    if let Some(expected) = body.read("bodyExpectation.size").and_then(Value::as_integer)
        && observed.body.len() as i64 != expected
    {
        out.push(Diagnostic::deny(
            "expect/body.size",
            &at,
            format!("expected a {expected}-byte body, observed {} bytes", observed.body.len()),
        ));
    }
    // `redact` is what the schema says it is — the named text is replaced "in both the observed
    // body and the expectation before comparison" — and `contains_utf8` is a comparison. Judging it
    // against the raw bytes is what made `<NextContinuationToken>__REDACTED__</NextContinuationToken>`,
    // the only spelling by which a case can assert *where* a server-minted value sits, impossible to
    // satisfy against any real response. `c-list-0042` is the case that could not pass.
    //
    // Both sides go through it: a no-op on a needle that already holds the placeholder, and — see
    // `xml::redact` — never a fill for `<X></X>`, so "present and not empty" stays sayable.
    let searched: Cow<'_, str> = if redactions.is_empty() {
        Cow::Borrowed(raw_text.as_str())
    } else {
        Cow::Owned(xml::redact(&raw_text, &redactions))
    };
    for needle in body.read_strings("bodyExpectation.contains_utf8").unwrap_or_default() {
        let expected = if redactions.is_empty() {
            Cow::Borrowed(needle)
        } else {
            Cow::Owned(xml::redact(needle, &redactions))
        };
        if !searched.contains(expected.as_ref()) {
            out.push(Diagnostic::deny(
                "expect/body.contains_utf8",
                &at,
                format!("the body does not contain {needle:?}"),
            ));
        }
    }
    // `not_contains_utf8` deliberately does **not** get the same treatment: it reads the bytes as
    // they arrived. A prohibition is about what actually went on the wire, and redacting first would
    // excuse the forbidden bytes for appearing inside exactly the element the case chose to redact —
    // which is where a leaked string-to-sign or credential would appear. `redaction_does_not_excuse`
    // below is the test that keeps the asymmetry deliberate.
    for needle in body.read_strings("bodyExpectation.not_contains_utf8").unwrap_or_default() {
        if let Some(offset) = raw_text.find(needle) {
            out.push(Diagnostic::deny(
                "expect/body.not_contains_utf8",
                &at,
                format!("the body must not contain {needle:?}, found at byte {offset}"),
            ));
        }
    }
    check_body_xml(body, &raw_text, &at, out);
}

fn check_body_xml(body: &Value, text: &str, at: &str, out: &mut Vec<Diagnostic>) {
    let Some(spec) = body.read("bodyExpectation.xml") else { return };
    let root = xml::root_tag(text);
    if let Some(expected) = spec.read("bodyExpectation.xml.root").and_then(Value::as_str) {
        let actual = root.as_ref().map(|tag| tag.name.as_str());
        if actual != Some(expected) {
            out.push(Diagnostic::deny(
                "expect/body.xml.root",
                &format!("{at}/xml/root"),
                format!("expected root element <{expected}>, observed <{}>", actual.unwrap_or("nothing")),
            ));
        }
    }
    if let Some(expected) = spec.read("bodyExpectation.xml.xmlns").and_then(Value::as_str) {
        let actual = root.as_ref().and_then(|tag| tag.attribute("xmlns"));
        if actual.as_deref() != Some(expected) {
            out.push(Diagnostic::deny(
                "expect/body.xml.xmlns",
                &format!("{at}/xml/xmlns"),
                format!("expected xmlns={expected:?}, observed {:?}", actual.unwrap_or_default()),
            ));
        }
    }
    if let Some(expected) = spec.read("bodyExpectation.xml.declaration").and_then(Value::as_bool)
        && xml::has_declaration(text) != expected
    {
        out.push(Diagnostic::deny(
            "expect/body.xml.declaration",
            &format!("{at}/xml/declaration"),
            format!("expected the XML declaration to be {}", if expected { "present" } else { "absent" }),
        ));
    }
    if let Some(order) = spec.read_strings("bodyExpectation.xml.element_order")
        && !order.is_empty()
    {
        let observed_names = xml::root_child_names(text);
        let mut cursor = 0;
        for name in &order {
            match observed_names.iter().skip(cursor).position(|child| child == name) {
                Some(offset) => cursor += offset + 1,
                None => out.push(Diagnostic::deny(
                    "expect/body.xml.element_order",
                    &format!("{at}/xml/element_order"),
                    format!(
                        "<{name}> does not appear after the elements declared before it; observed order was {observed_names:?}"
                    ),
                )),
            }
        }
    }
    if let Some(expected) = spec.read("bodyExpectation.xml.empty_elements").and_then(Value::as_str) {
        let styles = xml::empty_element_styles(text);
        for (name, style) in &styles {
            let actual = match style {
                xml::EmptyElementStyle::SelfClosing => "self_closing",
                xml::EmptyElementStyle::Paired => "paired",
            };
            let acceptable = match expected {
                "absent" => false,
                other => other == actual,
            };
            if !acceptable {
                out.push(Diagnostic::deny(
                    "expect/body.xml.empty_elements",
                    &format!("{at}/xml/empty_elements"),
                    format!("<{name}> is rendered as `{actual}`, the case requires `{expected}`"),
                ));
            }
        }
    }
}

fn compare_exact(expected: &[u8], observed: &[u8], redactions: &[&str], at: &str, field: &str, out: &mut Vec<Diagnostic>) {
    let (left, right) = if redactions.is_empty() {
        (expected.to_vec(), observed.to_vec())
    } else {
        let left = xml::redact(&String::from_utf8_lossy(expected), redactions);
        let right = xml::redact(&String::from_utf8_lossy(observed), redactions);
        (left.into_bytes(), right.into_bytes())
    };
    if left == right {
        return;
    }
    let offset = first_difference(&left, &right);
    out.push(Diagnostic::deny(
        &format!("expect/body.{field}"),
        at,
        format!(
            "bodies differ at byte {offset} (expected {} bytes, observed {} bytes)\n    expected: {}\n    observed: {}",
            left.len(),
            right.len(),
            window(&left, offset),
            window(&right, offset),
        ),
    ));
}

fn first_difference(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| left.len().min(right.len()))
}

/// A short, escaped slice around `offset`, so a failure shows the bytes rather than the whole body.
fn window(bytes: &[u8], offset: usize) -> String {
    const RADIUS: usize = 40;
    let start = offset.saturating_sub(RADIUS / 2);
    let end = (offset + RADIUS).min(bytes.len());
    let slice = bytes.get(start..end).unwrap_or_default();
    let rendered: String = String::from_utf8_lossy(slice).escape_debug().collect();
    let prefix = if start > 0 { "…" } else { "" };
    let suffix = if end < bytes.len() { "…" } else { "" };
    format!("{prefix}{rendered}{suffix}")
}

fn strip_one_trailing_newline(bytes: &[u8]) -> &[u8] {
    match bytes {
        [head @ .., b'\r', b'\n'] => head,
        [head @ .., b'\n'] => head,
        other => other,
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

fn check_counters(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    if let Some(expected) = expect.read("expect.body_bytes_before_error").and_then(Value::as_integer) {
        match observed.body_bytes_before_error {
            Some(actual) if actual as i64 == expected => {}
            Some(actual) => out.push(Diagnostic::deny(
                "expect/body_bytes_before_error",
                &format!("{pointer}/body_bytes_before_error"),
                format!("expected {expected} response bytes before the error, observed {actual}"),
            )),
            None => out.push(Diagnostic::deny(
                "expect/body_bytes_before_error",
                &format!("{pointer}/body_bytes_before_error"),
                format!("expected {expected} response bytes before the error, the transport did not record any"),
            )),
        }
    }
    let Some(progress) = expect.read("expect.request_progress") else { return };
    if let Some(expected) = progress
        .read("expect.request_progress.body_bytes_sent_at_response")
        .and_then(Value::as_integer)
    {
        match observed.request_body_bytes_sent_at_response {
            Some(actual) if actual as i64 == expected => {}
            Some(actual) => out.push(Diagnostic::deny(
                "expect/request_progress.body_bytes_sent_at_response",
                &format!("{pointer}/request_progress/body_bytes_sent_at_response"),
                format!(
                    "expected {expected} request-body bytes written when the head arrived, observed {actual}; \
                     a larger number means the server consumed the payload before refusing"
                ),
            )),
            None => out.push(Diagnostic::deny(
                "expect/request_progress.body_bytes_sent_at_response",
                &format!("{pointer}/request_progress/body_bytes_sent_at_response"),
                "the transport did not record how much of the request body had been written".to_owned(),
            )),
        }
    }
    if let Some(expected) = progress
        .read("expect.request_progress.body_fully_sent")
        .and_then(Value::as_bool)
    {
        match observed.request_body_fully_sent {
            Some(actual) if actual == expected => {}
            Some(actual) => out.push(Diagnostic::deny(
                "expect/request_progress.body_fully_sent",
                &format!("{pointer}/request_progress/body_fully_sent"),
                format!("expected body_fully_sent = {expected}, observed {actual}"),
            )),
            None => out.push(Diagnostic::deny(
                "expect/request_progress.body_fully_sent",
                &format!("{pointer}/request_progress/body_fully_sent"),
                "the transport did not record whether the request body was fully written".to_owned(),
            )),
        }
    }
}

fn check_timing(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(timing) = expect.read("expect.timing") else { return };
    let at = format!("{pointer}/timing");
    if let Some(limit) = timing.read("expect.timing.terminate_within_ms").and_then(Value::as_integer)
        && observed.elapsed_ms as i64 > limit
    {
        out.push(Diagnostic::deny(
            "expect/timing.terminate_within_ms",
            &at,
            format!(
                "the exchange took {}ms, the case allows {limit}ms; this is the assertion that \
                     catches a client left waiting",
                observed.elapsed_ms
            ),
        ));
    }
    if let Some(floor) = timing.read("expect.timing.no_response_before_ms").and_then(Value::as_integer)
        && let Some(ttfb) = observed.ttfb_ms
        && (ttfb as i64) < floor
    {
        out.push(Diagnostic::deny(
            "expect/timing.no_response_before_ms",
            &at,
            format!("the head arrived after {ttfb}ms, the case requires at least {floor}ms"),
        ));
    }
    // Two bounds, two reads, two lines: one source location may claim one schema key, so that a
    // loop over a list of field names cannot stand in for reading them.
    let ceiling = timing.read("expect.timing.ttfb_max_ms").and_then(Value::as_integer);
    let floor = timing.read("expect.timing.ttfb_min_ms").and_then(Value::as_integer);
    check_ttfb(ceiling, observed.ttfb_ms, Bound::Ceiling, &at, out);
    check_ttfb(floor, observed.ttfb_ms, Bound::Floor, &at, out);
}

/// Which end of the time-to-first-byte range a bound is.
#[derive(Debug, Clone, Copy)]
enum Bound {
    /// `ttfb_max_ms`.
    Ceiling,
    /// `ttfb_min_ms`.
    Floor,
}

fn check_ttfb(bound: Option<i64>, ttfb_ms: Option<u64>, end: Bound, at: &str, out: &mut Vec<Diagnostic>) {
    let Some(bound) = bound else { return };
    let rule = match end {
        Bound::Ceiling => "expect/timing.ttfb_max_ms",
        Bound::Floor => "expect/timing.ttfb_min_ms",
    };
    let Some(ttfb) = ttfb_ms else {
        out.push(Diagnostic::deny(rule, at, "the transport did not record time to first byte".to_owned()));
        return;
    };
    let violated = match end {
        Bound::Ceiling => ttfb as i64 > bound,
        Bound::Floor => (ttfb as i64) < bound,
    };
    if violated {
        out.push(Diagnostic::deny(rule, at, format!("time to first byte was {ttfb}ms, bound is {bound}ms")));
    }
}

fn check_connection(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(expected) = expect.read("expect.connection_after").and_then(Value::as_str) else { return };
    let actual = observed.connection_after.map(crate::observation::ConnectionState::as_str);
    if actual != Some(expected) {
        out.push(Diagnostic::deny(
            "expect/connection_after",
            &format!("{pointer}/connection_after"),
            format!(
                "expected the connection to be `{expected}` afterwards, observed `{}`",
                actual.unwrap_or("unknown")
            ),
        ));
    }
}

fn check_events(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(Value::Array(events)) = expect.read("expect.events") else { return };
    for (index, spec) in events.iter().enumerate() {
        let at = format!("{pointer}/events/{index}");
        let Some(event_type) = spec.read("expect.events[].type").and_then(Value::as_str) else { continue };
        let count = observed.events.iter().filter(|event| event.event_type == event_type).count() as i64;
        let minimum = spec
            .read("expect.events[].min_count")
            .and_then(Value::as_integer)
            .unwrap_or(1);
        let maximum = spec.read("expect.events[].max_count").and_then(Value::as_integer);
        if count < minimum {
            out.push(Diagnostic::deny(
                "expect/events.min_count",
                &at,
                format!("expected at least {minimum} `{event_type}` frames, observed {count}"),
            ));
        }
        if maximum.is_some_and(|limit| count > limit) {
            out.push(Diagnostic::deny(
                "expect/events.max_count",
                &at,
                format!("expected at most {} `{event_type}` frames, observed {count}", maximum.unwrap_or_default()),
            ));
        }
    }
}

fn collect_captures(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) -> Captures {
    let mut captures = Captures::new();
    let Some(Value::Table(entries)) = expect.read("expect.capture") else { return captures };
    let body = observed.body_text();
    for (name, source) in entries {
        let at = format!("{pointer}/capture/{name}");
        if let Some(element) = source.read("expect.capture.*.xml_text").and_then(Value::as_str) {
            match xml::first_element_text(&body, element) {
                Some(text) => {
                    captures.insert(name.clone(), text);
                }
                None => out.push(Diagnostic::deny(
                    "expect/capture",
                    &at,
                    format!("cannot capture `{name}`: the body has no <{element}> element"),
                )),
            }
        } else if let Some(header) = source.read("expect.capture.*.header").and_then(Value::as_str) {
            match observed.header(header) {
                Some(value) => {
                    captures.insert(name.clone(), value.to_owned());
                }
                None => out.push(Diagnostic::deny(
                    "expect/capture",
                    &at,
                    format!("cannot capture `{name}`: the response has no `{header}` header"),
                )),
            }
        }
    }
    captures
}

#[cfg(test)]
mod tests;
