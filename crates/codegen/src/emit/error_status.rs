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

//! The error code to HTTP status table, rendered from the overlay authority.
//!
//! Responsible for: the three renderings of `overlays/error-status.toml` —
//! `generated/error_status.rs` (one associated constant per declared code and the lookup behind
//! `ErrorCode::is_known`), `generated/ERROR_CODES.md` for a reader, and
//! `generated/error_codes.json` for a program.
//! NOT responsible for: the `ErrorCode` type itself, which `rustfs-gateway-types` owns, or for
//! which code an operation returns, which is per-operation IR and lives in `error_codes.rs`.
//! Upstream: [`rustfs_gateway_model::ErrorStatus`]. Downstream:
//! `rustfs-gateway-types::scalar::error_code`.
//!
//! # Why the constants are generated and not just the table
//!
//! A hand-written constant list beside a generated status table is the "one rule in two places"
//! shape this pipeline exists to prevent: a constant whose row was deleted would still compile,
//! and would answer with whatever the lookup did when it missed. Emitting both from one input
//! makes `ErrorCode::NO_SUCH_KEY` exist exactly when the authority holds a row for it, which is
//! what makes the status total without a fallback. The names stay greppable because
//! `overlays/error-status.toml` carries every one of them in a `constant = "..."` field.
//!
//! # Why three renderings and not one
//!
//! The mapping has three audiences and no two of them can read the same file. The runtime needs
//! Rust. A person triaging a `<Code>` off the wire needs a table they can scan, and TOML that
//! spends five lines per row is not that. A tool needs to answer "what does this gateway answer
//! with, and will an SDK retry it" without parsing either TOML or Rust — the status band is the
//! contract SDK retry and circuit-breaker logic branches on, so it is the one fact worth
//! publishing in a form nothing has to be built to read.
//!
//! All three come out of one `&[ErrorStatus]` in one `cargo xtask codegen` run, so
//! `cargo xtask spec verify` is what makes them agree: there is no second input any of them could
//! disagree from. Each is a pure function of the authority and of nothing else — in particular
//! none of them re-states which operation produces which code, which is per-operation IR and is
//! already inverted under `by_error_code` in `generated/OPERATIONS.json`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::ErrorStatus;
use rustfs_gateway_model::json::{self, Value};

use super::dto::LICENSE;

/// Renders the error status module included by the types crate.
///
/// # Errors
///
/// Returns the offending status when a row asks for one `http::StatusCode` has no associated
/// constant for. A numeric literal would compile and would put a status into the tree that no
/// reader can match against `StatusCode::NOT_FOUND`, so this is a hard failure rather than a
/// fallback.
pub fn render(rows: &[ErrorStatus]) -> Result<String, String> {
    let mut out = String::from(LICENSE);
    out.push_str(
        "\n// The error code to HTTP status table, from `model/overlays/error-status.toml`. Included\n\
         // by `rustfs-gateway-types::scalar::error_code`, which owns `ErrorCode` itself; nothing\n\
         // here mints a type. There is no fallback row: a code with no entry here has no constant\n\
         // and no status, and reaches the wire only through `ErrorCode::custom`, which makes its\n\
         // caller name the status.\n\n",
    );

    out.push_str("impl ErrorCode {\n");
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let status = status_constant(row.status)?;
        let _ = writeln!(out, "    /// `{}`, HTTP `{}`.", row.name, row.status);
        if let Some((first, rest)) = row.note.split_first() {
            out.push_str("    ///\n");
            let _ = writeln!(out, "    /// {first}");
            for line in rest {
                let _ = writeln!(out, "    /// {line}");
            }
        }
        let _ = writeln!(
            out,
            "    pub const {}: Self = Self {{\n        \
                 name: Cow::Borrowed(\"{}\"),\n        \
                 status: StatusCode::{status},\n    }};",
            row.constant, row.name
        );
    }
    out.push_str("}\n\n");

    out.push_str(
        "/// Every code the authority declares, with its status. The lookup behind\n\
         /// [`ErrorCode::is_known`] and [`ErrorCode::known`], and nothing else: a status is\n\
         /// carried by the value, so no caller ever has to miss in this table and guess.\n",
    );
    out.push_str("pub(super) static CODE_TABLE: &[(&str, StatusCode)] = &[\n");
    for row in rows {
        let status = status_constant(row.status)?;
        let _ = writeln!(out, "    (\"{}\", StatusCode::{status}),", row.name);
    }
    out.push_str("];\n");
    Ok(out)
}

/// The `http::StatusCode` associated constant for a status the authority declares.
///
/// Deliberately not exhaustive over 100..=599: a status with no name here is a status nobody has
/// decided this gateway may answer with, and it should stop the build rather than be spelled as a
/// number.
fn status_constant(status: u16) -> Result<&'static str, String> {
    let name = match status {
        200 => "OK",
        204 => "NO_CONTENT",
        206 => "PARTIAL_CONTENT",
        301 => "MOVED_PERMANENTLY",
        304 => "NOT_MODIFIED",
        307 => "TEMPORARY_REDIRECT",
        400 => "BAD_REQUEST",
        401 => "UNAUTHORIZED",
        403 => "FORBIDDEN",
        404 => "NOT_FOUND",
        405 => "METHOD_NOT_ALLOWED",
        408 => "REQUEST_TIMEOUT",
        409 => "CONFLICT",
        411 => "LENGTH_REQUIRED",
        412 => "PRECONDITION_FAILED",
        413 => "PAYLOAD_TOO_LARGE",
        416 => "RANGE_NOT_SATISFIABLE",
        429 => "TOO_MANY_REQUESTS",
        500 => "INTERNAL_SERVER_ERROR",
        501 => "NOT_IMPLEMENTED",
        502 => "BAD_GATEWAY",
        503 => "SERVICE_UNAVAILABLE",
        504 => "GATEWAY_TIMEOUT",
        other => {
            return Err(format!(
                "error-status.toml declares status {other}, which has no `http::StatusCode` constant \
                 in the emitter; add it there rather than emitting a bare number"
            ));
        }
    };
    Ok(name)
}

/// Wire code to `ErrorCode` constant, for emitters that must name a code at a call site.
///
/// A generated call site that carried the wire string would push the lookup into the request path,
/// where a code the authority does not declare has nowhere to get a status from. Resolving it here
/// makes that a build failure instead.
#[derive(Debug, Default, Clone)]
pub struct Constants(BTreeMap<String, String>);

impl Constants {
    /// Indexes the authority by wire spelling.
    #[must_use]
    pub fn new(rows: &[ErrorStatus]) -> Self {
        Self(rows.iter().map(|row| (row.name.clone(), row.constant.clone())).collect())
    }

    /// The `ErrorCode::<CONSTANT>` path for a wire code.
    ///
    /// # Errors
    ///
    /// The wire code, when `model/overlays/error-status.toml` declares no row for it.
    pub fn path(&self, code: &str) -> Result<String, String> {
        self.0
            .get(code)
            .map(|constant| format!("ErrorCode::{constant}"))
            .ok_or_else(|| {
                format!(
                    "`{code}` is named by an operation but `model/overlays/error-status.toml` declares no \
                 row for it, so it has no HTTP status; add the row rather than letting the code reach \
                 the wire with a status nobody chose"
                )
            })
    }
}

/// The three machine-readable facts every code entry of `error_codes.json` carries, in the order
/// they are written.
///
/// The order is the field order of an entry, and `scripts/check_error_codes_json_fields.sh`
/// asserts it against the artefact: a consumer that read the fields positionally would be reading
/// a different document after a silent reorder.
pub const JSON_FIELDS: [&str; 3] = ["constant", "status", "server_fault"];

/// The index inverting each field, in the same order.
pub const JSON_INDEXES: [&str; 3] = ["by_constant", "by_status", "by_server_fault"];

/// What `error_codes.json` says about itself.
const JSON_NOTE: &str = "Generated from model/overlays/error-status.toml by `cargo xtask codegen`; \
                         edit the overlay and regenerate, never this file. ERROR_CODES.md is the \
                         same rows for a human reader. `server_fault` is true on exactly the codes \
                         answered in the 5xx band, which is the set an SDK retries and a circuit \
                         breaker opens on. Which operation produces which code is not here: that is \
                         per-operation IR, and OPERATIONS.json inverts it under `by_error_code`.";

/// One row's three machine fields: the name, the rendered value, and the index keys it contributes.
///
/// `JSON_FIELDS` and `JSON_INDEXES` are the same three, in the same order, and this is the only
/// place a field's value and its inversion are written down. Declaring them apart is how an index
/// comes to be built from the wrong field.
fn json_fields(row: &ErrorStatus) -> [(&'static str, Value, String); 3] {
    [
        ("constant", Value::Str(row.constant.clone()), row.constant.clone()),
        ("status", Value::Int(i64::from(row.status)), row.status.to_string()),
        ("server_fault", Value::Bool(row.server_fault), row.server_fault.to_string()),
    ]
}

/// Renders `generated/error_codes.json`: the authority, keyed by wire code, plus one index per field.
#[must_use]
pub fn render_json(rows: &[ErrorStatus]) -> String {
    let mut sorted: Vec<&ErrorStatus> = rows.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let mut forward: Vec<(String, Value)> = Vec::with_capacity(sorted.len());
    let mut indexes: Vec<(String, BTreeMap<String, Vec<String>>)> = JSON_INDEXES
        .iter()
        .map(|name| ((*name).to_owned(), BTreeMap::new()))
        .collect();

    for row in &sorted {
        let mut members: Vec<(String, Value)> = Vec::with_capacity(JSON_FIELDS.len());
        for (position, (name, value, key)) in json_fields(row).into_iter().enumerate() {
            members.push((name.to_owned(), value));
            if let Some((_, inverted)) = indexes.get_mut(position) {
                inverted.entry(key).or_default().push(row.name.clone());
            }
        }
        forward.push((row.name.clone(), Value::Object(members)));
    }

    let mut document: Vec<(String, Value)> = vec![
        ("generated_by".to_owned(), Value::Str("cargo xtask codegen".to_owned())),
        ("note".to_owned(), Value::Str(JSON_NOTE.to_owned())),
        ("codes".to_owned(), Value::Object(forward)),
    ];
    for (name, inverted) in indexes {
        document.push((
            name,
            Value::Object(
                inverted
                    .into_iter()
                    .map(|(key, mut codes)| {
                        codes.sort();
                        (key, Value::Array(codes.into_iter().map(Value::Str).collect()))
                    })
                    .collect(),
            ),
        ));
    }
    json::write_canonical(&Value::Object(document))
}

/// Every band [`band`] can answer, in ascending status order rather than alphabetically.
///
/// The census line reads as a progression from "the client is fine" to "we are", which an
/// alphabetical order — client, redirect, server — inverts halfway through.
const BANDS: [&str; 4] = ["success", "redirect", "client", "server"];

/// The band a status is answered in, as a reader thinks of it.
///
/// Derived from the status rather than declared beside it: a second declaration is a second thing
/// that can be wrong, and this one would be wrong in the direction that matters — a `server_fault`
/// row filed under "client".
fn band(status: u16) -> &'static str {
    match status {
        ..=299 => "success",
        300..=399 => "redirect",
        400..=499 => "client",
        _ => "server",
    }
}

/// Escapes the one character that would end a Markdown table cell early.
fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

/// Renders `generated/ERROR_CODES.md`: the same rows, for somebody holding a `<Code>` off the wire.
///
/// # Errors
///
/// Returns the offending status when a row declares one the emitter has no `StatusCode` constant
/// for — the same refusal [`render`] makes, so the two renderings cannot accept different tables.
pub fn render_markdown(rows: &[ErrorStatus]) -> Result<String, String> {
    let mut sorted: Vec<&ErrorStatus> = rows.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for row in &sorted {
        status_constant(row.status)?;
    }

    let mut out = String::from("# Error codes\n\n");
    out.push_str(
        "<!-- @generated by `cargo xtask codegen`. Do not edit: change\n\
         `model/overlays/error-status.toml` and regenerate. -->\n\n\
         Every code this gateway may put in the `<Code>` element of an `<Error>` body, and the HTTP\n\
         status it is answered with. `model/overlays/error-status.toml` is the only place that\n\
         pairing is written by hand; this file and `generated/error_codes.json` are renderings of\n\
         it, and `cargo xtask spec verify` fails when either has drifted from it.\n\n\
         There is no fallback row. A code with no entry here has no constant and no status, and\n\
         reaches the wire only through `ErrorCode::custom`, which makes its caller name the status.\n\n",
    );

    let census = BANDS
        .iter()
        .filter_map(|name| {
            let count = sorted.iter().filter(|row| band(row.status) == *name).count();
            (count > 0).then(|| format!("{count} {name}"))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "{} codes: {census}.\n", sorted.len());

    out.push_str("## The 5xx allowlist\n\n");
    out.push_str(
        "A 5xx tells an SDK to retry and trips its circuit breaker, so a client error that lands in\n\
         the 5xx band is amplified into an outage. Every code below carries `server_fault = true` in\n\
         the authority, and `scripts/check_error_status_total.sh` refuses the flag without the band\n\
         and the band without the flag. Nothing else in this document is retried on the status\n\
         alone.\n\n\
         | Code | Status | Constant |\n| --- | --- | --- |\n",
    );
    for row in sorted.iter().filter(|row| row.server_fault) {
        let _ = writeln!(out, "| `{}` | {} | `ErrorCode::{}` |", row.name, row.status, row.constant);
    }

    out.push_str("\n## By status\n\n");
    out.push_str(
        "The other direction: what a status can mean when a client sees it.\n\n\
         | Status | Band | Codes |\n| --- | --- | --- |\n",
    );
    let mut by_status: BTreeMap<u16, Vec<&str>> = BTreeMap::new();
    for row in &sorted {
        by_status.entry(row.status).or_default().push(row.name.as_str());
    }
    for (status, codes) in &by_status {
        let names = codes.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", ");
        let _ = writeln!(out, "| {status} | {} | {names} |", band(*status));
    }

    out.push_str("\n## Every code\n\n");
    out.push_str("| Code | Status | Constant | Note |\n| --- | --- | --- | --- |\n");
    for row in &sorted {
        let note = cell(&row.note.join(" "));
        let _ = writeln!(
            out,
            "| `{}` | {} | `ErrorCode::{}` | {} |",
            row.name,
            row.status,
            row.constant,
            if note.is_empty() { "—" } else { &note }
        );
    }
    Ok(out)
}
