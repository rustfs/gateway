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

//! The error code to HTTP status authority, as the overlay declares it.
//!
//! Responsible for: parsing `overlays/error-status.toml` into rows, and refusing every shape that
//! would let two rows disagree — a repeated wire name, a repeated constant, a status outside the
//! HTTP range, and a 5xx row that has not declared itself a server fault.
//! NOT responsible for: rendering the rows (that is `rustfs-gateway-codegen`), or deciding which
//! code an operation returns (that is the per-operation overlay).
//! Upstream: [`crate::toml_lite`]. Downstream: [`super::Overlay`], the error-status emitter.
//!
//! # Why the 5xx flag is required rather than inferred
//!
//! The status alone already says whether a row is a 5xx, so a flag that repeats it looks
//! redundant. It is not: the flag is the allowlist. A client error that lands in the 5xx band is
//! amplified — SDKs retry it and circuit breakers open on it — so the failure worth catching is a
//! row that *became* a 5xx by a typo in one digit. A typo cannot also write `server_fault = true`,
//! and a row that carries the flag without a 5xx status is just as wrong in the other direction,
//! so both directions are refused here.

use crate::error::{Error, Result};
use crate::toml_lite::Toml;

/// One row of the error code to HTTP status authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorStatus {
    /// The wire spelling, as it appears in the `<Code>` element of an error body.
    pub name: String,
    /// The associated constant this row becomes on `ErrorCode`.
    pub constant: String,
    /// The HTTP status, as the wire carries it.
    pub status: u16,
    /// Declared server fault. Required on every 5xx row and refused on every other row.
    pub server_fault: bool,
    /// Rustdoc lines, verbatim, for a row whose status reads wrong at a glance.
    pub note: Vec<String>,
}

/// The file name of the one cross-family error-status file.
pub(super) const ERROR_STATUS_FILE: &str = "error-status.toml";

/// Reads the authority file into rows, in declaration order.
///
/// # Errors
///
/// [`Error::Overlay`] when the file carries anything per-operation, declares no row, repeats a
/// wire name or a constant, or holds a row whose status and `server_fault` flag disagree.
pub(super) fn read(doc: &Toml) -> Result<Vec<ErrorStatus>> {
    for key in ["include", "deferred", "op", "shape", "quirk", "scalar"] {
        if doc.get(key).is_some() {
            return Err(Error::Overlay(format!(
                "{ERROR_STATUS_FILE} carries `{key}`; it holds `[[code]]` rows alone, and everything \
                 per-operation belongs in `ops/<family>.toml`"
            )));
        }
    }
    let rows = doc.get("code").and_then(Toml::as_array).unwrap_or_default();
    if rows.is_empty() {
        return Err(Error::Overlay(format!(
            "{ERROR_STATUS_FILE} declares no `[[code]]` row; an empty authority would map every code \
             to nothing at all"
        )));
    }
    let mut out: Vec<ErrorStatus> = Vec::with_capacity(rows.len());
    for row in rows {
        let entry = one(row)?;
        if let Some(first) = out.iter().find(|seen| seen.name == entry.name) {
            return Err(Error::Overlay(format!(
                "{ERROR_STATUS_FILE}: `{}` is declared twice, as `{}` and as `{}`; one of the two \
                 statuses would win silently",
                entry.name, first.constant, entry.constant
            )));
        }
        if let Some(first) = out.iter().find(|seen| seen.constant == entry.constant) {
            return Err(Error::Overlay(format!(
                "{ERROR_STATUS_FILE}: constant `{}` is declared twice, for `{}` and for `{}`",
                entry.constant, first.name, entry.name
            )));
        }
        out.push(entry);
    }
    Ok(out)
}

fn one(row: &Toml) -> Result<ErrorStatus> {
    let name = string(row, "name")?;
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::Overlay(format!(
            "{ERROR_STATUS_FILE}: `{name}` is not a wire code spelling; it is the literal text of a \
             `<Code>` element, so it is ASCII alphanumeric and never empty"
        )));
    }
    let constant = string(row, "constant")?;
    let shape_ok = !constant.is_empty()
        && constant.starts_with(|c: char| c.is_ascii_uppercase())
        && constant
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !constant.ends_with('_');
    if !shape_ok {
        return Err(Error::Overlay(format!(
            "{ERROR_STATUS_FILE}: `{constant}` is not a Rust associated-constant name for `{name}`"
        )));
    }
    let status = row
        .get("status")
        .and_then(Toml::as_int)
        .ok_or_else(|| Error::Overlay(format!("{ERROR_STATUS_FILE}: `{name}` has no integer `status`")))?;
    let status = u16::try_from(status)
        .ok()
        .filter(|status| (100..=599).contains(status))
        .ok_or_else(|| {
            Error::Overlay(format!("{ERROR_STATUS_FILE}: `{name}` has status {status}, which is not an HTTP status"))
        })?;
    let server_fault = row.get("server_fault").and_then(Toml::as_bool).unwrap_or(false);
    if server_fault != (status >= 500) {
        return Err(Error::Overlay(format!(
            "{ERROR_STATUS_FILE}: `{name}` has status {status} and `server_fault = {server_fault}`; \
             the flag is the 5xx allowlist, so it is required on every 5xx row and refused on every \
             other one"
        )));
    }
    let note = match row.get("note") {
        None => Vec::new(),
        Some(value) => value.string_array(&format!("{ERROR_STATUS_FILE}: `{name}` note"))?,
    };
    if note.iter().any(|line| line.trim().is_empty()) {
        return Err(Error::Overlay(format!(
            "{ERROR_STATUS_FILE}: `{name}` has an empty note line; a note is rustdoc, and a blank \
             line in it renders as a summary break nobody asked for"
        )));
    }
    Ok(ErrorStatus {
        name,
        constant,
        status,
        server_fault,
        note,
    })
}

fn string(row: &Toml, key: &str) -> Result<String> {
    row.get(key)
        .and_then(Toml::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Overlay(format!("{ERROR_STATUS_FILE}: every `[[code]]` row needs a string `{key}`")))
}
