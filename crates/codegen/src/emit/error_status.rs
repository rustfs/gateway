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
//! Responsible for: `generated/error_status.rs` — one associated constant per declared code and
//! the lookup table behind `ErrorCode::is_known`, both from `overlays/error-status.toml`.
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

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::ErrorStatus;

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
