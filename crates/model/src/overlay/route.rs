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

//! The reader for `overlays/route.toml`, the one hand-written cross-precedence shadowing source.
//!
//! Responsible for: parsing `[evidence.<id>]`, `[reason.<id>]` and `[[shadowing]]`, resolving every
//! reference into a self-contained [`ShadowingDecl`], and refusing — never ignoring — a record that
//! is incomplete, unreferenced, duplicated or self-referential.
//! NOT responsible for: deciding whether two selectors actually overlap (that is
//! `rustfs-gateway-core`'s lattice, at table-build time), assigning precedence (that is
//! `[op.<Operation>]` in `ops/<family>.toml`), or emitting anything.
//! Upstream: [`crate::toml_lite`]. Downstream: [`super::Overlay`], and through it the
//! `route_shadowing` emitter.
//!
//! # Why the references exist at all
//!
//! Four hundred pairs cite sixty-six AWS references between them, and two hundred and forty-six of
//! them share three paragraphs of reasoning. Written out in place, one operation's reference would
//! appear a dozen times and one paragraph two hundred: a correction would have to find every copy,
//! and the copies it missed would be a second, quietly wrong answer. So a reference and a shared
//! paragraph are each written once, under an id, and a pair names the id.
//!
//! What that must not become is two ways to say the same thing. A pair whose reasoning is its own
//! carries it inline; a paragraph that two pairs share may not be written inline twice — the
//! loader refuses the second copy and names the first, which is the only rule here whose whole
//! purpose is to keep the file from drifting away from itself.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::error::{Error, Result};
use crate::toml_lite::{self, Toml};

/// One reviewed cross-precedence shadowing decision, with every reference already resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowingDecl {
    /// The operation with the lower (earlier) precedence.
    pub winner: String,
    /// The operation it hides for the overlapping requests.
    pub shadowed: String,
    /// Why this order is correct, inline or resolved from `[reason.<id>]`.
    pub reason: String,
    /// One `url — summary` string per cited reference, in declaration order.
    pub evidence: Vec<String>,
}

/// The file name, relative to the overlay directory.
pub const ROUTE_FILE: &str = "route.toml";

/// The shortest reason that says anything. Below this the field is present but not written.
const MIN_REASON: usize = 40;

/// The shortest evidence summary that says anything, matching the quirk rule.
const MIN_SUMMARY: usize = 16;

/// The top-level tables this file is allowed to carry.
const TOP_LEVEL: [&str; 3] = ["evidence", "reason", "shadowing"];

/// The keys one `[[shadowing]]` entry is allowed to carry.
const ENTRY_KEYS: [&str; 5] = ["winner", "shadowed", "reason", "reason_ref", "evidence"];

fn overlay(message: impl Into<String>) -> Error {
    Error::Overlay(message.into())
}

/// Reads and validates the route overlay.
///
/// # Errors
///
/// [`Error::Io`] when the file is absent — it is the authority for a build-time refusal, so a
/// missing one is a failure and never an empty declaration set. [`Error::Toml`] when it does not
/// parse, and [`Error::Overlay`] for every rule this module enforces.
pub(super) fn read(path: &Path) -> Result<Vec<ShadowingDecl>> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::io(path.display().to_string(), source))?;
    let doc = toml_lite::parse(&path.display().to_string(), &text)?;
    parse(&doc)
}

fn parse(doc: &Toml) -> Result<Vec<ShadowingDecl>> {
    let entries = doc
        .as_table()
        .ok_or_else(|| overlay(format!("{ROUTE_FILE} is not a table")))?;
    for (key, _) in entries {
        if !TOP_LEVEL.contains(&key.as_str()) {
            return Err(overlay(format!(
                "{ROUTE_FILE} carries `{key}`; it holds `[evidence.<id>]`, `[reason.<id>]` and \
                 `[[shadowing]]` alone, and everything per-operation belongs in `ops/<family>.toml`"
            )));
        }
    }

    let evidence = read_evidence(doc)?;
    let reasons = read_reasons(doc)?;

    // An absent `[[shadowing]]` is legal and means exactly one thing: no cross-precedence overlap
    // has been reviewed yet. It is not a way to switch the rule off — an overlap the table finds
    // and this file does not declare is still a build failure, so an emptied file makes the table
    // refuse to build rather than quietly accept every ordering.
    let empty: Vec<Toml> = Vec::new();
    let rows = doc.get("shadowing").and_then(Toml::as_array).unwrap_or(&empty);

    let mut used_evidence: BTreeSet<String> = BTreeSet::new();
    let mut used_reasons: BTreeSet<String> = BTreeSet::new();
    let mut inline_reasons: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut decls = Vec::with_capacity(rows.len());

    for row in rows {
        for (key, _) in row.as_table().unwrap_or_default() {
            if !ENTRY_KEYS.contains(&key.as_str()) {
                return Err(overlay(format!("`[[shadowing]]` carries an unknown key `{key}`")));
            }
        }
        let winner = required_str(row, "winner")?;
        let shadowed = required_str(row, "shadowed")?;
        let pair = format!("{winner} over {shadowed}");
        if winner == shadowed {
            return Err(overlay(format!(
                "shadowing declaration for `{winner}` names itself as shadowed; a route cannot hide itself"
            )));
        }
        if !seen.insert((winner.clone(), shadowed.clone())) {
            return Err(overlay(format!(
                "shadowing declaration `{pair}` is declared twice; one pair has one reviewed answer"
            )));
        }

        let reason = match (row.get("reason"), row.get("reason_ref")) {
            (Some(_), Some(_)) => {
                return Err(overlay(format!(
                    "shadowing declaration `{pair}` carries both `reason` and `reason_ref`; exactly one \
                     of them says where the reasoning lives"
                )));
            }
            (None, None) => {
                return Err(overlay(format!(
                    "shadowing declaration `{pair}` carries neither `reason` nor `reason_ref`; an \
                     undeclared ordering is a guess"
                )));
            }
            (Some(_), None) => {
                let text = required_str(row, "reason")?;
                if text.len() < MIN_REASON {
                    return Err(overlay(format!(
                        "shadowing declaration `{pair}` has a {}-byte `reason`; at least {MIN_REASON} \
                         bytes, and it is read by whoever changes the order",
                        text.len()
                    )));
                }
                if let Some(first) = inline_reasons.get(&text) {
                    return Err(overlay(format!(
                        "shadowing declarations `{first}` and `{pair}` carry the same inline `reason`; \
                         give it an id under `[reason.<id>]` and name it with `reason_ref`, so that \
                         changing it changes every pair that meant it"
                    )));
                }
                inline_reasons.insert(text.clone(), pair.clone());
                text
            }
            (None, Some(_)) => {
                let id = required_str(row, "reason_ref")?;
                let Some(text) = reasons.get(&id) else {
                    return Err(overlay(format!(
                        "shadowing declaration `{pair}` names reason `{id}`, which no `[reason.{id}]` declares"
                    )));
                };
                used_reasons.insert(id);
                text.clone()
            }
        };

        let ids = row
            .get("evidence")
            .ok_or_else(|| overlay(format!("shadowing declaration `{pair}` carries no `evidence`")))?
            .string_array(&format!("shadowing declaration `{pair}` evidence"))?;
        if ids.is_empty() {
            return Err(overlay(format!(
                "shadowing declaration `{pair}` carries an empty `evidence` list; an unsourced ordering \
                 is a guess"
            )));
        }
        let mut cited = Vec::with_capacity(ids.len());
        for id in &ids {
            let Some(text) = evidence.get(id) else {
                return Err(overlay(format!(
                    "shadowing declaration `{pair}` cites evidence `{id}`, which no `[evidence.{id}]` declares"
                )));
            };
            used_evidence.insert(id.clone());
            cited.push(text.clone());
        }

        decls.push(ShadowingDecl {
            winner,
            shadowed,
            reason,
            evidence: cited,
        });
    }

    for id in evidence.keys() {
        if !used_evidence.contains(id) {
            return Err(overlay(format!(
                "`[evidence.{id}]` is cited by no shadowing declaration; an unread reference is dead weight"
            )));
        }
    }
    for id in reasons.keys() {
        if !used_reasons.contains(id) {
            return Err(overlay(format!(
                "`[reason.{id}]` is named by no shadowing declaration; an unread paragraph is dead weight"
            )));
        }
    }

    Ok(decls)
}

/// `id -> "url — summary"`, the one string a declaration cites.
fn read_evidence(doc: &Toml) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let Some(table) = doc.get("evidence").and_then(Toml::as_table) else {
        return Ok(out);
    };
    for (id, entry) in table {
        let url = required_str(entry, "url").map_err(|e| overlay(format!("`[evidence.{id}]`: {e}")))?;
        if !url.starts_with("https://") {
            return Err(overlay(format!("`[evidence.{id}]` has a `url` that is not an https reference: {url}")));
        }
        let summary = required_str(entry, "summary").map_err(|e| overlay(format!("`[evidence.{id}]`: {e}")))?;
        if summary.len() < MIN_SUMMARY {
            return Err(overlay(format!(
                "`[evidence.{id}]` has a {}-byte `summary`; at least {MIN_SUMMARY} bytes, written here \
                 rather than quoted",
                summary.len()
            )));
        }
        out.insert(id.clone(), format!("{url} — {summary}"));
    }
    Ok(out)
}

/// `id -> text`, the paragraphs several pairs share.
fn read_reasons(doc: &Toml) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let Some(table) = doc.get("reason").and_then(Toml::as_table) else {
        return Ok(out);
    };
    for (id, entry) in table {
        let text = required_str(entry, "text").map_err(|e| overlay(format!("`[reason.{id}]`: {e}")))?;
        if text.len() < MIN_REASON {
            return Err(overlay(format!(
                "`[reason.{id}]` is {} bytes; at least {MIN_REASON}, and it is read by whoever changes \
                 the order",
                text.len()
            )));
        }
        out.insert(id.clone(), text);
    }
    Ok(out)
}

fn required_str(value: &Toml, key: &str) -> Result<String> {
    let text = value
        .get(key)
        .ok_or_else(|| overlay(format!("`{key}` is missing")))?
        .as_str()
        .ok_or_else(|| overlay(format!("`{key}` must be a string")))?;
    if text.trim().is_empty() {
        return Err(overlay(format!("`{key}` is empty")));
    }
    Ok(text.to_owned())
}
