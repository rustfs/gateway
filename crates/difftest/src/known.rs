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

//! The known-diffs register: every difference between the two stacks that is accepted, why, and
//! until when.
//!
//! Responsible for: reading `known-diffs.toml` strictly (an unknown key, a missing `reason` or
//! `expires`, a malformed date, id or pattern, an unpinned route or outcome entry, or a duplicate
//! id refuses the whole file); judging a request's findings against it — a finding matched by an
//! entry is known, a message wording difference is reported as information, and every other
//! finding fails; and naming the entries whose review date has passed.
//! NOT responsible for: finding differences (`decode.rs`), or comparing the entry set with the
//! base branch's.
//! Upstream: `known-diffs.toml`. Downstream: tests, corpus runners, the shadow proxy.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;

use crate::decode::{Finding, Priority};

/// The operation of an entry that holds for every operation: allowed only for a message wording
/// entry that pins the gateway's sentence, because a sentence is one fact wherever it is written.
pub const ANY_OPERATION: &str = "*";

/// The register checked into this crate.
pub const CHECKED_IN: &str = include_str!("../known-diffs.toml");

/// Which differential an entry belongs to.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A request decoded differently.
    Decode,
    /// An output encoded differently.
    Encode,
}

/// One accepted difference.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnownDiff {
    /// `kd-<decode|encode>-NNNN`, stable for the life of the entry.
    pub id: String,
    /// Which differential reports it.
    pub kind: Kind,
    /// The operation the finding concerns, or [`ANY_OPERATION`] for a message wording entry.
    pub operation: String,
    /// The finding's item: `route`, `outcome`, `error.status`, `error.code`, `error.message`,
    /// `rest_body`, or an input member path such as `GetObjectInput.range` — or a pattern with
    /// one `*` over member paths.
    pub item: String,
    /// The gateway side exactly as the finding renders it, or a pattern with one `*`; any value
    /// when absent.
    #[serde(default)]
    pub gateway: Option<String>,
    /// The s3s side exactly as the finding renders it, or a pattern with one `*`; any value when
    /// absent.
    #[serde(default)]
    pub s3s: Option<String>,
    /// Why the difference is accepted.
    pub reason: String,
    /// The review date, `YYYY-MM-DD`: after it the entry is stale and the expiry gate fails.
    pub expires: String,
    /// The ruling in the request-divergence register, when one exists (`rd-…`).
    #[serde(default)]
    pub ruling: Option<String>,
    /// The ADR, when the difference is an architecture decision.
    #[serde(default)]
    pub adr: Option<String>,
}

impl KnownDiff {
    fn matches(&self, finding: &Finding) -> bool {
        (self.operation == finding.operation || self.operation == ANY_OPERATION)
            && matches_value(&self.item, &finding.item.to_string())
            && self
                .gateway
                .as_deref()
                .is_none_or(|pattern| matches_value(pattern, &finding.gateway))
            && self.s3s.as_deref().is_none_or(|pattern| matches_value(pattern, &finding.s3s))
    }
}

/// An exact value, or — with one `*` — every value that starts with what precedes it and ends
/// with what follows it (for a refusal whose message repeats request bytes around a fixed text).
fn matches_value(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => {
            value.len() >= prefix.len() + suffix.len() && value.starts_with(prefix) && value.ends_with(suffix)
        }
        None => pattern == value,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default, rename = "diff")]
    diffs: Vec<KnownDiff>,
}

/// Why a register was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterError(pub String);

impl fmt::Display for RegisterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RegisterError {}

/// The whole register.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KnownDiffs {
    entries: Vec<KnownDiff>,
}

impl KnownDiffs {
    /// Reads a register, refusing anything malformed.
    ///
    /// # Errors
    ///
    /// Not TOML; an unknown key; a missing `id`, `kind`, `operation`, `item`, `reason` or
    /// `expires`; an empty reason; an id that is not `kd-<kind>-NNNN` for its own kind; a date that
    /// is not `YYYY-MM-DD`; a duplicate id.
    pub fn parse(text: &str) -> Result<Self, RegisterError> {
        let document: Document = toml::from_str(text).map_err(|error| RegisterError(format!("known-diffs: {error}")))?;
        let mut ids = BTreeSet::new();
        for entry in &document.diffs {
            let prefix = match entry.kind {
                Kind::Decode => "kd-decode-",
                Kind::Encode => "kd-encode-",
            };
            let digits = entry.id.strip_prefix(prefix).unwrap_or_default();
            if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(RegisterError(format!("{}: the id must be {prefix}NNNN", entry.id)));
            }
            if !ids.insert(entry.id.clone()) {
                return Err(RegisterError(format!("{}: the id is registered twice", entry.id)));
            }
            if entry.reason.trim().is_empty() {
                return Err(RegisterError(format!("{}: the reason is empty", entry.id)));
            }
            if !is_date(&entry.expires) {
                return Err(RegisterError(format!("{}: expires {:?} is not YYYY-MM-DD", entry.id, entry.expires)));
            }
            if entry.operation.is_empty() || entry.item.is_empty() {
                return Err(RegisterError(format!("{}: operation and item must name what differs", entry.id)));
            }
            let patterns = [Some(entry.item.as_str()), entry.gateway.as_deref(), entry.s3s.as_deref()];
            if patterns.iter().flatten().any(|pattern| pattern.matches('*').count() > 1) {
                return Err(RegisterError(format!("{}: a pattern holds at most one *", entry.id)));
            }
            if matches!(entry.item.as_str(), "route" | "outcome") && (entry.gateway.is_none() || entry.s3s.is_none()) {
                return Err(RegisterError(format!(
                    "{}: a route or outcome entry pins both sides, or it would accept every such difference",
                    entry.id
                )));
            }
            if entry.operation == ANY_OPERATION && (entry.item != "error.message" || entry.gateway.is_none()) {
                return Err(RegisterError(format!(
                    "{}: only an error.message entry that pins the gateway sentence may hold for every operation",
                    entry.id
                )));
            }
        }
        Ok(Self { entries: document.diffs })
    }

    /// The register checked into this crate.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`].
    pub fn checked_in() -> Result<Self, RegisterError> {
        Self::parse(CHECKED_IN)
    }

    /// Every entry, in file order.
    #[must_use]
    pub fn entries(&self) -> &[KnownDiff] {
        &self.entries
    }

    /// The entries whose review date is before `today` (`YYYY-MM-DD`): each must be reviewed —
    /// removed, or re-argued with a new date — before anything else lands.
    #[must_use]
    pub fn expired_on(&self, today: &str) -> Vec<&KnownDiff> {
        self.entries.iter().filter(|entry| entry.expires.as_str() < today).collect()
    }

    /// Judges `findings` against the register.
    #[must_use]
    pub fn verdict(&self, findings: Vec<Finding>) -> Verdict {
        let mut verdict = Verdict::default();
        for finding in findings {
            match self.entries.iter().find(|entry| entry.matches(&finding)) {
                Some(entry) => verdict.known.push((finding, entry.id.clone())),
                None => verdict.failures.push(finding),
            }
        }
        verdict
    }
}

/// `YYYY-MM-DD` with a month 1–12 and a day 1–31.
fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| text.get(range).and_then(|part| part.parse::<u32>().ok());
    matches!((digits(0..4), digits(5..7), digits(8..10)), (Some(_), Some(1..=12), Some(1..=31)))
}

/// What the register made of one request's findings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Findings no entry accepts. The request fails when this is not empty.
    pub failures: Vec<Finding>,
    /// Findings an entry accepts, with its id.
    pub known: Vec<(Finding, String)>,
}

impl Verdict {
    /// No unregistered difference.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// The accepted findings that are message wording only, reported as information.
    pub fn info(&self) -> impl Iterator<Item = &(Finding, String)> {
        self.known.iter().filter(|(finding, _)| finding.priority == Priority::Info)
    }
}
