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

//! The rulings ledger: one reviewed, dated verdict per case a run may leave unpassed.
//!
//! Responsible for: reading `--rulings <toml>` (`[[ruling]]` rows), refusing an incomplete or
//! unreadable row, binding every row to a case the corpus holds, and judging a finished report —
//! which failed or skipped cases carry an unexpired ruling and which do not.
//! NOT responsible for: deciding a case's verdict (`crate::expect`, `crate::runner`), rendering a
//! ruled case as anything but what it was (`crate::report` keeps a ruled failure a failure), or
//! the exit code (`crate::cli`, which reads the judgement).
//! Upstream: `crate::toml`, `crate::time`, `crate::report`. Downstream: `crate::cli`.

use crate::report::{CaseOutcome, Report, Verdict};
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet};

/// What a ruling says about the difference it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulingVerdict {
    /// The candidate answers as legacy RustFS answers, and the case expects something else.
    LegacyIdentical,
    /// The difference from legacy RustFS was reviewed and accepted as the intended behaviour.
    AcceptedChange,
}

impl RulingVerdict {
    /// The two spellings a ledger may use.
    pub const SPELLINGS: [&'static str; 2] = ["legacy-identical", "accepted-change"];

    /// The ledger spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RulingVerdict::LegacyIdentical => "legacy-identical",
            RulingVerdict::AcceptedChange => "accepted-change",
        }
    }

    /// Parses the ledger spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<RulingVerdict> {
        match text {
            "legacy-identical" => Some(RulingVerdict::LegacyIdentical),
            "accepted-change" => Some(RulingVerdict::AcceptedChange),
            _ => None,
        }
    }
}

/// One reviewed verdict on one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruling {
    /// The case the ruling covers.
    pub id: String,
    /// What the ruling says.
    pub verdict: RulingVerdict,
    /// The issue that holds the review, as `<owner>/<repository>#<number>`.
    pub issue: String,
    /// Who approved the ruling.
    pub approved_by: String,
    /// The last day the ruling holds, as `YYYY-MM-DD`.
    pub expires: String,
    /// `expires`, in days since the Unix epoch.
    expires_day: i64,
}

impl Ruling {
    /// Whether the ruling has lapsed on `today`, in days since the Unix epoch.
    ///
    /// A ruling holds through its `expires` date and not past it: the day after is expired.
    #[must_use]
    pub fn is_expired(&self, today: i64) -> bool {
        today > self.expires_day
    }
}

/// The fields a row must carry, and may carry nothing else.
const FIELDS: [&str; 5] = ["id", "verdict", "issue", "approved_by", "expires"];

/// The ledger: every ruling, by case id.
#[derive(Debug, Clone, Default)]
pub struct Rulings {
    rulings: BTreeMap<String, Ruling>,
}

impl Rulings {
    /// Reads a ledger: `[[ruling]]` rows, each with exactly `id`, `verdict`, `issue`,
    /// `approved_by` and `expires`. An empty document is an empty ledger.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending row and field when a row is incomplete, carries an
    /// unknown key, spells a verdict, issue or date in a form the ledger does not define, or rules
    /// the same case twice.
    pub fn parse(text: &str) -> Result<Rulings, String> {
        let document = crate::toml::parse(text).map_err(|error| format!("rulings: {error}"))?;
        let Some(top) = document.as_table() else {
            return Err("rulings: the ledger is not a table".to_owned());
        };
        let mut rulings = BTreeMap::new();
        for (key, value) in top {
            if key != "ruling" {
                return Err(format!(
                    "rulings: unknown top-level key `{key}`; a ledger holds `[[ruling]]` rows and nothing else"
                ));
            }
            let Some(rows) = value.as_array() else {
                return Err("rulings: `ruling` must be an array of tables, one `[[ruling]]` per row".to_owned());
            };
            for (index, row) in rows.iter().enumerate() {
                let ruling = read_ruling(row, index)?;
                if rulings.contains_key(&ruling.id) {
                    return Err(format!("rulings: `{}` is ruled twice", ruling.id));
                }
                rulings.insert(ruling.id.clone(), ruling);
            }
        }
        Ok(Rulings { rulings })
    }

    /// Checks that every ruling names a case the corpus holds.
    ///
    /// # Errors
    ///
    /// Returns a message listing every ruled id the corpus does not know. A ruling nothing can
    /// match is a ruling that excuses nothing and reads as if it did.
    pub fn bind<'a>(&self, case_ids: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
        let known: BTreeSet<&str> = case_ids.into_iter().collect();
        let unknown: Vec<&str> = self
            .rulings
            .keys()
            .map(String::as_str)
            .filter(|id| !known.contains(id))
            .collect();
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(format!("rulings: no case in the corpus is named {}", unknown.join(", ")))
        }
    }

    /// The ruling on a case, when the ledger holds one.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Ruling> {
        self.rulings.get(id)
    }

    /// How many cases the ledger rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rulings.len()
    }

    /// Whether the ledger rules nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rulings.is_empty()
    }

    /// Judges a finished report on `today`, in days since the Unix epoch.
    ///
    /// Every case that did not pass owes an unexpired ruling — a skip included, whatever its
    /// reason: a case that did not run is not evidence, and the ledger is where the reason it is
    /// tolerated is written down. A ruling on a case that passed is stale and reported as such.
    #[must_use]
    pub fn judge<'a>(&'a self, report: &'a Report, today: i64) -> Judgement<'a> {
        let mut judgement = Judgement::default();
        for outcome in &report.outcomes {
            match (outcome.verdict, self.get(&outcome.id)) {
                (Verdict::Passed | Verdict::Validated, Some(ruling)) => judgement.stale.push(ruling),
                (Verdict::Passed | Verdict::Validated, None) => {}
                (Verdict::Failed | Verdict::Skipped, None) => judgement.unruled.push(outcome),
                (Verdict::Failed | Verdict::Skipped, Some(ruling)) if ruling.is_expired(today) => {
                    judgement.expired.push((outcome, ruling));
                }
                (Verdict::Failed | Verdict::Skipped, Some(ruling)) => judgement.ruled.push((outcome, ruling)),
            }
        }
        judgement
    }
}

fn read_ruling(row: &Value, index: usize) -> Result<Ruling, String> {
    let Some(fields) = row.as_table() else {
        return Err(format!("rulings: ruling {index} is not a table"));
    };
    let label = fields
        .iter()
        .find(|(key, _)| key == "id")
        .and_then(|(_, value)| value.as_str())
        .map_or_else(|| format!("ruling {index}"), |id| format!("`{id}`"));
    for (key, _) in fields {
        if !FIELDS.contains(&key.as_str()) {
            return Err(format!(
                "rulings: {label} has an unknown key `{key}`; the fields are {}",
                FIELDS.join(", ")
            ));
        }
    }
    let field = |name: &str| -> Result<&str, String> {
        let value = fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
            .ok_or_else(|| format!("rulings: {label} has no `{name}`"))?;
        let text = value
            .as_str()
            .ok_or_else(|| format!("rulings: {label}: `{name}` must be a string"))?;
        if text.trim().is_empty() {
            return Err(format!("rulings: {label}: `{name}` is empty"));
        }
        Ok(text)
    };
    let id = field("id")?.to_owned();
    let verdict_text = field("verdict")?;
    let verdict = RulingVerdict::parse(verdict_text).ok_or_else(|| {
        format!(
            "rulings: {label}: verdict `{verdict_text}` is not one of {}",
            RulingVerdict::SPELLINGS.join(" | ")
        )
    })?;
    let issue = field("issue")?.to_owned();
    if !is_issue_reference(&issue) {
        return Err(format!(
            "rulings: {label}: issue `{issue}` is not of the form `<owner>/<repository>#<number>`"
        ));
    }
    let approved_by = field("approved_by")?.to_owned();
    let expires = field("expires")?.to_owned();
    let expires_day = civil_day(&expires).map_err(|error| format!("rulings: {label}: expires {error}"))?;
    Ok(Ruling {
        id,
        verdict,
        issue,
        approved_by,
        expires,
        expires_day,
    })
}

/// `<owner>/<repository>#<number>`, the one form a review can be found from.
fn is_issue_reference(text: &str) -> bool {
    let Some((repository, number)) = text.split_once('#') else {
        return false;
    };
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    let word = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    };
    word(owner) && word(name) && !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit())
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` calendar date.
///
/// # Errors
///
/// Returns a message naming the text when it is not that form, or not a date.
pub fn civil_day(text: &str) -> Result<i64, String> {
    let bad = || format!("`{text}` is not a calendar date of the form YYYY-MM-DD");
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 10
        && bytes.iter().enumerate().all(|(index, byte)| {
            if index == 4 || index == 7 {
                *byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        });
    if !shaped {
        return Err(bad());
    }
    let instant = crate::time::parse_rfc3339(&format!("{text}T00:00:00Z")).map_err(|_| bad())?;
    Ok(instant.unix_seconds.div_euclid(86_400))
}

/// Today in days since the Unix epoch, from the wall clock.
///
/// # Errors
///
/// Returns a message when the wall clock reads before the epoch or past what a day count holds.
pub fn today() -> Result<i64, String> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("the wall clock reads before the Unix epoch: {error}"))?;
    i64::try_from(elapsed.as_secs() / 86_400).map_err(|_| "the wall clock reads past what a day count holds".to_owned())
}

/// What a finished report owes the ledger, and what the ledger no longer needs.
#[derive(Debug, Default)]
pub struct Judgement<'a> {
    /// Failed or skipped cases with an unexpired ruling.
    pub ruled: Vec<(&'a CaseOutcome, &'a Ruling)>,
    /// Failed or skipped cases with no ruling at all.
    pub unruled: Vec<&'a CaseOutcome>,
    /// Failed or skipped cases whose ruling has lapsed.
    pub expired: Vec<(&'a CaseOutcome, &'a Ruling)>,
    /// Rulings on cases that passed; a note, never a failure.
    pub stale: Vec<&'a Ruling>,
}

impl Judgement<'_> {
    /// Whether the run must exit red: a case without an unexpired ruling.
    #[must_use]
    pub fn blocks(&self) -> bool {
        !self.unruled.is_empty() || !self.expired.is_empty()
    }

    /// The judgement as the reader sees it, one line per case.
    #[must_use]
    pub fn render(&self, ledger: &str) -> String {
        let mut out = format!(
            "rulings: {ledger}: {} ruled, {} unruled, {} expired\n",
            self.ruled.len(),
            self.unruled.len(),
            self.expired.len()
        );
        for (outcome, ruling) in &self.ruled {
            out.push_str(&format!(
                "  ruled    {} is {} — {}, {}, approved by {}, until {}\n",
                outcome.id,
                outcome.verdict.as_str(),
                ruling.verdict.as_str(),
                ruling.issue,
                ruling.approved_by,
                ruling.expires
            ));
        }
        for outcome in &self.unruled {
            let reason = outcome
                .skip_reason
                .as_deref()
                .map_or_else(String::new, |reason| format!(": {reason}"));
            out.push_str(&format!(
                "  unruled  {} is {} ({}){reason}\n",
                outcome.id,
                outcome.verdict.as_str(),
                outcome.relative
            ));
        }
        for (outcome, ruling) in &self.expired {
            out.push_str(&format!(
                "  expired  {} is {} — ruling expired {} ({})\n",
                outcome.id,
                outcome.verdict.as_str(),
                ruling.expires,
                ruling.issue
            ));
        }
        if !self.stale.is_empty() {
            let ids: Vec<&str> = self.stale.iter().map(|ruling| ruling.id.as_str()).collect();
            out.push_str(&format!(
                "  stale    {} ruling(s) name cases that passed and can be removed: {}\n",
                ids.len(),
                ids.join(", ")
            ));
        }
        out
    }
}

#[cfg(test)]
#[path = "rulings/tests.rs"]
mod tests;
