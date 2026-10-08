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

//! Verdicts, grouping, and baseline-aware reporting.
//!
//! Responsible for: one conclusion per case with the reason attached, grouped by capability
//! domain, and the decision of what fails a run. A first run against a foreign implementation is
//! always largely red, so a run fails on a *regression* against a checked-in baseline rather than
//! on the absolute failure count — that tolerance is the only reason anyone runs a foreign suite
//! against their own server twice.
//! NOT responsible for: producing verdicts (`crate::runner`) or judging assertions
//! (`crate::expect`).
//! Upstream: `crate::diagnostic`, `crate::json`. Downstream: `crate::cli`.

use crate::diagnostic::{Diagnostic, Severity};
use crate::json;
use crate::rulings::{Ruling, Rulings};
use crate::value::Value;
use std::collections::BTreeMap;

/// The conclusion for one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Every assertion held.
    Passed,
    /// At least one assertion or convention failed.
    Failed,
    /// The case did not run, and why is recorded.
    Skipped,
    /// The case is internally consistent, and no assertion in it was evaluated.
    ///
    /// This is what `validate` produces, and it is deliberately not [`Verdict::Passed`]. A corpus
    /// check that reached the same verdict as an executed case made a newly written case whose
    /// every assertion was wrong read green through the one command the feedback-loop table sends
    /// an agent to after changing a case.
    Validated,
}

impl Verdict {
    /// The lowercase spelling used in reports and baselines.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Passed => "passed",
            Verdict::Failed => "failed",
            Verdict::Skipped => "skipped",
            Verdict::Validated => "validated",
        }
    }

    /// How much evidence this verdict is, on the ladder the ratchet moves along.
    ///
    /// A pass is evidence the behaviour holds. A skip is the absence of evidence. A failure is
    /// evidence the behaviour does not hold, and it is the bottom rung because it is the one a
    /// reader must act on. A validation sits beside the failure: it also evaluated no assertion,
    /// so it pays off nothing — it can never be the improvement a recorded failure waits for.
    /// Deliberately not the derived `Ord`, whose order is the declaration
    /// order of the variants and means nothing.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            // A validation evaluated no assertion, so like a failure it pays off nothing: it can
            // never be the improvement a recorded failure waits for.
            Verdict::Failed | Verdict::Validated => 0,
            Verdict::Skipped => 1,
            Verdict::Passed => 2,
        }
    }
}

/// How far a case got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Reading and parsing the file.
    Load,
    /// Validation against the frozen schema.
    Schema,
    /// The conventions the schema cannot express.
    Convention,
    /// Running the exchanges against a target.
    Execute,
}

impl Phase {
    /// The lowercase spelling used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Load => "load",
            Phase::Schema => "schema",
            Phase::Convention => "convention",
            Phase::Execute => "execute",
        }
    }
}

/// One case's conclusion.
#[derive(Debug, Clone)]
pub struct CaseOutcome {
    /// The case identifier.
    pub id: String,
    /// The capability domain, which is the directory.
    pub domain: String,
    /// Path relative to the corpus root, for jumping straight to the file.
    pub relative: String,
    /// The case title, when it declares one.
    pub title: Option<String>,
    /// The conclusion.
    pub verdict: Verdict,
    /// How far it got.
    pub phase: Phase,
    /// Why it was skipped, when it was.
    pub skip_reason: Option<String>,
    /// Whether the skip is the target's transport limit ([`crate::sut::SutError::TransportLimit`]),
    /// the one kind of skip a socket transport can turn into a verdict. Not rendered: the skip
    /// reason says the same in words.
    pub transport_limited: bool,
    /// Every finding, failing and advisory alike.
    pub diagnostics: Vec<Diagnostic>,
    /// The quirks this case declares, printed with a failure so the reader knows what it protects.
    pub quirks: Vec<String>,
    /// The evidence URLs, for the same reason.
    pub evidence: Vec<String>,
}

impl CaseOutcome {
    /// The findings that failed the case.
    #[must_use]
    pub fn failures(&self) -> Vec<&Diagnostic> {
        self.diagnostics.iter().filter(|d| d.severity == Severity::Deny).collect()
    }

    /// The advisory findings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&Diagnostic> {
        self.diagnostics.iter().filter(|d| d.severity == Severity::Warn).collect()
    }

    /// Whether this case skipped because it declares it does not apply to *this run*.
    ///
    /// `case.applies_to` gates on the profile, the HTTP version and TLS, and `crate::runner`
    /// answers such a case with a skip at [`Phase::Convention`] — before a target is touched at
    /// all. Every other skip happens at [`Phase::Execute`], where the target was asked and could
    /// not answer.
    ///
    /// The distinction only matters because a skip can now be a regression. Without it, running a
    /// baseline recorded under `--profile aws` against `--profile minio` would report every
    /// `aws`-only case as a regression, which is the run's own options manufacturing findings
    /// about an implementation they never reached.
    #[must_use]
    pub fn declared_inapplicable(&self) -> bool {
        self.verdict == Verdict::Skipped && self.phase == Phase::Convention
    }
}

/// The result of a run.
#[derive(Debug, Clone)]
pub struct Report {
    /// What the run was pointed at.
    pub target: String,
    /// The assembly path.
    pub transport: String,
    /// The profile the target claims.
    pub profile: String,
    /// One conclusion per case, in corpus order.
    pub outcomes: Vec<CaseOutcome>,
    /// Cases filtered out before anything ran.
    pub filtered_out: usize,
    /// Selected cases this run left to the other shards of a `--shard` split; `0` without one.
    ///
    /// Kept apart from `filtered_out` because it answers a different question: those cases were
    /// wanted and will run elsewhere, so a shard that owns none of them is a partial run, not an
    /// empty selection.
    pub left_to_other_shards: usize,
    /// Run-wide notes, printed once at the end.
    ///
    /// A reason that applies to every case — "no target is wired, and here is what the facade
    /// must expose" — is a property of the run, not of a hundred and fifty cases. Repeating it
    /// per case buries the per-case conclusions it was meant to explain.
    pub notes: Vec<String>,
    /// Negative and positive case counts, for the corpus-wide polarity requirement.
    pub polarity: (usize, usize),
    /// Whether the run stopped after the corpus checks, without touching the target.
    ///
    /// The renderer needs this and not only the verdicts: `target`, `transport` and `profile`
    /// describe a target this run never contacted, and printing them over a corpus check is the
    /// half of the defect the verdict alone does not cover.
    pub validate_only: bool,
}

/// What the renderers know about a run beyond its verdicts.
///
/// The endpoint and build are what the target reported about itself before the run
/// (`crate::sut::TargetIdentity`); the ledger is the one the run was judged against, named by the
/// path the command line gave. Every field is absent by default, and an absent field renders as
/// `null` — a report must never carry a name the run did not observe.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunContext<'a> {
    /// The URL the run was pointed at, when it was pointed at one.
    pub endpoint: Option<&'a str>,
    /// The target's `Server` header on an unsigned `HEAD /`, when it sent one.
    pub target_build: Option<&'a str>,
    /// The rulings ledger, as the path the command line named and the rulings it holds.
    pub rulings: Option<(&'a str, &'a Rulings)>,
}

impl RunContext<'_> {
    fn ruling_on(&self, id: &str) -> Option<&Ruling> {
        self.rulings.and_then(|(_, rulings)| rulings.get(id))
    }
}

impl Report {
    /// Counts of each verdict.
    #[must_use]
    pub fn tally(&self) -> BTreeMap<Verdict, usize> {
        let mut tally = BTreeMap::new();
        for outcome in &self.outcomes {
            *tally.entry(outcome.verdict).or_insert(0) += 1;
        }
        tally
    }

    /// Outcomes grouped by capability domain, in name order.
    #[must_use]
    pub fn by_domain(&self) -> BTreeMap<&str, Vec<&CaseOutcome>> {
        let mut grouped: BTreeMap<&str, Vec<&CaseOutcome>> = BTreeMap::new();
        for outcome in &self.outcomes {
            grouped.entry(outcome.domain.as_str()).or_default().push(outcome);
        }
        grouped
    }

    /// Cases whose conclusion is worse than the one the baseline records.
    ///
    /// The comparison is over the whole ladder [`Verdict::rank`] defines, not over failure alone.
    /// A case the baseline records as `passed` and that now *skips* has stopped being evidence
    /// just as completely as one that fails: rustfs/gateway#203 found the whole `object/` domain
    /// running against `Unwired` in `cargo test`, so every case in it was a skip, and
    /// rustfs/gateway#214's mutation lost all thirty-nine `acl` cases with the ratchet still
    /// reporting `0 regression(s)` and exit 0. While a skip could not regress, every `passed` row
    /// in the baseline was inert — a failing case with a `passed` row and a failing case with no
    /// row at all took the identical branch — so recording a case bought nothing and the file was
    /// a list of excuses rather than a table of expectations.
    ///
    /// A case the baseline does not name is therefore read as `passed`: the baseline is complete
    /// by policy for this repository (`conformance/README.md`, and the corpus-wide guard in
    /// `tests/corpus.rs` that refuses a case with no row), so an absent row is a case that ought
    /// to have one and not a case nothing has an opinion about.
    ///
    /// With no baseline *at all* only a failure is a regression. That is the first run against a
    /// foreign server: nothing has yet claimed any case ever ran, so a skip has nothing to be
    /// worse than — and being red on every skip is exactly the welcome that stops anyone running
    /// a foreign suite twice.
    ///
    /// One skip is exempt in both directions: [`CaseOutcome::declared_inapplicable`]. A case that
    /// declares `applies_to.profiles = ["aws"]` skips under `--profile minio` because the case
    /// says so, not because the target lost anything, and a run's own options must not be able to
    /// manufacture regressions in a baseline recorded under different ones.
    #[must_use]
    pub fn regressions<'a>(&'a self, baseline: Option<&Baseline>) -> Vec<&'a CaseOutcome> {
        self.outcomes
            .iter()
            .filter(|outcome| !outcome.declared_inapplicable())
            .filter(|outcome| match baseline {
                None => outcome.verdict == Verdict::Failed,
                Some(baseline) => {
                    let expected = baseline.expected(&outcome.id).unwrap_or(Verdict::Passed);
                    outcome.verdict.rank() < expected.rank()
                }
            })
            .collect()
    }

    /// Cases whose conclusion is better than the one the baseline records — the ratchet's other
    /// end, and the same ladder read upwards.
    #[must_use]
    pub fn improvements<'a>(&'a self, baseline: Option<&Baseline>) -> Vec<&'a CaseOutcome> {
        let Some(baseline) = baseline else { return Vec::new() };
        self.outcomes
            .iter()
            .filter(|outcome| !outcome.declared_inapplicable())
            .filter(|outcome| {
                let expected = baseline.expected(&outcome.id).unwrap_or(Verdict::Passed);
                outcome.verdict.rank() > expected.rank()
            })
            .collect()
    }

    /// The human-readable report.
    #[must_use]
    pub fn render_text(&self, baseline: Option<&Baseline>) -> String {
        let mut out = String::new();
        if self.validate_only {
            // Deliberately not the run banner. `target`, `transport` and `profile` describe a
            // target this run never contacted, and a header that names one reports an intention as
            // an observation. The last line names the command that does measure, because a reader
            // who wanted a measurement is holding the wrong report.
            out.push_str(&format!("conformance: {} case(s) validated, none executed\n", self.outcomes.len()));
            out.push_str("  checked   the frozen schema and the corpus conventions\n");
            out.push_str("  not run   no case was executed, and no assertion in one was evaluated\n");
            out.push_str("  to run    conformance run --filter '<case-id>'\n");
        } else {
            out.push_str(&format!("conformance: {} cases\n", self.outcomes.len()));
            out.push_str(&format!("  target    {}\n", self.target));
            out.push_str(&format!("  transport {}\n", self.transport));
            out.push_str(&format!("  profile   {}\n", self.profile));
        }
        if self.filtered_out > 0 {
            out.push_str(&format!("  filtered  {} case(s) excluded by --filter\n", self.filtered_out));
        }
        if self.left_to_other_shards > 0 {
            out.push_str(&format!(
                "  sharded   {} selected case(s) belong to the other shards\n",
                self.left_to_other_shards
            ));
        }
        out.push('\n');

        for (domain, outcomes) in self.by_domain() {
            let count = |verdict: Verdict| outcomes.iter().filter(|o| o.verdict == verdict).count();
            let tally = if self.validate_only {
                format!("{} validated, {} failed", count(Verdict::Validated), count(Verdict::Failed))
            } else {
                format!(
                    "{} passed, {} failed, {} skipped",
                    count(Verdict::Passed),
                    count(Verdict::Failed),
                    count(Verdict::Skipped)
                )
            };
            out.push_str(&format!("{domain}/  {} case(s): {tally}\n", outcomes.len()));
            for outcome in outcomes {
                out.push_str(&format!(
                    "  {:<9} {:<16} {}\n",
                    outcome.verdict.as_str(),
                    outcome.id,
                    outcome.title.as_deref().unwrap_or("")
                ));
                if let Some(reason) = &outcome.skip_reason {
                    out.push_str(&format!("      reason: {reason}\n"));
                }
                for failure in outcome.failures() {
                    out.push_str(&format!("      FAIL {failure}\n"));
                }
                if outcome.verdict == Verdict::Failed {
                    out.push_str(&format!("      file: {}\n", outcome.relative));
                    if !outcome.quirks.is_empty() {
                        out.push_str(&format!("      quirks: {}\n", outcome.quirks.join(", ")));
                    }
                    for url in &outcome.evidence {
                        out.push_str(&format!("      evidence: {url}\n"));
                    }
                }
                for warning in outcome.warnings() {
                    out.push_str(&format!("      warn {warning}\n"));
                }
            }
            out.push('\n');
        }

        for note in &self.notes {
            out.push_str(&format!("note: {note}\n"));
        }
        if !self.notes.is_empty() {
            out.push('\n');
        }

        let tally = self.tally();
        let count = |verdict: Verdict| tally.get(&verdict).copied().unwrap_or(0);
        if self.validate_only {
            out.push_str(&format!(
                "summary: {} validated, {} failed — no case was executed\n",
                count(Verdict::Validated),
                count(Verdict::Failed)
            ));
        } else {
            out.push_str(&format!(
                "summary: {} passed, {} failed, {} skipped\n",
                count(Verdict::Passed),
                count(Verdict::Failed),
                count(Verdict::Skipped)
            ));
        }
        let (negative, positive) = self.polarity;
        out.push_str(&format!(
            "polarity: {negative} negative, {positive} positive ({})\n",
            if negative >= positive {
                "ok"
            } else {
                "negative cases must outnumber positive ones"
            }
        ));
        let regressions = self.regressions(baseline);
        if baseline.is_some() {
            out.push_str(&format!(
                "baseline: {} regression(s), {} improvement(s)\n",
                regressions.len(),
                self.improvements(baseline).len()
            ));
        }
        for outcome in &regressions {
            // The verdict is named because a regression is no longer always a failure: a case the
            // baseline records as passing that now *skips* is one, and "regression: c-acl-0001"
            // with no verdict reads as a failed assertion the reader will then go looking for.
            out.push_str(&format!(
                "regression: {} is {} ({})\n",
                outcome.id,
                outcome.verdict.as_str(),
                outcome.relative
            ));
        }
        out
    }

    /// The machine-readable report, for a run that observed nothing about its target and was
    /// judged against no ledger.
    #[must_use]
    pub fn render_json(&self) -> String {
        self.render_json_in(&RunContext::default())
    }

    /// The machine-readable report, with what the run learned about its target and its ledger.
    ///
    /// A ruled case keeps its verdict and gains a `ruling` object; an unruled one carries
    /// `"ruling": null`, so the key is always present.
    #[must_use]
    pub fn render_json_in(&self, context: &RunContext<'_>) -> String {
        let mut out = String::from("{\n");
        out.push_str(&format!("  \"validate_only\": {},\n", self.validate_only));
        // `null`, not the name, and not the field's absence. A validate-only run contacted no
        // target, so there is no value here that is true; a consumer holding this file and nothing
        // else would read the run banner's claim off `target` exactly as a reader of the text
        // report did before it was split. The keys stay present so that reading one is never a
        // missing-key error in a consumer that does not branch on `validate_only`.
        let named = |value: &str| if self.validate_only { "null".to_owned() } else { quote(value) };
        let observed = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), &named);
        out.push_str(&format!("  \"target\": {},\n", named(&self.target)));
        out.push_str(&format!("  \"transport\": {},\n", named(&self.transport)));
        out.push_str(&format!("  \"profile\": {},\n", named(&self.profile)));
        out.push_str(&format!("  \"endpoint\": {},\n", observed(context.endpoint)));
        out.push_str(&format!("  \"target_build\": {},\n", observed(context.target_build)));
        out.push_str(&format!(
            "  \"rulings\": {},\n",
            context.rulings.map_or_else(|| "null".to_owned(), |(ledger, _)| quote(ledger))
        ));
        out.push_str("  \"cases\": [\n");
        for (index, outcome) in self.outcomes.iter().enumerate() {
            let comma = if index + 1 == self.outcomes.len() { "" } else { "," };
            let failures: Vec<String> = outcome.failures().iter().map(|d| quote(&d.to_string())).collect();
            let ruling = context.ruling_on(&outcome.id).map_or_else(
                || "null".to_owned(),
                |ruling| {
                    format!(
                        "{{\"verdict\": {}, \"issue\": {}, \"approved_by\": {}, \"expires\": {}}}",
                        quote(ruling.verdict.as_str()),
                        quote(&ruling.issue),
                        quote(&ruling.approved_by),
                        quote(&ruling.expires)
                    )
                },
            );
            out.push_str(&format!(
                "    {{\"id\": {}, \"domain\": {}, \"file\": {}, \"verdict\": {}, \"phase\": {}, \"reason\": {}, \"failures\": [{}], \"ruling\": {ruling}}}{comma}\n",
                quote(&outcome.id),
                quote(&outcome.domain),
                quote(&outcome.relative),
                quote(outcome.verdict.as_str()),
                quote(outcome.phase.as_str()),
                quote(outcome.skip_reason.as_deref().unwrap_or("")),
                failures.join(", "),
            ));
        }
        out.push_str("  ]\n}\n");
        out
    }

    /// A JUnit document, for a CI system that already knows how to read one.
    #[must_use]
    pub fn render_junit(&self) -> String {
        self.render_junit_in(&RunContext::default())
    }

    /// A JUnit document that also notes each ruling beside the failure or skip it covers.
    ///
    /// JUnit has no colour for "failed, and ruled": the `<failure>` stays, and the ruling is a
    /// `<system-out>` line a reader finds next to it. Rendering a ruled case as a bare pass would
    /// be the report borrowing green it did not measure.
    #[must_use]
    pub fn render_junit_in(&self, context: &RunContext<'_>) -> String {
        let failures = self.outcomes.iter().filter(|o| o.verdict == Verdict::Failed).count();
        // A validated case counts as skipped, never as a JUnit pass: JUnit has no third colour,
        // and a bare `<testcase/>` is how a CI dashboard renders "this ran and held".
        let skipped = self
            .outcomes
            .iter()
            .filter(|o| matches!(o.verdict, Verdict::Skipped | Verdict::Validated))
            .count();
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(&format!(
            "<testsuite name=\"conformance\" tests=\"{}\" failures=\"{failures}\" skipped=\"{skipped}\">\n",
            self.outcomes.len()
        ));
        for outcome in &self.outcomes {
            out.push_str(&format!(
                "  <testcase classname=\"{}\" name=\"{}\"",
                escape_xml(&outcome.domain),
                escape_xml(&outcome.id)
            ));
            match outcome.verdict {
                Verdict::Passed => out.push_str("/>\n"),
                Verdict::Validated => {
                    out.push_str(">\n");
                    out.push_str(
                        "    <skipped message=\"validated against the schema and the conventions; \
                         no assertion was evaluated\"/>\n",
                    );
                    out.push_str("  </testcase>\n");
                }
                Verdict::Skipped => {
                    out.push_str(">\n");
                    out.push_str(&format!(
                        "    <skipped message=\"{}\"/>\n",
                        escape_xml(outcome.skip_reason.as_deref().unwrap_or("not run"))
                    ));
                    out.push_str(&ruling_note(context.ruling_on(&outcome.id)));
                    out.push_str("  </testcase>\n");
                }
                Verdict::Failed => {
                    out.push_str(">\n");
                    for failure in outcome.failures() {
                        out.push_str(&format!(
                            "    <failure message=\"{}\">{}</failure>\n",
                            escape_xml(&failure.rule),
                            escape_xml(&failure.to_string())
                        ));
                    }
                    out.push_str(&ruling_note(context.ruling_on(&outcome.id)));
                    out.push_str("  </testcase>\n");
                }
            }
        }
        out.push_str("</testsuite>\n");
        out
    }
}

/// The failures a previous run recorded, so only a regression fails CI.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    entries: BTreeMap<String, Verdict>,
}

impl Baseline {
    /// Reads a baseline document: `{"cases": {"c-etag-0001": "failed", ...}}`.
    ///
    /// # Errors
    ///
    /// Returns a message when the document is not JSON or does not have that shape.
    pub fn from_json(source: &str) -> Result<Baseline, String> {
        let document = json::parse(source).map_err(|error| error.to_string())?;
        let Some(Value::Table(cases)) = document.get("cases") else {
            return Err("a baseline needs a `cases` object mapping case id to verdict".to_owned());
        };
        let mut entries = BTreeMap::new();
        for (id, verdict) in cases {
            let verdict = match verdict.as_str() {
                Some("passed") => Verdict::Passed,
                Some("failed") => Verdict::Failed,
                Some("skipped") => Verdict::Skipped,
                other => return Err(format!("{id}: unknown verdict {other:?}")),
            };
            entries.insert(id.clone(), verdict);
        }
        Ok(Baseline { entries })
    }

    /// The verdict the baseline records for a case.
    #[must_use]
    pub fn expected(&self, id: &str) -> Option<Verdict> {
        self.entries.get(id).copied()
    }

    /// Every case id the baseline names, in id order.
    ///
    /// The table has to be readable in both directions to be checked in both directions: a row
    /// naming a case the corpus no longer holds is a tolerance nothing can spend, and
    /// [`Baseline::expected`] alone can only ever ask about ids somebody already thought of.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Renders the current report as a baseline document, for the maintainer to check in.
    #[must_use]
    pub fn render(report: &Report) -> String {
        let mut out = String::from("{\n  \"cases\": {\n");
        for (index, outcome) in report.outcomes.iter().enumerate() {
            let comma = if index + 1 == report.outcomes.len() { "" } else { "," };
            out.push_str(&format!("    {}: {}{comma}\n", quote(&outcome.id), quote(outcome.verdict.as_str())));
        }
        out.push_str("  }\n}\n");
        out
    }
}

/// The JUnit line that names a ruling, or nothing when the case has none.
fn ruling_note(ruling: Option<&Ruling>) -> String {
    ruling.map_or_else(String::new, |ruling| {
        format!(
            "    <system-out>ruling: {} {} approved by {}, expires {}</system-out>\n",
            escape_xml(ruling.verdict.as_str()),
            escape_xml(&ruling.issue),
            escape_xml(&ruling.approved_by),
            escape_xml(&ruling.expires)
        )
    })
}

fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
