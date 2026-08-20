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
    /// reader must act on. Deliberately not the derived `Ord`, whose order is the declaration
    /// order of the variants and means nothing.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Verdict::Failed => 0,
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

    /// The machine-readable report.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut out = String::from("{\n");
        out.push_str(&format!("  \"validate_only\": {},\n", self.validate_only));
        // `null`, not the name, and not the field's absence. A validate-only run contacted no
        // target, so there is no value here that is true; a consumer holding this file and nothing
        // else would read the run banner's claim off `target` exactly as a reader of the text
        // report did before it was split. The keys stay present so that reading one is never a
        // missing-key error in a consumer that does not branch on `validate_only`.
        let named = |value: &str| if self.validate_only { "null".to_owned() } else { quote(value) };
        out.push_str(&format!("  \"target\": {},\n", named(&self.target)));
        out.push_str(&format!("  \"transport\": {},\n", named(&self.transport)));
        out.push_str(&format!("  \"profile\": {},\n", named(&self.profile)));
        out.push_str("  \"cases\": [\n");
        for (index, outcome) in self.outcomes.iter().enumerate() {
            let comma = if index + 1 == self.outcomes.len() { "" } else { "," };
            let failures: Vec<String> = outcome.failures().iter().map(|d| quote(&d.to_string())).collect();
            out.push_str(&format!(
                "    {{\"id\": {}, \"domain\": {}, \"file\": {}, \"verdict\": {}, \"phase\": {}, \"reason\": {}, \"failures\": [{}]}}{comma}\n",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(id: &str, domain: &str, verdict: Verdict) -> CaseOutcome {
        CaseOutcome {
            id: id.to_owned(),
            domain: domain.to_owned(),
            relative: format!("cases/{domain}/{id}.toml"),
            title: Some("a title".to_owned()),
            verdict,
            phase: Phase::Execute,
            skip_reason: (verdict == Verdict::Skipped).then(|| "no target".to_owned()),
            diagnostics: if verdict == Verdict::Failed {
                vec![Diagnostic::deny(
                    "expect/status",
                    "/expect/status",
                    "expected 200, observed 500",
                )]
            } else {
                Vec::new()
            },
            quirks: vec!["q-etag-0001".to_owned()],
            evidence: vec!["https://example.test/a".to_owned()],
        }
    }

    fn report() -> Report {
        Report {
            target: "scripted".to_owned(),
            transport: "hyper".to_owned(),
            profile: "aws".to_owned(),
            outcomes: vec![
                outcome("c-etag-0001", "etag", Verdict::Passed),
                outcome("c-sig-0001", "sig", Verdict::Failed),
                outcome("c-mpu-0001", "mpu", Verdict::Skipped),
            ],
            filtered_out: 0,
            notes: vec!["the facade must expose: a service entry point".to_owned()],
            polarity: (2, 1),
            validate_only: false,
        }
    }

    /// A report in the shape `validate` produces: every case checked, none executed.
    fn validated_report() -> Report {
        Report {
            outcomes: vec![
                outcome("c-etag-0001", "etag", Verdict::Validated),
                outcome("c-sig-0001", "sig", Verdict::Failed),
            ],
            notes: Vec::new(),
            validate_only: true,
            ..report()
        }
    }

    #[test]
    fn the_text_report_groups_by_capability_domain() {
        let rendered = report().render_text(None);
        assert!(rendered.contains("etag/  1 case(s)"));
        assert!(rendered.contains("sig/  1 case(s)"));
        assert!(rendered.contains("summary: 1 passed, 1 failed, 1 skipped"));
    }

    /// Negative — the summary of a corpus check must not spell the word a run's summary spells.
    #[test]
    fn a_validate_only_summary_counts_validated_rather_than_passed() {
        let rendered = validated_report().render_text(None);
        assert!(
            !rendered.contains("passed"),
            "a corpus check reports a pass it never observed:\n{rendered}"
        );
        assert!(rendered.contains("summary: 1 validated, 1 failed"), "{rendered}");
        assert!(rendered.contains("etag/  1 case(s): 1 validated, 0 failed"), "{rendered}");
    }

    /// Negative — the banner must not name a target, a transport or a profile it never reached.
    ///
    /// The verdict alone does not cover this: an agent scanning the head of the report reads
    /// `target rustfs-gateway assembled in process ... transport hyper` and concludes a service
    /// answered.
    #[test]
    fn a_validate_only_report_names_no_target_and_no_transport() {
        let rendered = validated_report().render_text(None);
        assert!(!rendered.contains("scripted"), "the target it never contacted:\n{rendered}");
        assert!(!rendered.contains("transport"), "the transport it never opened:\n{rendered}");
        assert!(!rendered.contains("profile"), "the profile it never claimed:\n{rendered}");
        assert!(rendered.contains("no case was executed"), "{rendered}");
    }

    /// A reader holding a validate-only report is told which command does measure.
    #[test]
    fn a_validate_only_report_names_the_command_that_executes() {
        assert!(
            validated_report()
                .render_text(None)
                .contains("conformance run --filter \'<case-id>\'")
        );
    }

    /// Negative — a run report keeps its banner and its `passed` tally exactly as it was.
    #[test]
    fn an_executed_report_still_names_its_target_and_counts_passes() {
        let rendered = report().render_text(None);
        assert!(rendered.contains("target    scripted"), "{rendered}");
        assert!(rendered.contains("transport hyper"), "{rendered}");
        assert!(rendered.contains("summary: 1 passed, 1 failed, 1 skipped"), "{rendered}");
        assert!(!rendered.contains("validated"), "{rendered}");
    }

    /// Negative — JUnit has no third colour, and a bare `<testcase/>` is how a dashboard draws
    /// "this ran and held". A validated case must not reach that shape.
    #[test]
    fn a_validated_case_is_not_a_junit_pass() {
        let rendered = validated_report().render_junit();
        assert!(rendered.contains("tests=\"2\" failures=\"1\" skipped=\"1\""), "{rendered}");
        assert!(rendered.contains("no assertion was evaluated"), "{rendered}");
        assert!(
            !rendered.contains("name=\"c-etag-0001\"/>"),
            "the validated case is rendered as a JUnit pass:\n{rendered}"
        );
    }

    /// The machine-readable report carries the distinction too — a consumer that only reads JSON
    /// must not have to infer it from the command line that produced the file.
    #[test]
    fn the_json_report_spells_the_validated_verdict() {
        let rendered = validated_report().render_json();
        assert!(rendered.contains("\"verdict\": \"validated\""), "{rendered}");
        assert!(json::parse(&rendered).is_ok(), "{rendered}");
    }

    /// Negative — the machine-readable report must not name a target it never contacted either.
    ///
    /// The text banner was the half of this defect a reader sees; `validate --json <file>` writes
    /// the same claim through the same flag a run uses, and a consumer holding only that file has
    /// nothing else to go on. The per-case verdict already says `validated`; the header still said
    /// a service answered.
    #[test]
    fn a_validate_only_json_report_names_no_target_and_no_transport() {
        let rendered = validated_report().render_json();
        assert!(rendered.contains("\"validate_only\": true"), "{rendered}");
        assert!(!rendered.contains("\"scripted\""), "the target it never contacted:\n{rendered}");
        assert!(!rendered.contains("\"hyper\""), "the transport it never opened:\n{rendered}");
        assert!(json::parse(&rendered).is_ok(), "{rendered}");
    }

    /// Negative — a run's JSON keeps naming its target, which is what the field is for.
    #[test]
    fn an_executed_json_report_still_names_its_target() {
        let rendered = report().render_json();
        assert!(rendered.contains("\"validate_only\": false"), "{rendered}");
        assert!(rendered.contains("\"target\": \"scripted\""), "{rendered}");
        assert!(rendered.contains("\"transport\": \"hyper\""), "{rendered}");
    }

    /// Negative — a case that was never executed cannot pay off a baseline failure.
    #[test]
    fn a_validated_case_is_not_an_improvement_over_a_recorded_failure() {
        let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "failed"}}"#).expect("valid baseline");
        assert!(
            validated_report().improvements(Some(&baseline)).is_empty(),
            "a corpus check tightened the ratchet without running anything"
        );
    }

    /// Negative — and it cannot hide one either: a schema or convention failure is still a
    /// regression, which is what keeps `validate`\'s exit status meaningful.
    #[test]
    fn a_validate_only_report_still_regresses_on_a_convention_failure() {
        let subject = validated_report();
        // By id, not by count. A count of one is satisfied by whichever of the two cases the
        // filter happens to select, so `regressions()` could pick the validated case instead of
        // the failed one and this would still read green.
        let regressed: Vec<&str> = subject.regressions(None).iter().map(|o| o.id.as_str()).collect();
        assert_eq!(regressed, ["c-sig-0001"], "the failed case is the only regression");
    }

    #[test]
    fn a_failure_carries_the_file_the_quirks_and_the_evidence() {
        let rendered = report().render_text(None);
        assert!(rendered.contains("file: cases/sig/c-sig-0001.toml"));
        assert!(rendered.contains("quirks: q-etag-0001"));
        assert!(rendered.contains("evidence: https://example.test/a"));
    }

    #[test]
    fn a_skip_always_states_its_reason() {
        let rendered = report().render_text(None);
        assert!(rendered.contains("reason: no target"));
    }

    #[test]
    fn without_a_baseline_every_failure_is_a_regression() {
        assert_eq!(report().regressions(None).len(), 1);
    }

    /// The baseline that records exactly what [`report`] concludes, which is the shape the
    /// repository's own `conformance/baseline.json` is required to have: a row per case.
    fn matching_baseline() -> Baseline {
        Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "skipped"}}"#)
            .expect("valid baseline")
    }

    #[test]
    fn a_baseline_tolerates_a_recorded_failure() {
        assert!(report().regressions(Some(&matching_baseline())).is_empty());
    }

    #[test]
    fn a_baseline_does_not_tolerate_a_new_failure() {
        let baseline =
            Baseline::from_json(r#"{"cases": {"c-etag-0001": "failed", "c-sig-0001": "passed", "c-mpu-0001": "skipped"}}"#)
                .expect("valid baseline");
        let subject = report();
        let regressions = subject.regressions(Some(&baseline));
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].id, "c-sig-0001");
    }

    /// The rule that makes a `passed` row worth writing down.
    ///
    /// Under the previous comparison this read green: only a failure could regress, so a family
    /// that stopped executing altogether — rustfs/gateway#203's `object/` domain against
    /// `Unwired`, rustfs/gateway#214's thirty-nine lost `acl` cases — was indistinguishable from
    /// a family that ran and passed.
    #[test]
    fn a_recorded_pass_that_now_skips_is_a_regression() {
        let baseline =
            Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
                .expect("valid baseline");
        let subject = report();
        let regressions = subject.regressions(Some(&baseline));
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].id, "c-mpu-0001");
    }

    /// A skip the baseline already records is not news, and neither is one that turns into a pass.
    #[test]
    fn a_recorded_skip_may_keep_skipping_and_may_improve() {
        assert!(report().regressions(Some(&matching_baseline())).is_empty());
        let recovered =
            Baseline::from_json(r#"{"cases": {"c-etag-0001": "skipped", "c-sig-0001": "failed", "c-mpu-0001": "skipped"}}"#)
                .expect("valid baseline");
        let subject = report();
        let improvements = subject.improvements(Some(&recovered));
        assert_eq!(improvements.len(), 1);
        assert_eq!(improvements[0].id, "c-etag-0001");
    }

    /// A case with no row is read as one that ought to pass, so forgetting the row cannot buy
    /// silence for a case that skips.
    ///
    /// This is the half that makes the completeness policy enforceable rather than decorative:
    /// without it, deleting a row is strictly weaker than editing one, and
    /// `scripts/check_baseline_ratchet.sh` only ever looked at the rows that were there.
    #[test]
    fn a_case_with_no_row_is_expected_to_pass() {
        let baseline = Baseline::from_json(r#"{"cases": {"c-sig-0001": "failed"}}"#).expect("valid baseline");
        let subject = report();
        let regressions = subject.regressions(Some(&baseline));
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].id, "c-mpu-0001", "an unrecorded skip is a regression");
    }

    /// A case that declares it does not apply to this run is not evidence about the target, in
    /// either direction.
    ///
    /// The shape this stops: a baseline recorded under `--profile aws` replayed under
    /// `--profile minio` would otherwise report every `aws`-only case as a regression, because
    /// the *run's own options* turned it into a skip before any request went out.
    #[test]
    fn a_case_that_does_not_apply_to_this_run_is_neither_a_regression_nor_an_improvement() {
        let mut subject = report();
        subject.outcomes[2].phase = Phase::Convention;
        subject.outcomes[2].skip_reason = Some("case.applies_to.profiles is [aws]".to_owned());
        let baseline =
            Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
                .expect("valid baseline");
        assert!(
            subject.regressions(Some(&baseline)).is_empty(),
            "a profile-gated skip is the run's own doing, not the target's"
        );
        assert!(subject.improvements(Some(&baseline)).is_empty());
    }

    /// The control for the case above: the same verdict reached at [`Phase::Execute`] — the target
    /// was asked and could not answer — is a regression.
    #[test]
    fn a_skip_the_target_caused_is_still_a_regression() {
        let subject = report();
        assert_eq!(subject.outcomes[2].phase, Phase::Execute);
        let baseline =
            Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
                .expect("valid baseline");
        let regressions = subject.regressions(Some(&baseline));
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].id, "c-mpu-0001");
    }

    /// A regression line names the verdict, because a regression is no longer always a failure.
    ///
    /// Without it a reader who sees `regression: c-mpu-0001` goes looking for a failed assertion
    /// that does not exist, and the actual finding — the case stopped running at all — is the one
    /// thing the line does not say.
    #[test]
    fn a_regression_line_says_which_verdict_it_is() {
        let baseline =
            Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
                .expect("valid baseline");
        let rendered = report().render_text(Some(&baseline));
        assert!(
            rendered.contains("regression: c-mpu-0001 is skipped (cases/mpu/c-mpu-0001.toml)"),
            "{rendered}"
        );
    }

    #[test]
    fn the_verdict_ladder_puts_a_skip_between_a_failure_and_a_pass() {
        assert!(Verdict::Failed.rank() < Verdict::Skipped.rank());
        assert!(Verdict::Skipped.rank() < Verdict::Passed.rank());
    }

    #[test]
    fn an_improvement_is_reported_so_the_ratchet_can_tighten() {
        let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "failed"}}"#).expect("valid baseline");
        assert_eq!(report().improvements(Some(&baseline)).len(), 1);
    }

    #[test]
    fn a_baseline_with_an_unknown_verdict_is_refused() {
        assert!(Baseline::from_json(r#"{"cases": {"c-etag-0001": "flaky"}}"#).is_err());
    }

    #[test]
    fn a_rendered_baseline_reloads() {
        let rendered = Baseline::render(&report());
        let baseline = Baseline::from_json(&rendered).expect("round trip");
        assert_eq!(baseline.expected("c-sig-0001"), Some(Verdict::Failed));
    }

    #[test]
    fn the_junit_document_escapes_and_counts() {
        let rendered = report().render_junit();
        assert!(rendered.contains("tests=\"3\" failures=\"1\" skipped=\"1\""));
        assert!(rendered.contains("<skipped message=\"no target\"/>"));
        assert!(rendered.contains("<failure message=\"expect/status\">"));
    }

    #[test]
    fn junit_escapes_markup_in_a_failure_message() {
        let mut subject = report();
        subject.outcomes[1].diagnostics = vec![Diagnostic::deny(
            "expect/body",
            "/expect/body",
            "expected <Prefix/> observed <Prefix></Prefix>",
        )];
        let rendered = subject.render_junit();
        assert!(rendered.contains("&lt;Prefix/&gt;"));
        assert!(!rendered.contains("observed <Prefix>"));
    }

    #[test]
    fn the_json_report_is_parseable() {
        let rendered = report().render_json();
        let parsed = json::parse(&rendered).expect("valid JSON");
        assert_eq!(parsed.path("cases").and_then(Value::as_array).map(<[Value]>::len), Some(3));
    }
}
