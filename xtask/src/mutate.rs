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

//! `cargo xtask conformance mutate`: the per-quirk kill matrix.
//!
//! Responsible for: flipping one declared protocol rule at a time, rebuilding the gateway from the
//! mutated rule, running the corpus against it, and reporting for each rule whether a case caught
//! it — separating that from the two ways a green run means nothing.
//! NOT responsible for: choosing the flip (that is `rustfs_gateway_codegen::mutate`), writing it
//! into the IR (that is `rustfs_gateway_codegen::mutate::apply`), or any assertion in the corpus.
//! Upstream: `spec/quirks/*.toml` by way of the overlay. Downstream: the operator reading the
//! matrix and the issues that ask for it.
//!
//! # The two green runs that are not coverage
//!
//! A mutation that leaves the suite green is either a real gap in the corpus or a mutation that
//! never reached the program under test, and from the outside those look identical. Only one is a
//! finding, so this command proves the mutation landed before it is allowed to report a survivor:
//!
//! 1. The regenerated artefacts must differ from the unmutated ones. Identical bytes mean the flip
//!    was written somewhere code generation does not read.
//! 2. Cargo must have *recompiled* `rustfs-gateway`, the library the in-process target is
//!    assembled from. The tree is restored and rebuilt after every rule, so every unit is fresh
//!    when the next mutation is written; cargo then reports the gateway as stale exactly when the
//!    mutated artefact is one a production unit compiles. Artefacts that change without making the
//!    gateway stale are artefacts nothing in the running gateway reads — `q-lc-0001` is exactly
//!    that shape, and calling it a coverage gap would blame the corpus for a ledger claim.
//!    A debug rlib is not reproducible byte for byte across rebuilds, so its digest is used only
//!    as a control on cargo's own freshness claim, never as the claim itself.
//! 3. The mutated run must return a verdict for at least as many cases as the baseline run. A run
//!    that measured fewer cases has not shown that the surviving cases survived.
//!
//! Only after all three does a green run get called `SURVIVED`. A mutated tree that does not
//! compile is `KILLED_BY_COMPILE` and is counted separately: the compiler noticing is not the
//! corpus noticing, and this repository has been burned before by a check whose green came from
//! somewhere other than the thing it claimed to measure.
//!
//! # What `SURVIVED` still cannot separate
//!
//! Control 2 is at **file** granularity and the claim it supports — "running code reads this rule"
//! — is at **read** granularity. A generated constant that no code reads still sits in a file the
//! gateway compiles, so changing it makes cargo rebuild and the row reports `SURVIVED` exactly as a
//! real corpus gap does. `q-bkt-0001` was that shape: `RouteRow::success_status` was dropped by
//! `generated_entries`, and the repair that `SURVIVED` invites — write two cases — could not have
//! worked, because no response was built from the value. The two verdicts are told apart by reading
//! the rule's source path and asking who reads it; rustfs/gateway#242 records why this control
//! cannot answer that on its own, and that the tractable fix is to shrink the generated surface
//! until `dead_code` can answer it, not to add a fourth control here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rustfs_gateway_codegen::mutate::{self, Mutation};
use rustfs_gateway_codegen::{Artifacts, CodegenInput, CodegenOutput};
use rustfs_gateway_conformance::sha256;
use rustfs_gateway_model::{Overlay, RuleClassification};

use crate::codegen::repo_root;

#[cfg(test)]
mod tests;

/// What one mutated rule proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A case that was green at baseline is red under the mutation.
    Killed {
        /// The cases that flipped, in id order.
        by: Vec<String>,
        /// Whether at least one of them is a case the quirk's ledger row names.
        declared: bool,
    },
    /// The mutated tree does not compile. Real, but not evidence about the corpus.
    KilledByCompile,
    /// Applied, built, measured — and every case stayed green. This is the finding.
    Survived,
    /// The mutation changed nothing the running gateway reads, so nothing was measured.
    Inert(String),
    /// No flip could be planned for this rule's shape.
    Unplannable(String),
    /// The rule is not an IR-source rule; this executor has no writer for it.
    Unsupported(String),
    /// The run itself did not produce a usable measurement.
    NotMeasured(String),
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Outcome::Killed { .. } => "KILLED",
            Outcome::KilledByCompile => "KILLED_BY_COMPILE",
            Outcome::Survived => "SURVIVED",
            Outcome::Inert(_) => "INERT",
            Outcome::Unplannable(_) => "UNPLANNABLE",
            Outcome::Unsupported(_) => "UNSUPPORTED",
            Outcome::NotMeasured(_) => "NOT_MEASURED",
        }
    }

    /// Whether the run may exit zero on this outcome.
    ///
    /// Only a kill by a case counts. A compile kill is honest but is not the corpus catching
    /// anything, and every remaining outcome is either a gap or a hole in this executor.
    fn is_pass(&self) -> bool {
        matches!(self, Outcome::Killed { declared: true, .. })
    }
}

/// What was observed for one mutated rule, before it is judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Measurement {
    /// Whether regeneration produced different artefact bytes.
    pub(crate) artifacts_changed: bool,
    /// Whether the mutated tree compiled.
    pub(crate) compiled: bool,
    /// Whether cargo recompiled the gateway library for the mutated tree.
    pub(crate) library_rebuilt: bool,
    /// Case id to verdict, or `None` when the run produced no report at all.
    pub(crate) verdicts: Option<BTreeMap<String, String>>,
}

const PASSED: &str = "passed";

/// Judges one measurement against the baseline verdicts.
///
/// Split out as a pure function so the order of the three "this proves nothing" guards is itself
/// testable: they have to run before the green-suite branch, or a mutation that never reached the
/// gateway is reported as a corpus gap.
pub(crate) fn classify(baseline: &BTreeMap<String, String>, declared: &[String], observed: &Measurement) -> Outcome {
    if !observed.artifacts_changed {
        return Outcome::Inert("regenerating with the mutation produced byte-identical artefacts".to_owned());
    }
    if !observed.compiled {
        return Outcome::KilledByCompile;
    }
    if !observed.library_rebuilt {
        return Outcome::Inert(
            "the artefacts changed but cargo rebuilt no production code, so no running code reads this rule".to_owned(),
        );
    }
    // A survivor is only a finding when something could have caught it. A baseline in which no case
    // is green makes every mutation a survivor by arithmetic, which is the vacuous shape this whole
    // command exists to avoid — most easily reached by narrowing `--filter` onto a case the
    // baseline already records as failing.
    if !baseline.values().any(|verdict| verdict == PASSED) {
        return Outcome::NotMeasured("no case was green at baseline, so no mutation could have been caught".to_owned());
    }
    let Some(verdicts) = &observed.verdicts else {
        return Outcome::NotMeasured("the mutated run produced no report".to_owned());
    };
    if verdicts.len() < baseline.len() {
        return Outcome::NotMeasured(format!(
            "the mutated run returned {} verdicts against {} at baseline",
            verdicts.len(),
            baseline.len()
        ));
    }
    let mut by: Vec<String> = Vec::new();
    for (id, verdict) in baseline {
        if verdict != PASSED {
            continue;
        }
        match verdicts.get(id) {
            Some(found) if found == PASSED => {}
            // A case green at baseline that is no longer green — including one the mutated run did
            // not reach at all, which is a real change in what the suite can execute.
            _ => by.push(id.clone()),
        }
    }
    if by.is_empty() {
        return Outcome::Survived;
    }
    let declared_hit = by.iter().any(|id| declared.iter().any(|case| case == id));
    Outcome::Killed {
        by,
        declared: declared_hit,
    }
}

struct Options {
    family: Option<String>,
    quirk: Option<String>,
    filter: Option<String>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        family: None,
        quirk: None,
        filter: None,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let value =
            |rest: &mut std::slice::Iter<'_, String>| rest.next().cloned().ok_or_else(|| format!("`{arg}` needs a value"));
        match arg.as_str() {
            "--family" => options.family = Some(value(&mut rest)?),
            "--quirk" => options.quirk = Some(value(&mut rest)?),
            "--filter" => options.filter = Some(value(&mut rest)?),
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    if options.family.is_none() && options.quirk.is_none() {
        return Err("one of `--family <name>` or `--quirk <id>` is required".to_owned());
    }
    Ok(options)
}

/// Runs the command line.
pub(crate) fn command(args: &[String]) -> std::process::ExitCode {
    let options = match parse(args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("conformance mutate: {message}\n\n{USAGE}");
            return std::process::ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(message) => {
            eprintln!(
                "conformance mutate: {message}\n\
                 note: if the run stopped after a mutation was written, the generated tree still \
                 carries it — `cargo xtask codegen` puts it back."
            );
            std::process::ExitCode::from(3)
        }
    }
}

/// The usage text for the subcommand.
pub(crate) const USAGE: &str = "\
usage: cargo xtask conformance mutate (--family <name> | --quirk <id>) [--filter <glob>]

  --family <name>   every mutable rule the overlay file model/overlays/quirks/<name>.toml declares
  --quirk <id>      one rule, by its stable id
  --filter <glob>   narrow the corpus run; the default runs every case
";

/// One rule and the flips planned for its sources.
struct Target {
    quirk: String,
    dimension: String,
    declared_cases: Vec<String>,
    plan: Result<Vec<Mutation>, Outcome>,
}

#[allow(clippy::too_many_lines)] // The loop is the command; splitting it would hide the restore.
fn run(options: &Options) -> Result<bool, String> {
    let root = repo_root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);

    let baseline_artifacts = rustfs_gateway_codegen::generate(&input, &out).map_err(|e| e.to_string())?;
    // The tree has to already match its own generator, or "restore" would write bytes that are not
    // the bytes the operator started with.
    rustfs_gateway_codegen::verify(&input, &out)
        .map_err(|e| format!("the checked-in artefacts differ from `cargo xtask codegen`; regenerate first\n{e}"))?;

    let overlay = Overlay::load(&input.overlays).map_err(|e| e.to_string())?;
    let families = mutate::quirk_families(&input.overlays).map_err(|e| e.to_string())?;
    let targets = select(options, &overlay, &families, &baseline_artifacts)?;
    if targets.is_empty() {
        return Err(format!(
            "no mutable rule matched {}",
            options.family.as_ref().map_or_else(
                || format!("quirk `{}`", options.quirk.as_deref().unwrap_or("")),
                |f| format!("family `{f}`")
            )
        ));
    }

    println!(
        "baseline: building the gateway and running the corpus ({})",
        options
            .filter
            .as_ref()
            .map_or_else(|| "every case".to_owned(), |filter| format!("filter `{filter}`"))
    );
    build(&root)?.require_success("the unmutated tree does not build")?;
    let baseline_verdicts =
        corpus(&root, options.filter.as_deref())?.ok_or_else(|| "the unmutated corpus run produced no report".to_owned())?;
    println!(
        "baseline: {} cases measured, {} green",
        baseline_verdicts.len(),
        baseline_verdicts.values().filter(|v| *v == PASSED).count()
    );

    // Settle the freshness signal before it becomes load-bearing. The corpus run is a second cargo
    // invocation and on a cold target directory it leaves the gateway stale, so the first mutated
    // rule of a run reads as `library_rebuilt` whether or not the mutation touched anything the
    // gateway compiles — which reports an INERT rule as SURVIVED, the one confusion this command
    // exists to prevent. Observed on `main` for `q-lc-0001`: SURVIVED on the first run of a fresh
    // worktree, INERT on every run after. One rebuild absorbs the staleness; if the next build is
    // still not fresh, freshness cannot answer for anything here and saying so is the only honest
    // outcome.
    build(&root)?.require_success("the unmutated tree does not build after the baseline run")?;
    let mut settled = build(&root)?.require_success("the unmutated tree does not build after the baseline run")?;
    if settled.rebuilt {
        return Err(
            "cargo rebuilt `rustfs-gateway` from an unchanged tree, so its freshness cannot say whether a \
             mutation reached the library; every rule would be reported as SURVIVED without evidence"
                .to_owned(),
        );
    }
    println!();

    let mut results: Vec<(String, String, Outcome)> = Vec::new();
    for target in &targets {
        let outcome = match &target.plan {
            Err(outcome) => outcome.clone(),
            Ok(mutations) => {
                let observed = measure(&input, &out, &root, &baseline_artifacts, &settled, options, mutations);
                // Whatever happened, the tree goes back and is rebuilt before the next rule is
                // touched, so the next build's freshness answers only about the next mutation.
                restore(&baseline_artifacts)?;
                settled = build(&root)?.require_success("the restored tree does not build")?;
                classify(&baseline_verdicts, &target.declared_cases, &observed?)
            }
        };
        println!("{:<34} {:<26} {}", target.quirk, target.dimension, describe(&outcome));
        results.push((target.quirk.clone(), target.dimension.clone(), outcome));
    }

    // The closing control: the tree the operator started with is the tree they are left with.
    restore(&baseline_artifacts)?;
    rustfs_gateway_codegen::verify(&input, &out).map_err(|e| format!("the mutation loop did not put the tree back\n{e}"))?;
    build(&root)?.require_success("the restored tree does not build")?;

    print!("{}", summary(&results));
    Ok(results.iter().all(|(_, _, outcome)| outcome.is_pass()))
}

fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Killed { by, declared: true } => format!("KILLED by {}", by.join(", ")),
        Outcome::Killed { by, declared: false } => {
            format!("KILLED by {} — none of them is a case this rule's ledger row names", by.join(", "))
        }
        Outcome::KilledByCompile => "KILLED_BY_COMPILE — the mutated tree does not build; no case was consulted".to_owned(),
        Outcome::Survived => "SURVIVED — the mutation reached a file the gateway compiles and no case noticed; \
             that is a corpus gap OR a lowered value nothing reads, and the freshness control cannot tell them \
             apart (rustfs/gateway#242)"
            .to_owned(),
        Outcome::Inert(why) | Outcome::Unplannable(why) | Outcome::Unsupported(why) | Outcome::NotMeasured(why) => {
            format!("{} — {why}", outcome.label())
        }
    }
}

fn summary(results: &[(String, String, Outcome)]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, _, outcome) in results {
        *counts.entry(outcome.label()).or_default() += 1;
    }
    let mut out = String::from("\nmatrix: ");
    let rendered: Vec<String> = counts.iter().map(|(label, count)| format!("{count} {label}")).collect();
    out.push_str(&rendered.join(", "));
    let _ = writeln!(out, " (of {} rule(s))", results.len());
    if results.iter().all(|(_, _, outcome)| outcome.is_pass()) {
        out.push_str("every rule was killed by a case its ledger row names\n");
    } else {
        out.push_str("not every rule was killed by a case it names; the rows above that are not KILLED are the work left\n");
    }
    out
}

fn select(
    options: &Options,
    overlay: &Overlay,
    families: &BTreeMap<String, String>,
    artifacts: &Artifacts,
) -> Result<Vec<Target>, String> {
    let mut targets = Vec::new();
    let wanted: Vec<String> = match (&options.quirk, &options.family) {
        (Some(id), _) => vec![id.clone()],
        (None, Some(family)) => families
            .iter()
            .filter(|(_, declared)| *declared == family)
            .map(|(id, _)| id.clone())
            .collect(),
        (None, None) => Vec::new(),
    };
    for id in wanted {
        let Some(quirk) = overlay.quirks.get(&id) else {
            return Err(format!("`{id}` is not a declared quirk"));
        };
        if overlay.classifications.get(&id).copied() != Some(RuleClassification::Mutable) {
            // A contract row is deliberately skipped rather than reported: it is not this
            // executor's subject, and listing 248 of them would bury the matrix.
            if options.quirk.is_some() {
                return Err(format!("`{id}` is a contract record, not a mutable rule"));
            }
            continue;
        }
        let declared_cases = quirk.cases.clone();
        let (dimension, plan) = match overlay.source_rules.get(&id) {
            Some(rule) => {
                let dimension = rule.mutation_dimension.as_str().to_owned();
                let sources = artifacts
                    .source_rules
                    .get(&id)
                    .ok_or_else(|| format!("quirk `{id}` has no resolved source"))?;
                let planned: Result<Vec<Mutation>, String> = sources
                    .iter()
                    .map(|source| mutate::plan(&id, rule.mutation_dimension, source))
                    .collect();
                (dimension, planned.map_err(Outcome::Unplannable))
            }
            None => {
                let dimension = overlay
                    .codec_rules
                    .get(&id)
                    .map_or_else(|| "unknown".to_owned(), |rule| rule.mutation_dimension.as_str().to_owned());
                (
                    dimension,
                    Err(Outcome::Unsupported(
                        "this rule is a codec input, not a lowered-IR source; it needs a second writer".to_owned(),
                    )),
                )
            }
        };
        targets.push(Target {
            quirk: id,
            dimension,
            declared_cases,
            plan,
        });
    }
    Ok(targets)
}

fn measure(
    input: &CodegenInput,
    out: &CodegenOutput,
    root: &Path,
    baseline_artifacts: &Artifacts,
    settled: &Built,
    options: &Options,
    mutations: &[Mutation],
) -> Result<Measurement, String> {
    let mutated = rustfs_gateway_codegen::generate_mutated(input, out, mutations).map_err(|e| e.to_string())?;
    let artifacts_changed = mutated.files != baseline_artifacts.files;
    if !artifacts_changed {
        return Ok(Measurement {
            artifacts_changed: false,
            compiled: false,
            library_rebuilt: false,
            verdicts: None,
        });
    }
    if paths(&mutated) != paths(baseline_artifacts) {
        return Err("the mutation changed which artefacts exist; this executor only restores bytes".to_owned());
    }
    write_files(&mutated)?;
    let built = build(root)?;
    if !built.ok {
        return Ok(Measurement {
            artifacts_changed: true,
            compiled: false,
            library_rebuilt: false,
            verdicts: None,
        });
    }
    // Control on cargo's own answer: a unit it calls fresh must be the file it was fresh from. A
    // debug rlib is not reproducible across rebuilds, so this is the only direction that can be
    // asserted — and it is the direction that would hide a mutation.
    if !built.rebuilt && built.digest != settled.digest {
        return Err(format!(
            "cargo reported `{}` fresh but its digest moved from {} to {}",
            built.rlib.display(),
            settled.digest,
            built.digest
        ));
    }
    let verdicts = if built.rebuilt {
        corpus(root, options.filter.as_deref())?
    } else {
        None
    };
    Ok(Measurement {
        artifacts_changed: true,
        compiled: true,
        library_rebuilt: built.rebuilt,
        verdicts,
    })
}

fn paths(artifacts: &Artifacts) -> BTreeSet<&PathBuf> {
    artifacts.files.iter().map(|(path, _)| path).collect()
}

fn write_files(artifacts: &Artifacts) -> Result<(), String> {
    for (path, body) in &artifacts.files {
        let unchanged = std::fs::read_to_string(path).map(|old| old == *body).unwrap_or(false);
        if !unchanged {
            std::fs::write(path, body).map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

fn restore(baseline: &Artifacts) -> Result<(), String> {
    write_files(baseline)
}

fn digest(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ok(sha256::hex_digest(&bytes))
}

/// What one build of the gateway library produced.
pub(crate) struct Built {
    ok: bool,
    rebuilt: bool,
    rlib: PathBuf,
    digest: String,
}

impl Built {
    fn require_success(self, failure: &str) -> Result<Built, String> {
        if self.ok { Ok(self) } else { Err(failure.to_owned()) }
    }
}

/// Builds the library the in-process conformance target is assembled from, and reports whether
/// cargo had to recompile it.
///
/// Freshness is the load-bearing answer: the caller restores and rebuilds after every rule, so a
/// build cargo calls fresh is one whose inputs the mutation did not touch — which is the difference
/// between a rule no case checks and a rule no code reads.
fn build(root: &Path) -> Result<Built, String> {
    let output = Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["build", "--package", "rustfs-gateway", "--lib", "--message-format", "json"])
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("failed to run cargo build: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut found: Option<(bool, PathBuf)> = None;
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        if value
            .get("target")
            .and_then(|target| target.get("name"))
            .and_then(serde_json::Value::as_str)
            != Some("rustfs_gateway")
        {
            continue;
        }
        let fresh = value.get("fresh").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let rlib = value
            .get("filenames")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .find(|name| name.ends_with(".rlib"));
        if let Some(rlib) = rlib {
            found = Some((fresh, PathBuf::from(rlib)));
        }
    }
    if !output.status.success() {
        return Ok(Built {
            ok: false,
            rebuilt: false,
            rlib: PathBuf::new(),
            digest: String::new(),
        });
    }
    // A successful build that named no artefact would leave every later comparison unanchored, so
    // refusing is the only honest answer.
    let (fresh, rlib) =
        found.ok_or_else(|| "cargo reported no rlib for `rustfs-gateway`; there is nothing to fingerprint".to_owned())?;
    let digest = digest(&rlib)?;
    Ok(Built {
        ok: true,
        rebuilt: !fresh,
        rlib,
        digest,
    })
}

/// Runs the corpus and returns case id to verdict, or `None` when no report was produced.
fn corpus(root: &Path, filter: Option<&str>) -> Result<Option<BTreeMap<String, String>>, String> {
    let report = root.join("target").join("mutate-report.json");
    // A stale report from the previous rule would be read as this rule's measurement.
    let _ = std::fs::remove_file(&report);
    let mut command = Command::new(env!("CARGO"));
    command
        .current_dir(root)
        .args([
            "run",
            "--quiet",
            "--package",
            "rustfs-gateway-conformance",
            "--bin",
            "rustfs-gateway-conformance",
            "--",
            "run",
            "--json",
        ])
        .arg(&report);
    if let Some(filter) = filter {
        command.args(["--filter", filter]);
    }
    let status = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("failed to run the conformance suite: {e}"))?;
    // Exit 1 means cases failed, which is the point. Exit 3 means the suite could not reach a
    // target, which is not a measurement of anything.
    if status.code() == Some(3) {
        return Ok(None);
    }
    let Ok(text) = std::fs::read_to_string(&report) else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(None);
    };
    let Some(cases) = value.get("cases").and_then(serde_json::Value::as_array) else {
        return Ok(None);
    };
    let mut verdicts = BTreeMap::new();
    for case in cases {
        let (Some(id), Some(verdict)) = (
            case.get("id").and_then(serde_json::Value::as_str),
            case.get("verdict").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        verdicts.insert(id.to_owned(), verdict.to_owned());
    }
    if verdicts.is_empty() { Ok(None) } else { Ok(Some(verdicts)) }
}
