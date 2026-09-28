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

//! Whether a surviving mutation's changed generated code ever ran during the corpus run.
//!
//! Responsible for: the one question `SURVIVED` cannot answer by itself (rustfs/gateway#671) —
//! is a green suite under a mutation a corpus gap, or did the mutated code never execute? It
//! reruns the corpus against the still-mutated tree in a coverage-instrumented build, and reads the
//! line counts LLVM records for the changed lines.
//! NOT responsible for: applying or restoring the mutation, or the outcome of the uninstrumented
//! run; `super::run` owns both, and calls this only for a row it has already judged `SURVIVED`.
//! Upstream: `super::run`. Downstream: the matrix row.
//!
//! # Three answers, never two
//!
//! - **reached**: some changed line has a counted execution. The survivor is a corpus gap.
//! - **unreached**: the changed range has instrumented lines and every one of them counted zero.
//!   The mutated code never ran, so no case could have caught it: a dead source, not a gap.
//! - **unknown**: nothing in the changed range is instrumented — a constant, a type, a deleted line
//!   — or the coverage run itself could not be completed. A missing mapping is never read as zero
//!   executions; that would turn every changed constant into a false "dead source".
//!
//! The changed lines are the lines of the mutated file outside a longest common subsequence with
//! the baseline, and "unreached" needs **every** one of them instrumented and at zero: a changed
//! constant beside a changed branch leaves the answer unknown, because a constant is read wherever
//! it is used, not on its own line. The instrumented run must also reproduce the uninstrumented
//! run's verdicts exactly, or a slower instrumented build timing out would read as code not run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What the coverage run says about a surviving mutation's changed code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reach {
    /// At least one changed line executed.
    Reached,
    /// Every instrumented changed line counted zero executions.
    Unreached(String),
    /// Nothing could be concluded, with the reason.
    Unknown(String),
}

/// Line counts per canonical source path, as LLVM's `DA:` records report them.
pub(crate) type LineCounts = BTreeMap<PathBuf, BTreeMap<u32, u64>>;

/// Changed lines of one file: the 1-based lines of `new` outside its longest common subsequence
/// with `old`. Empty when no line of `new` differs (identical text, or lines only removed).
pub(crate) type Changed = BTreeSet<u32>;

/// The largest differing window, in `old` lines times `new` lines, that is diffed line by line. A
/// mutation changes a handful of lines; a window beyond this is not one, and answers `None`.
const MAX_WINDOW: usize = 4_000_000;

/// The lines of `new` a mutation changed, or `None` when the differing window is too large to diff.
pub(crate) fn changed_lines(old: &str, new: &str) -> Option<Changed> {
    let old: Vec<&str> = old.lines().collect();
    let new: Vec<&str> = new.lines().collect();
    let prefix = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
    let suffix = old[prefix..]
        .iter()
        .rev()
        .zip(new[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (a, b) = (&old[prefix..old.len() - suffix], &new[prefix..new.len() - suffix]);
    if a.len().saturating_mul(b.len()) > MAX_WINDOW {
        return None;
    }
    // Longest common subsequence over the differing window; a line of `b` it does not keep changed.
    let mut table = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i][j] = if a[i] == b[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    let mut changed = Changed::new();
    let (mut i, mut j) = (0, 0);
    while j < b.len() {
        if i < a.len() && a[i] == b[j] {
            i += 1;
            j += 1;
        } else if i < a.len() && table[i + 1][j] >= table[i][j + 1] {
            i += 1;
        } else {
            changed.insert(u32::try_from(prefix + j + 1).ok()?);
            j += 1;
        }
    }
    Some(changed)
}

/// Reads an LCOV tracefile into line counts per source path.
///
/// Only `SF:`, `DA:` and `end_of_record` carry what is needed; every other record is skipped. A
/// malformed `DA:` or one outside a file section is an error rather than a skipped line, because a
/// line silently dropped here would later read as "not instrumented".
pub(crate) fn parse_lcov(text: &str) -> Result<LineCounts, String> {
    let mut counts = LineCounts::new();
    let mut current: Option<PathBuf> = None;
    for (index, line) in text.lines().enumerate() {
        if let Some(path) = line.strip_prefix("SF:") {
            current = Some(PathBuf::from(path));
        } else if let Some(record) = line.strip_prefix("DA:") {
            let file = current
                .as_ref()
                .ok_or_else(|| format!("lcov line {}: DA outside a source file section", index + 1))?;
            let mut fields = record.split(',');
            let parsed = match (fields.next(), fields.next()) {
                (Some(number), Some(hits)) => number.parse::<u32>().ok().zip(hits.parse::<u64>().ok()),
                _ => None,
            };
            let (number, hits) = parsed.ok_or_else(|| format!("lcov line {}: malformed DA record `{line}`", index + 1))?;
            let slot = counts.entry(file.clone()).or_default().entry(number).or_default();
            *slot = slot.saturating_add(hits);
        } else if line == "end_of_record" {
            current = None;
        }
    }
    Ok(counts)
}

/// Judges the changed lines against the recorded line counts.
///
/// `changed` maps each canonical generated source path to its changed lines, or `None` when the
/// file could not be diffed line by line.
pub(crate) fn judge(changed: &BTreeMap<PathBuf, Option<Changed>>, counts: &LineCounts) -> Reach {
    if changed.is_empty() {
        return Reach::Unknown("the mutation changed no generated Rust source".to_owned());
    }
    let mut unreached: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for (path, lines) in changed {
        let shown = path.display();
        let Some(lines) = lines else {
            unknown.push(format!("{shown}: the change is too large to diff line by line"));
            continue;
        };
        if lines.is_empty() {
            unknown.push(format!("{shown}: the change only removed lines"));
            continue;
        }
        let Some(recorded) = counts.get(path) else {
            unknown.push(format!("{shown}: not in the coverage map"));
            continue;
        };
        let hits: Vec<Option<u64>> = lines.iter().map(|line| recorded.get(line).copied()).collect();
        if hits.iter().any(|hits| hits.is_some_and(|hits| hits > 0)) {
            return Reach::Reached;
        }
        let listed: Vec<String> = lines.iter().map(u32::to_string).collect();
        if hits.iter().any(Option::is_none) {
            unknown.push(format!("{shown}: changed line(s) {} are not all instrumented", listed.join(",")));
        } else {
            unreached.push(format!("{shown}: changed line(s) {} instrumented, none executed", listed.join(",")));
        }
    }
    if unknown.is_empty() {
        Reach::Unreached(unreached.join("; "))
    } else {
        Reach::Unknown(unknown.join("; "))
    }
}

/// Reads a corpus report into case id to verdict, or `None` when there is no usable report.
pub(crate) fn read_verdicts(report: &Path) -> Option<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(report).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    let mut verdicts = BTreeMap::new();
    for case in value.get("cases")?.as_array()? {
        let (Some(id), Some(verdict)) = (
            case.get("id").and_then(serde_json::Value::as_str),
            case.get("verdict").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        verdicts.insert(id.to_owned(), verdict.to_owned());
    }
    (!verdicts.is_empty()).then_some(verdicts)
}

/// The instrumented run measures the same thing only if every case ended the same way.
fn same_verdicts(expected: &BTreeMap<String, String>, observed: &BTreeMap<String, String>) -> Result<(), String> {
    if expected == observed {
        return Ok(());
    }
    let differing: Vec<&str> = expected
        .keys()
        .chain(observed.keys())
        .filter(|id| expected.get(*id) != observed.get(*id))
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Err(format!(
        "the instrumented run's verdicts differ from the measured run for {}",
        differing.join(", ")
    ))
}

/// Where the coverage build lives, apart from the target directory whose freshness the mutation
/// loop reads — an instrumented rebuild there would answer the next rule's freshness question.
fn coverage_target(root: &Path) -> PathBuf {
    root.join("target").join("mutate-coverage")
}

/// The LLVM tool of the active toolchain, which is the only one whose profile format matches.
fn llvm_tool(name: &str) -> Result<PathBuf, String> {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("rustc --print sysroot: {e}"))?;
    let version = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|e| format!("rustc -vV: {e}"))?;
    let host = String::from_utf8_lossy(&version.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .ok_or_else(|| "rustc -vV names no host".to_owned())?;
    let path = PathBuf::from(String::from_utf8_lossy(&sysroot.stdout).trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "`{}` is missing; install it with `rustup component add llvm-tools`",
            path.display()
        ))
    }
}

/// Reruns the corpus against the mutated tree on disk with coverage, and judges `changed`.
///
/// Every failure to collect is `Unknown` with its reason: a missing capability is a skip that
/// says why, never a verdict.
pub(crate) fn measure(
    root: &Path,
    filter: Option<&str>,
    expected: &BTreeMap<String, String>,
    changed: &BTreeMap<PathBuf, Option<Changed>>,
) -> Reach {
    match collect(root, filter, expected) {
        Ok(counts) => judge(changed, &counts),
        Err(why) => Reach::Unknown(format!("coverage was not collected: {why}")),
    }
}

fn collect(root: &Path, filter: Option<&str>, expected: &BTreeMap<String, String>) -> Result<LineCounts, String> {
    let profdata = llvm_tool("llvm-profdata")?;
    let llvm_cov = llvm_tool("llvm-cov")?;
    let target = coverage_target(root);
    let profiles = target.join("profiles");
    // A profile left by the previous rule would be merged into this rule's counts.
    let _ = std::fs::remove_dir_all(&profiles);
    std::fs::create_dir_all(&profiles).map_err(|e| format!("creating {}: {e}", profiles.display()))?;

    let built = crate::nested_cargo::without_package_environment(&mut Command::new(env!("CARGO")))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target)
        .env("RUSTFLAGS", "-C instrument-coverage")
        // Build scripts and proc-macros are instrumented too; their profiles go here, not into
        // the working tree, and are never merged.
        .env("LLVM_PROFILE_FILE", target.join("build-profiles").join("build-%p-%m.profraw"))
        .args(["build", "--package", super::CONFORMANCE, "--bin", super::CONFORMANCE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("instrumented build: {e}"))?;
    if !built.success() {
        return Err("the instrumented corpus binary does not build".to_owned());
    }
    let binary = target.join("debug").join(super::CONFORMANCE);
    let report = profiles.join("report.json");
    let mut run = Command::new(&binary);
    run.current_dir(root)
        .env("LLVM_PROFILE_FILE", profiles.join("corpus-%p-%m.profraw"))
        .args(["run", "--json"])
        .arg(&report);
    if let Some(filter) = filter {
        run.args(["--filter", filter]);
    }
    let status = run
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("instrumented corpus run: {e}"))?;
    // Exit 1 is failing cases, which a survivor's run does not have but a report still proves the
    // run happened; anything without a report measured nothing.
    if !matches!(status.code(), Some(0 | 1)) {
        return Err(format!("the instrumented corpus run exited with {status}"));
    }
    let observed = read_verdicts(&report).ok_or_else(|| "the instrumented corpus run produced no report".to_owned())?;
    same_verdicts(expected, &observed)?;
    let raw: Vec<PathBuf> = std::fs::read_dir(&profiles)
        .map_err(|e| format!("reading {}: {e}", profiles.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "profraw"))
        .collect();
    if raw.is_empty() {
        return Err("the instrumented run wrote no profile".to_owned());
    }
    let merged = profiles.join("corpus.profdata");
    let status = Command::new(&profdata)
        .args(["merge", "-sparse", "-o"])
        .arg(&merged)
        .args(&raw)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("llvm-profdata: {e}"))?;
    if !status.success() {
        return Err("llvm-profdata could not merge the profiles".to_owned());
    }
    let exported = Command::new(&llvm_cov)
        .args(["export", "--format=lcov", "--instr-profile"])
        .arg(&merged)
        .arg(&binary)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("llvm-cov: {e}"))?;
    if !exported.status.success() {
        return Err("llvm-cov could not export the profile".to_owned());
    }
    let counts = parse_lcov(&String::from_utf8_lossy(&exported.stdout))?;
    Ok(canonical(root, counts))
}

/// Canonicalises coverage paths so a file compiled through the ADR-0005 symlink
/// (`crates/types/generated`) matches the artefact path it was generated to (`generated/dto`).
fn canonical(root: &Path, counts: LineCounts) -> LineCounts {
    let mut out = LineCounts::new();
    for (path, lines) in counts {
        let absolute = if path.is_absolute() { path } else { root.join(path) };
        let key = std::fs::canonicalize(&absolute).unwrap_or(absolute);
        let slot = out.entry(key).or_default();
        for (line, hits) in lines {
            let count = slot.entry(line).or_default();
            *count = count.saturating_add(hits);
        }
    }
    out
}

/// The changed lines of every generated Rust file that differs between the two artefact sets,
/// keyed by canonical path so they meet [`canonical`] coverage paths.
pub(crate) fn changed_sources(
    baseline: &[(PathBuf, String)],
    mutated: &[(PathBuf, String)],
) -> BTreeMap<PathBuf, Option<Changed>> {
    let before: BTreeMap<&PathBuf, &String> = baseline.iter().map(|(path, body)| (path, body)).collect();
    mutated
        .iter()
        .filter(|(path, _)| path.extension().is_some_and(|extension| extension == "rs"))
        .filter_map(|(path, body)| {
            let old = before.get(path)?;
            (*old != body).then(|| {
                let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                (key, changed_lines(old, body))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(file: &str, lines: &[(u32, u64)]) -> LineCounts {
        let mut out = LineCounts::new();
        out.insert(PathBuf::from(file), lines.iter().copied().collect());
        out
    }

    fn lines(numbers: &[u32]) -> Option<Changed> {
        Some(numbers.iter().copied().collect())
    }

    fn changed(file: &str, changed: Option<Changed>) -> BTreeMap<PathBuf, Option<Changed>> {
        BTreeMap::from([(PathBuf::from(file), changed)])
    }

    fn verdicts(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(id, verdict)| ((*id).to_owned(), (*verdict).to_owned()))
            .collect()
    }

    #[test]
    fn a_changed_line_is_found() {
        assert_eq!(changed_lines("a\nb\nc\n", "a\nX\nc\n"), lines(&[2]));
    }

    #[test]
    fn n_two_separate_changes_are_two_lines_not_the_span_between_them() {
        assert_eq!(changed_lines("a\nb\nc\nd\n", "X\nb\nc\nY\n"), lines(&[1, 4]));
    }

    #[test]
    fn n_an_insertion_is_the_inserted_lines_only() {
        assert_eq!(changed_lines("a\nc\n", "a\nb1\nb2\nc\n"), lines(&[2, 3]));
    }

    #[test]
    fn n_a_change_that_only_removes_lines_changes_no_line() {
        assert_eq!(changed_lines("a\nb\nc\n", "a\nc\n"), lines(&[]));
    }

    #[test]
    fn n_identical_text_changes_no_line() {
        assert_eq!(changed_lines("a\nb\n", "a\nb\n"), lines(&[]));
    }

    #[test]
    fn n_a_window_too_large_to_diff_is_not_guessed() {
        let old: String = (0..3000).map(|n| format!("o{n}\n")).collect();
        let new: String = (0..3000).map(|n| format!("n{n}\n")).collect();
        assert_eq!(changed_lines(&old, &new), None);
    }

    #[test]
    fn lcov_line_counts_are_read_per_file() {
        let text = "TN:\nSF:/g/a.rs\nFN:1,f\nDA:3,0\nDA:4,7\nend_of_record\nSF:/g/b.rs\nDA:1,2\nend_of_record\n";
        let parsed = parse_lcov(text).expect("parses");
        assert_eq!(parsed[Path::new("/g/a.rs")], BTreeMap::from([(3, 0), (4, 7)]));
        assert_eq!(parsed[Path::new("/g/b.rs")], BTreeMap::from([(1, 2)]));
    }

    #[test]
    fn n_a_repeated_file_section_adds_its_counts() {
        let text = "SF:/g/a.rs\nDA:3,1\nend_of_record\nSF:/g/a.rs\nDA:3,2\nend_of_record\n";
        assert_eq!(parse_lcov(text).expect("parses")[Path::new("/g/a.rs")][&3], 3);
    }

    #[test]
    fn n_a_malformed_line_record_is_an_error_not_a_dropped_line() {
        assert!(parse_lcov("SF:/g/a.rs\nDA:three,1\nend_of_record\n").is_err());
        assert!(parse_lcov("SF:/g/a.rs\nDA:3\nend_of_record\n").is_err());
    }

    #[test]
    fn n_a_line_record_outside_a_file_is_an_error() {
        assert!(parse_lcov("DA:3,1\n").is_err());
    }

    #[test]
    fn one_executed_changed_line_is_reached() {
        let reach = judge(&changed("/g/a.rs", lines(&[3, 4])), &counts("/g/a.rs", &[(3, 0), (4, 1)]));
        assert_eq!(reach, Reach::Reached);
    }

    #[test]
    fn instrumented_changed_lines_that_all_counted_zero_are_unreached() {
        let reach = judge(&changed("/g/a.rs", lines(&[3, 4])), &counts("/g/a.rs", &[(2, 9), (3, 0), (4, 0), (5, 9)]));
        assert!(matches!(reach, Reach::Unreached(_)), "{reach:?}");
    }

    #[test]
    fn n_executions_on_unchanged_lines_do_not_count() {
        let reach = judge(&changed("/g/a.rs", lines(&[3])), &counts("/g/a.rs", &[(2, 5), (3, 0), (4, 5)]));
        assert!(matches!(reach, Reach::Unreached(_)), "{reach:?}");
    }

    #[test]
    fn n_an_uninstrumented_changed_line_is_unknown_not_unreached() {
        // A changed constant: the file is mapped, the constant's line is not.
        let reach = judge(&changed("/g/a.rs", lines(&[3])), &counts("/g/a.rs", &[(2, 0), (4, 0)]));
        assert!(matches!(reach, Reach::Unknown(_)), "{reach:?}");
    }

    #[test]
    fn n_changed_constants_around_an_unexecuted_line_are_unknown() {
        // Lines 1 and 3 are constants read elsewhere; line 2 sits between them and never ran.
        let reach = judge(&changed("/g/a.rs", lines(&[1, 3])), &counts("/g/a.rs", &[(2, 0)]));
        assert!(matches!(reach, Reach::Unknown(_)), "{reach:?}");
    }

    #[test]
    fn n_one_uninstrumented_line_withholds_unreached_from_a_zero_line() {
        let reach = judge(&changed("/g/a.rs", lines(&[3, 4])), &counts("/g/a.rs", &[(3, 0)]));
        assert!(matches!(reach, Reach::Unknown(_)), "{reach:?}");
    }

    #[test]
    fn n_a_file_absent_from_the_coverage_map_is_unknown_not_unreached() {
        let reach = judge(&changed("/g/a.rs", lines(&[3])), &counts("/g/other.rs", &[(3, 0)]));
        assert!(matches!(reach, Reach::Unknown(_)), "{reach:?}");
    }

    #[test]
    fn n_a_removal_only_change_is_unknown() {
        let reach = judge(&changed("/g/a.rs", lines(&[])), &counts("/g/a.rs", &[(3, 0)]));
        assert!(matches!(reach, Reach::Unknown(_)), "{reach:?}");
    }

    #[test]
    fn n_an_undiffable_change_is_unknown() {
        let reach = judge(&changed("/g/a.rs", None), &counts("/g/a.rs", &[(3, 0)]));
        assert!(matches!(reach, Reach::Unknown(_)), "{reach:?}");
    }

    #[test]
    fn n_nothing_changed_is_unknown() {
        assert!(matches!(judge(&BTreeMap::new(), &LineCounts::new()), Reach::Unknown(_)));
    }

    #[test]
    fn n_one_reached_file_outweighs_an_unknown_one() {
        let mut spans = changed("/g/a.rs", lines(&[3]));
        spans.insert(PathBuf::from("/g/b.rs"), lines(&[1]));
        let mut recorded = counts("/g/a.rs", &[]);
        recorded.insert(PathBuf::from("/g/b.rs"), BTreeMap::from([(1, 4)]));
        assert_eq!(judge(&spans, &recorded), Reach::Reached);
    }

    #[test]
    fn n_one_unknown_file_withholds_an_unreached_verdict() {
        let mut spans = changed("/g/a.rs", lines(&[3]));
        spans.insert(PathBuf::from("/g/b.rs"), lines(&[1]));
        let recorded = counts("/g/a.rs", &[(3, 0)]);
        assert!(matches!(judge(&spans, &recorded), Reach::Unknown(_)));
    }

    #[test]
    fn only_rust_sources_that_differ_are_compared() {
        let baseline = vec![
            (PathBuf::from("/nonexistent/a.rs"), "x\ny\n".to_owned()),
            (PathBuf::from("/nonexistent/b.rs"), "same\n".to_owned()),
            (PathBuf::from("/nonexistent/c.toml"), "k = 1\n".to_owned()),
        ];
        let mutated = vec![
            (PathBuf::from("/nonexistent/a.rs"), "x\nz\n".to_owned()),
            (PathBuf::from("/nonexistent/b.rs"), "same\n".to_owned()),
            (PathBuf::from("/nonexistent/c.toml"), "k = 2\n".to_owned()),
        ];
        let spans = changed_sources(&baseline, &mutated);
        assert_eq!(spans, BTreeMap::from([(PathBuf::from("/nonexistent/a.rs"), lines(&[2]))]));
    }

    #[test]
    fn a_file_compiled_through_a_symlink_meets_its_artefact_path() {
        let dir = std::env::temp_dir().join(format!("gateway-reach-{}", std::process::id()));
        let real = dir.join("generated");
        std::fs::create_dir_all(&real).expect("temp dir");
        std::fs::write(real.join("a.rs"), "x\nz\n").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, dir.join("linked")).expect("symlink");
        let spans = changed_sources(&[(real.join("a.rs"), "x\ny\n".to_owned())], &[(real.join("a.rs"), "x\nz\n".to_owned())]);
        let mut recorded = LineCounts::new();
        recorded.insert(dir.join("linked").join("a.rs"), BTreeMap::from([(2, 3)]));
        recorded.insert(PathBuf::from("crates/x/../../generated/a.rs"), BTreeMap::from([(2, 0)]));
        let recorded = canonical(&dir, recorded);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(judge(&spans, &recorded), Reach::Reached);
    }

    #[test]
    fn identical_verdicts_are_the_same_measurement() {
        let run = verdicts(&[("c-a", "passed"), ("c-b", "failed")]);
        assert!(same_verdicts(&run, &run.clone()).is_ok());
    }

    #[test]
    fn n_a_case_that_ended_differently_under_coverage_refuses_the_measurement() {
        let measured = verdicts(&[("c-a", "passed"), ("c-b", "passed")]);
        let instrumented = verdicts(&[("c-a", "passed"), ("c-b", "failed")]);
        let refusal = same_verdicts(&measured, &instrumented).expect_err("a timed-out case is not the same run");
        assert!(refusal.contains("c-b"), "{refusal}");
    }

    #[test]
    fn n_a_case_missing_under_coverage_refuses_the_measurement() {
        let measured = verdicts(&[("c-a", "passed"), ("c-b", "passed")]);
        let instrumented = verdicts(&[("c-a", "passed")]);
        assert!(same_verdicts(&measured, &instrumented).is_err());
    }
}
