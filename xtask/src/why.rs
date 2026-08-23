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

//! Reverse tracing from a protocol or assembly identifier to its recorded reason.
//!
//! Responsible for: resolving quirk, operation, error-code, header, ADR and `asm-*` targets and
//! rendering the stable `RULE / EVIDENCE / CASES / ADR / SPEC / RELATED` contract.
//! NOT responsible for: forward generation, route explanation or running conformance cases.
//! Upstream: overlays, operation IR, conformance cases, ADRs and assembly rules. Downstream:
//! agents reading `cargo xtask why` text or JSON output.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rustfs_gateway::RuleRef;
use rustfs_gateway_model::ir::{Evidence, OperationIr, Quirk};
use rustfs_gateway_model::{ErrorStatus, Overlay};

use crate::codegen::repo_root;

mod distance;
mod error_code;
#[cfg(test)]
mod tests;

use distance::distance;

const WHY_USAGE: &str = "usage: cargo xtask why [error-code] <quirk | operation | error-code | header | ADR | rule> [--json]";

/// The namespace in which a reverse-trace target was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WhyTarget {
    /// An overlay or conformance-case quirk id.
    Quirk(String),
    /// An AWS operation name.
    Op(String),
    /// An S3 error code.
    ErrorCode(String),
    /// An HTTP header name.
    Header(String),
    /// An accepted architecture decision.
    Adr(String),
    /// An assembly-time rule id.
    Rule(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EvidenceLine {
    url: String,
    summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CaseLine {
    id: String,
    title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AdrLine {
    id: String,
    title: String,
}

#[derive(Debug, Clone)]
struct CaseRecord {
    line: CaseLine,
    operation: Option<String>,
    quirks: Vec<String>,
    evidence: Vec<EvidenceLine>,
    path: String,
    source: String,
}

#[derive(Debug, Clone)]
struct AdrRecord {
    line: AdrLine,
    path: String,
}

struct RuleTestRecord {
    rule: String,
    line: CaseLine,
}
#[derive(Debug, Clone)]
struct Answer {
    id: String,
    summary: String,
    evidence: Vec<EvidenceLine>,
    cases: Vec<CaseLine>,
    adrs: Vec<AdrLine>,
    spec: Vec<String>,
    related: Vec<String>,
    complete: bool,
}

struct Index {
    operations: Vec<OperationIr>,
    error_status: Vec<ErrorStatus>,
    cases: Vec<CaseRecord>,
    adrs: Vec<AdrRecord>,
    rule_tests: Vec<RuleTestRecord>,
    root: PathBuf,
}

/// Runs `cargo xtask why <target> [--json]`.
pub(crate) fn run(args: &[String]) -> ExitCode {
    let mut positional = Vec::new();
    let mut json = false;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            positional.push(arg.as_str());
        }
    }
    let (namespace, argument) = match positional.as_slice() {
        [argument] => (None, *argument),
        [namespace, argument] => (Some(*namespace), *argument),
        _ => {
            eprintln!("{WHY_USAGE}");
            return ExitCode::from(2);
        }
    };
    if namespace.is_some_and(|namespace| namespace != "error-code") {
        eprintln!("{WHY_USAGE}");
        return ExitCode::from(2);
    }

    let index = match Index::load(repo_root()) {
        Ok(index) => index,
        Err(error) => {
            eprintln!("why index could not be loaded: {error}");
            return ExitCode::FAILURE;
        }
    };
    let target = match namespace.map_or_else(|| index.resolve(argument), |_| error_code::resolve(&index.error_status, argument)) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let answer = index.answer(target);
    if json {
        println!("{}", render_json(&answer));
    } else {
        print!("{}", render_text(&answer));
    }
    if answer_succeeds(&answer) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn answer_succeeds(answer: &Answer) -> bool {
    answer.complete
}

impl Index {
    fn load(root: PathBuf) -> Result<Self, String> {
        let input = rustfs_gateway_codegen::CodegenInput::at(&root);
        let output = rustfs_gateway_codegen::CodegenOutput::at(&root);
        let operations = rustfs_gateway_codegen::generate(&input, &output)
            .map_err(|error| format!("operation IR: {error}"))?
            .operations;
        let error_status = Overlay::load(&input.overlays)
            .map_err(|error| format!("error status authority: {error}"))?
            .error_status;
        let cases = load_cases(&root)?;
        let adrs = load_adrs(&root)?;
        let rule_tests = load_rule_tests(&root)?;
        Ok(Self {
            operations,
            error_status,
            cases,
            adrs,
            rule_tests,
            root,
        })
    }

    fn resolve(&self, argument: &str) -> Result<WhyTarget, String> {
        if argument.starts_with("q-")
            && (self.find_quirk(argument).is_some() || self.cases.iter().any(|case| contains(&case.quirks, argument)))
        {
            return Ok(WhyTarget::Quirk(argument.to_owned()));
        }
        if let Some(operation) = self
            .operations
            .iter()
            .find(|operation| operation.operation.eq_ignore_ascii_case(argument))
        {
            return Ok(WhyTarget::Op(operation.operation.clone()));
        }
        if let Some(status) = self
            .error_status
            .iter()
            .find(|status| status.name.eq_ignore_ascii_case(argument))
        {
            return Ok(WhyTarget::ErrorCode(status.name.clone()));
        }
        let lower = argument.to_ascii_lowercase();
        if self.operations.iter().any(|operation| contains(&operation.headers(), &lower)) {
            return Ok(WhyTarget::Header(lower));
        }
        let upper = argument.to_ascii_uppercase();
        if let Some(adr) = self.adrs.iter().find(|adr| adr.line.id == upper) {
            return Ok(WhyTarget::Adr(adr.line.id.clone()));
        }
        if RuleRef::ALL.iter().any(|rule| rule.as_str() == argument) {
            return Ok(WhyTarget::Rule(argument.to_owned()));
        }
        let closest = self.nearest(argument);
        Err(format!(
            "target `{argument}` not found; closest candidates: {}",
            if closest.is_empty() {
                "none".to_owned()
            } else {
                closest.join(", ")
            }
        ))
    }

    fn answer(&self, target: WhyTarget) -> Answer {
        match target {
            WhyTarget::Quirk(id) => self.quirk_answer(&id),
            WhyTarget::Op(name) => self.operation_answer(&name),
            WhyTarget::ErrorCode(code) => error_code::answer(&self.error_status, &self.operations, &self.cases, &code),
            WhyTarget::Header(header) => self.header_answer(&header),
            WhyTarget::Adr(id) => self.adr_answer(&id),
            WhyTarget::Rule(id) => self.rule_answer(&id),
        }
    }

    fn quirk_answer(&self, id: &str) -> Answer {
        let quirk = self.find_quirk(id);
        let matching_cases: Vec<&CaseRecord> = self.cases.iter().filter(|case| contains(&case.quirks, id)).collect();
        let mut evidence = quirk.map_or_else(Vec::new, |quirk| evidence_lines(&quirk.evidence));
        if evidence.is_empty() {
            evidence.extend(matching_cases.iter().flat_map(|case| case.evidence.clone()));
        }
        let cases = matching_cases.iter().map(|case| case.line.clone()).collect();
        let mut related: Vec<String> = self
            .operations
            .iter()
            .filter(|operation| contains(&operation.referenced_quirk_ids(), id))
            .map(|operation| operation.operation.clone())
            .collect();
        related.extend(matching_cases.iter().filter_map(|case| case.operation.clone()));
        let mut spec = find_quirk_sources(&self.root, id);
        if spec.is_empty() {
            spec.extend(matching_cases.iter().map(|case| format!("{}:case.quirks", case.path)));
        }
        finish(Answer {
            id: id.to_owned(),
            summary: quirk
                .map(|quirk| quirk.summary.clone())
                .or_else(|| matching_cases.first().map(|case| case.line.title.clone()))
                .unwrap_or_else(|| "quirk referenced by a conformance case".to_owned()),
            evidence,
            cases,
            adrs: vec![adr_line("ADR-0001", "Licensing and provenance boundary")],
            spec,
            related,
            complete: !matching_cases.is_empty(),
        })
    }

    fn operation_answer(&self, name: &str) -> Answer {
        let operation = self.operations.iter().find(|operation| operation.operation == name);
        let Some(operation) = operation else {
            return empty_answer(name);
        };
        let quirks = operation.referenced_quirk_ids();
        let relevant_cases: Vec<&CaseRecord> = self
            .cases
            .iter()
            .filter(|case| case.operation.as_deref() == Some(name) || case.quirks.iter().any(|id| contains(&quirks, id)))
            .collect();
        let evidence = operation
            .quirks
            .iter()
            .filter(|quirk| contains(&quirks, &quirk.id))
            .flat_map(|quirk| evidence_lines(&quirk.evidence))
            .collect();
        finish(Answer {
            id: name.to_owned(),
            summary: format!(
                "{} {} selects {} with precedence {}",
                operation.http.method.as_str(),
                operation.http.path_shape,
                operation.operation,
                operation.http.precedence
            ),
            evidence,
            cases: relevant_cases.into_iter().map(|case| case.line.clone()).collect(),
            adrs: vec![adr_line("ADR-0001", "Licensing and provenance boundary")],
            spec: vec![format!("spec/operations/{name}.toml")],
            related: quirks,
            complete: true,
        })
    }

    fn header_answer(&self, header: &str) -> Answer {
        let names: Vec<String> = self
            .operations
            .iter()
            .filter(|operation| contains(&operation.headers(), header))
            .map(|operation| operation.operation.clone())
            .collect();
        let cases = self
            .cases
            .iter()
            .filter(|case| contains_token(&case.source.to_ascii_lowercase(), header))
            .map(|case| case.line.clone())
            .collect();
        finish(Answer {
            id: header.to_owned(),
            summary: format!("HTTP header bound by {}", names.join(", ")),
            evidence: Vec::new(),
            cases,
            adrs: Vec::new(),
            spec: names
                .iter()
                .map(|name| format!("spec/operations/{name}.toml:wire_name"))
                .collect(),
            related: names,
            complete: true,
        })
    }

    fn adr_answer(&self, id: &str) -> Answer {
        let adr = self.adrs.iter().find(|adr| adr.line.id == id);
        let Some(adr) = adr else {
            return empty_answer(id);
        };
        finish(Answer {
            id: id.to_owned(),
            summary: adr.line.title.clone(),
            evidence: Vec::new(),
            cases: self
                .cases
                .iter()
                .filter(|case| case.source.contains(id))
                .map(|case| case.line.clone())
                .collect(),
            adrs: vec![adr.line.clone()],
            spec: vec![adr.path.clone()],
            related: Vec::new(),
            complete: true,
        })
    }

    fn rule_answer(&self, id: &str) -> Answer {
        let rule = RuleRef::ALL.iter().find(|rule| rule.as_str() == id);
        let summary = rule.map_or("assembly rule", |rule| rule.explanation()).to_owned();
        let cases: Vec<CaseLine> = self
            .rule_tests
            .iter()
            .filter(|record| record.rule == id)
            .map(|record| record.line.clone())
            .collect();
        finish(Answer {
            id: id.to_owned(),
            summary,
            evidence: Vec::new(),
            cases: cases.clone(),
            adrs: Vec::new(),
            spec: vec!["crates/gateway/src/assembly.rs:RuleRef::ALL".to_owned()],
            related: Vec::new(),
            complete: !cases.is_empty(),
        })
    }

    fn find_quirk(&self, id: &str) -> Option<&Quirk> {
        self.operations
            .iter()
            .find_map(|operation| operation.quirks.iter().find(|quirk| quirk.id == id))
    }

    fn nearest(&self, argument: &str) -> Vec<String> {
        let mut universe = BTreeSet::new();
        for operation in &self.operations {
            universe.insert(operation.operation.clone());
            universe.extend(operation.errors.codes.iter().cloned());
            universe.extend(operation.headers());
            universe.extend(operation.quirks.iter().map(|quirk| quirk.id.clone()));
        }
        universe.extend(self.error_status.iter().map(|status| status.name.clone()));
        universe.extend(self.cases.iter().flat_map(|case| case.quirks.iter().cloned()));
        universe.extend(self.adrs.iter().map(|adr| adr.line.id.clone()));
        universe.extend(RuleRef::ALL.iter().map(|rule| rule.as_str().to_owned()));
        let needle = argument.to_ascii_lowercase();
        let mut scored: Vec<(usize, String)> = universe
            .into_iter()
            .map(|candidate| (distance(&needle, &candidate.to_ascii_lowercase()), candidate))
            .collect();
        scored.sort();
        scored.into_iter().take(3).map(|(_, candidate)| candidate).collect()
    }
}

fn load_cases(root: &Path) -> Result<Vec<CaseRecord>, String> {
    let base = root.join("conformance/cases");
    let mut paths = Vec::new();
    collect_files(&base, "toml", &mut paths)?;
    paths.sort();
    paths.into_iter().map(|path| parse_case(root, &path)).collect()
}

fn parse_case(root: &Path, path: &Path) -> Result<CaseRecord, String> {
    let source = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let id = assignment(&source, "id").ok_or_else(|| format!("{}: missing case id", path.display()))?;
    let title = assignment(&source, "title").ok_or_else(|| format!("{}: missing case title", path.display()))?;
    let operation = assignment(&source, "operation");
    let quirks = string_array(&source, "quirks");
    let mut evidence = Vec::new();
    let mut pending_url = None;
    for line in source.lines() {
        if let Some(url) = assignment_line(line, "url") {
            pending_url = Some(url);
        } else if let Some(summary) = assignment_line(line, "summary")
            && let Some(url) = pending_url.take()
        {
            evidence.push(EvidenceLine { url, summary });
        }
    }
    Ok(CaseRecord {
        line: CaseLine { id, title },
        operation,
        quirks,
        evidence,
        path: relative(root, path),
        source,
    })
}
fn load_rule_tests(root: &Path) -> Result<Vec<RuleTestRecord>, String> {
    let assembly_path = root.join("crates/gateway/src/assembly.rs");
    let assembly = fs::read_to_string(&assembly_path).map_err(|error| format!("{}: {error}", assembly_path.display()))?;
    let mut constants = Vec::new();
    let mut pending = None;
    for line in assembly.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub const ")
            && let Some((name, _)) = rest.split_once(':')
        {
            pending = Some(name.to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("id: \"")
            && let Some(id) = rest.strip_suffix("\",")
            && let Some(name) = pending.take()
        {
            constants.push((name, id.to_owned()));
        }
    }
    let mut paths = vec![assembly_path];
    collect_files(&root.join("crates/gateway/tests"), "rs", &mut paths)?;
    paths.sort();
    let mut records = Vec::new();
    for path in paths {
        let source = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let lines: Vec<&str> = source.lines().collect();
        let starts: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                let trimmed = line.trim();
                (trimmed == "#[test]" || trimmed == "#[tokio::test]").then_some(index)
            })
            .collect();
        for (position, start) in starts.iter().copied().enumerate() {
            let end = starts.get(position + 1).copied().unwrap_or(lines.len());
            let chunk = lines[start..end].join("\n");
            let Some(name) = lines[start..end].iter().find_map(|line| test_function_name(line)) else {
                continue;
            };
            let mut matched = Vec::new();
            if chunk.contains("RuleRef::ALL") {
                continue;
            } else {
                for (constant, id) in &constants {
                    if chunk.contains(&format!("RuleRef::{constant}")) {
                        matched.push(id.clone());
                    }
                }
            }
            for rule in matched {
                records.push(RuleTestRecord {
                    rule,
                    line: CaseLine {
                        id: name.clone(),
                        title: relative(root, &path),
                    },
                });
            }
        }
    }
    Ok(records)
}
fn test_function_name(line: &str) -> Option<String> {
    let name = line.split_once("fn ")?.1.split_once('(')?.0.trim();
    (!name.is_empty()).then(|| name.to_owned())
}
fn load_adrs(root: &Path) -> Result<Vec<AdrRecord>, String> {
    let base = root.join("docs/adr");
    let mut paths = Vec::new();
    collect_files(&base, "md", &mut paths)?;
    paths.sort();
    let mut records = Vec::new();
    for path in paths {
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let Some(number) = stem.split('-').next() else {
            continue;
        };
        if number == "0000" || number.len() != 4 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let source = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let id = format!("ADR-{number}");
        let prefix = format!("# {id}: ");
        let title = source
            .lines()
            .next()
            .and_then(|line| line.strip_prefix(&prefix))
            .ok_or_else(|| format!("{}: malformed ADR title", path.display()))?
            .to_owned();
        records.push(AdrRecord {
            line: AdrLine { id, title },
            path: relative(root, &path),
        });
    }
    Ok(records)
}

fn collect_files(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, extension, out)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
            out.push(path);
        }
    }
    Ok(())
}

fn find_quirk_sources(root: &Path, id: &str) -> Vec<String> {
    let base = root.join("model/overlays/quirks");
    let mut paths = Vec::new();
    if collect_files(&base, "toml", &mut paths).is_err() {
        return Vec::new();
    }
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            fs::read_to_string(&path)
                .ok()
                .filter(|source| source.lines().any(|line| assignment_line(line, "id").as_deref() == Some(id)))
                .map(|_| format!("{}:quirk[id={id}]", relative(root, &path)))
        })
        .collect()
}

fn evidence_lines(evidence: &[Evidence]) -> Vec<EvidenceLine> {
    evidence
        .iter()
        .map(|entry| EvidenceLine {
            url: evidence_url(entry),
            summary: entry.summary.clone(),
        })
        .collect()
}

fn evidence_url(evidence: &Evidence) -> String {
    let reference = evidence.reference.trim();
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return reference.to_owned();
    }
    match evidence.kind.as_str() {
        "s3s-issue" => format!("https://github.com/s3s-project/s3s/issues/{reference}"),
        "s3s-pr" => format!("https://github.com/s3s-project/s3s/pull/{reference}"),
        _ => reference.to_owned(),
    }
}

fn finish(mut answer: Answer) -> Answer {
    answer.evidence.sort();
    answer.evidence.dedup();
    answer.cases.sort();
    answer.cases.dedup();
    answer.adrs.sort();
    answer.adrs.dedup();
    answer.spec.sort();
    answer.spec.dedup();
    answer.related.sort();
    answer.related.dedup();
    answer
}

fn empty_answer(id: &str) -> Answer {
    Answer {
        id: id.to_owned(),
        summary: "target not found".to_owned(),
        evidence: Vec::new(),
        cases: Vec::new(),
        adrs: Vec::new(),
        spec: Vec::new(),
        related: Vec::new(),
        complete: false,
    }
}

fn render_text(answer: &Answer) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "RULE      {} — {}", answer.id, answer.summary);
    render_lines(&mut out, "EVIDENCE", &answer.evidence, |line| format!("{} — {}", line.url, line.summary));
    if answer.cases.is_empty() {
        let suffix = if answer.complete { "NONE" } else { "NONE — this is a bug" };
        let _ = writeln!(out, "CASES     {suffix}");
    } else {
        render_lines(&mut out, "CASES", &answer.cases, |line| format!("{} — {}", line.id, line.title));
    }
    render_lines(&mut out, "ADR", &answer.adrs, |line| format!("{} — {}", line.id, line.title));
    render_lines(&mut out, "SPEC", &answer.spec, Clone::clone);
    render_lines(&mut out, "RELATED", &answer.related, Clone::clone);
    out
}

fn render_lines<T>(out: &mut String, label: &str, values: &[T], render: impl Fn(&T) -> String) {
    if values.is_empty() {
        let _ = writeln!(out, "{label:<10}NONE");
        return;
    }
    for (index, value) in values.iter().enumerate() {
        let prefix = if index == 0 { label } else { "" };
        let _ = writeln!(out, "{prefix:<10}{}", render(value));
    }
}

fn render_json(answer: &Answer) -> String {
    let evidence = answer
        .evidence
        .iter()
        .map(|line| {
            format!(
                "{{\"url\":\"{}\",\"summary\":\"{}\"}}",
                escape_json(&line.url),
                escape_json(&line.summary)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let cases = answer
        .cases
        .iter()
        .map(|line| format!("{{\"id\":\"{}\",\"title\":\"{}\"}}", escape_json(&line.id), escape_json(&line.title)))
        .collect::<Vec<_>>()
        .join(",");
    let adrs = answer
        .adrs
        .iter()
        .map(|line| format!("{{\"id\":\"{}\",\"title\":\"{}\"}}", escape_json(&line.id), escape_json(&line.title)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"rule\":{{\"id\":\"{}\",\"summary\":\"{}\"}},\"evidence\":[{}],\"cases\":[{}],\"adr\":[{}],\"spec\":{},\"related\":{},\"complete\":{}}}",
        escape_json(&answer.id),
        escape_json(&answer.summary),
        evidence,
        cases,
        adrs,
        json_strings(&answer.spec),
        json_strings(&answer.related),
        answer.complete
    )
}

fn json_strings(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", escape_json(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn assignment(source: &str, key: &str) -> Option<String> {
    source.lines().find_map(|line| assignment_line(line, key))
}

fn assignment_line(line: &str, key: &str) -> Option<String> {
    let value = line.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?.trim();
    value.strip_prefix('"')?.strip_suffix('"').map(str::to_owned)
}

fn string_array(source: &str, key: &str) -> Vec<String> {
    let mut value = String::new();
    let mut found = false;
    for line in source.lines() {
        if found {
            value.push(' ');
            value.push_str(line.trim());
        } else if let Some(rest) = line
            .trim()
            .strip_prefix(key)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
        {
            found = true;
            value.push_str(rest.trim());
        }
        if found && value.contains(']') {
            break;
        }
    }
    if !found {
        return Vec::new();
    }
    let value = value.split_once(']').map_or(value.as_str(), |(array, _)| array);
    value
        .split('"')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, value)| value.to_owned())
        .collect()
}

fn contains(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

fn contains_token(source: &str, needle: &str) -> bool {
    source.match_indices(needle).any(|(start, _)| {
        let before = source[..start].bytes().next_back();
        let after = source[start + needle.len()..].bytes().next();
        before.is_none_or(|byte| !is_token_byte(byte)) && after.is_none_or(|byte| !is_token_byte(byte))
    })
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).display().to_string()
}

fn adr_line(id: &str, title: &str) -> AdrLine {
    AdrLine {
        id: id.to_owned(),
        title: title.to_owned(),
    }
}
