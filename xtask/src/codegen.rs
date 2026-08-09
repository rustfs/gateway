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

//! The `codegen`, `spec verify` and `why` subcommands.
//!
//! Responsible for: argument handling, the run report, and exit codes.
//! NOT responsible for: any generation logic, which lives in `rustfs-gateway-codegen` so that it can be
//! tested without a process boundary.
//! Upstream: `xtask::main`. Downstream: `rustfs-gateway-codegen`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{fs, io};

use rustfs_gateway_codegen::{CodegenInput, CodegenOutput, Report, semantic};

use crate::catalog;

/// The repository root, derived from this crate's manifest directory so the commands work from
/// any working directory.
pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `cargo xtask codegen [--check] [--diff]`.
pub(crate) fn codegen(args: &[String]) -> ExitCode {
    let (args, json) = take_json(args);
    let args = args.as_slice();
    let root = repo_root();
    let input = CodegenInput::at(&root);
    let output = CodegenOutput::at(&root);

    let valid = args.is_empty()
        || matches!(args, [arg] if arg == "--check" || arg == "--diff")
        || matches!(args, [command, flag] if command == "diff" && flag == "--semantic");
    if !valid {
        eprintln!("usage: cargo xtask codegen [--check] | codegen diff --semantic");
        return ExitCode::from(2);
    }
    if args.first().is_some_and(|arg| arg == "diff") || args.iter().any(|arg| arg == "--diff") {
        return diff(&input, &output, args.iter().any(|arg| arg == "--semantic"), json);
    }
    if args.iter().any(|a| a == "--check") {
        return if json { verify(&["--json".to_owned()]) } else { verify(&[]) };
    }

    match regenerate() {
        Ok(report) => {
            if json {
                println!(
                    "{{\"command\":\"codegen\",\"ok\":true,\"included\":{},\"deferred\":{},\"files\":{},\"stripped_traits\":{}}}",
                    report.included,
                    report.deferred,
                    report.files.len() + 1,
                    report.stripped_traits
                );
            } else {
                print_report(&root, &report);
            }
            if report.goldens.iter().any(|g| !g.differences.is_empty()) {
                // A golden difference is information, not a build failure: the samples are
                // hand-written and may be the side that is wrong. The gate that must stay red is
                // `spec verify`.
                eprintln!("note: the generated IR differs from the frozen samples; see the report above");
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail(err),
    }
}

pub(crate) fn regenerate() -> Result<Report, String> {
    let root = repo_root();
    let report =
        rustfs_gateway_codegen::write(&CodegenInput::at(&root), &CodegenOutput::at(&root)).map_err(|error| error.to_string())?;
    let operations = crate::catalog::operations()?;
    write_verify_map(&operations)?;
    Ok(report)
}

/// `cargo xtask spec verify` — the zero-diff gate.
pub(crate) fn verify(args: &[String]) -> ExitCode {
    let json = matches!(args, [flag] if flag == "--json");
    if !args.is_empty() && !json {
        eprintln!("usage: cargo xtask spec verify");
        return ExitCode::from(2);
    }
    match verify_generated() {
        Ok(count) => {
            if json {
                println!("{{\"command\":\"spec verify\",\"ok\":true,\"files\":{count},\"differ\":0}}");
            } else {
                println!("spec verify: clean ({count} files, 0 differ)");
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

pub(crate) fn verify_generated() -> Result<usize, String> {
    let root = repo_root();
    let input = CodegenInput::at(&root);
    let output = CodegenOutput::at(&root);
    let count = match rustfs_gateway_codegen::verify(&input, &output) {
        Ok(count) => count,
        Err(err) => return Err(err.to_string()),
    };
    let artifacts = match rustfs_gateway_codegen::generate(&input, &output) {
        Ok(artifacts) => artifacts,
        Err(err) => return Err(err.to_string()),
    };
    let expected = catalog::render_verify_map(&artifacts.operations)?;
    let path = catalog::verify_map_path();
    match fs::read_to_string(&path) {
        Ok(actual) if actual == expected => Ok(count + 1),
        Ok(_) => Err(format!(
            "generated verification map was manually modified or stale at {}; a-xt-0020",
            path.display()
        )),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// `cargo xtask codegen --diff` — the semantic summary for a PR body.
fn diff(input: &CodegenInput, output: &CodegenOutput, semantic_only: bool, json: bool) -> ExitCode {
    let old = match semantic::load_ir_dir(&output.generated_dir.join("ir")) {
        Ok(old) => old,
        Err(err) => return fail(err),
    };
    let artifacts = match rustfs_gateway_codegen::generate(input, output) {
        Ok(artifacts) => artifacts,
        Err(err) => return fail(err),
    };
    let new = artifacts
        .operations
        .iter()
        .map(|ir| (ir.operation.clone(), rustfs_gateway_model::ir::emit::to_json(ir)))
        .collect();
    let rendered = semantic::compare_sets(&old, &new).render();
    if json {
        let summary = rendered.lines().take(50).collect::<Vec<_>>().join("\n");
        println!("{{\"command\":\"codegen diff\",\"ok\":true,\"semantic\":\"{}\"}}", escape_json(&summary));
    } else if semantic_only {
        let lines: Vec<&str> = rendered.lines().collect();
        for line in lines.iter().take(50) {
            println!("{line}");
        }
        if lines.len() > 50 {
            eprintln!("semantic diff truncated from {} to 50 lines", lines.len());
        }
    } else {
        print!("{rendered}");
    }
    ExitCode::SUCCESS
}

fn write_verify_map(operations: &[rustfs_gateway_model::ir::OperationIr]) -> Result<(), String> {
    let path = catalog::verify_map_path();
    let body = catalog::render_verify_map(operations)?;
    fs::write(&path, body).map_err(|error| io_error(&path, error))
}

fn io_error(path: &Path, error: io::Error) -> String {
    format!("{}: {error}", path.display())
}

fn take_json(args: &[String]) -> (Vec<String>, bool) {
    let mut args = args.to_vec();
    let index = args.iter().position(|argument| argument == "--json");
    if let Some(index) = index {
        args.remove(index);
    }
    (args, index.is_some())
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn print_report(root: &Path, report: &Report) {
    match &report.pinned_commit {
        Some(sha) => println!("model:      model/s3.json (pinned {})", &sha[..7.min(sha.len())]),
        None => println!("model:      model/s3.json"),
    }
    println!("traits:     {} documentation/endpoint occurrences stripped", report.stripped_traits);
    println!("operations: {} included, {} deferred", report.included, report.deferred);
    println!("quirks:     {} resolved", report.quirks);
    println!("emitted:    {} files", report.files.len());
    for path in &report.files {
        println!("            {}", relative(root, path));
    }
    let matched = report.goldens.iter().filter(|g| g.differences.is_empty()).count();
    println!("IR golden:  {}/{} match spec/ir/samples", matched, report.goldens.len());
    for golden in &report.goldens {
        if golden.differences.is_empty() {
            continue;
        }
        println!("            {} — {} difference(s)", golden.operation, golden.differences.len());
        for difference in &golden.differences {
            println!("              {difference}");
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).display().to_string()
}

fn fail(err: impl std::fmt::Display) -> ExitCode {
    eprintln!("what: code generation or generated-output verification failed");
    eprintln!("where: model + overlays + generated artifacts");
    eprintln!("rule: a-xt-0016/a-xt-0017 generated output must be a zero-diff function of pinned inputs");
    eprintln!("detail: {err}");
    ExitCode::FAILURE
}
