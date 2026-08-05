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
//! NOT responsible for: any generation logic, which lives in `s3gate-codegen` so that it can be
//! tested without a process boundary.
//! Upstream: `xtask::main`. Downstream: `s3gate-codegen`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use s3gate_codegen::{CodegenInput, CodegenOutput, Report, semantic, why};

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
    let root = repo_root();
    let input = CodegenInput::at(&root);
    let output = CodegenOutput::at(&root);

    if args.iter().any(|a| a == "--diff") {
        return diff(&input, &output);
    }
    if args.iter().any(|a| a == "--check") {
        return verify(&[]);
    }

    match s3gate_codegen::write(&input, &output) {
        Ok(report) => {
            print_report(&root, &report);
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

/// `cargo xtask spec verify` — the zero-diff gate.
pub(crate) fn verify(_args: &[String]) -> ExitCode {
    let root = repo_root();
    match s3gate_codegen::verify(&CodegenInput::at(&root), &CodegenOutput::at(&root)) {
        Ok(count) => {
            println!("spec verify: clean ({count} files, 0 differ)");
            ExitCode::SUCCESS
        }
        Err(err) => fail(err),
    }
}

/// `cargo xtask codegen --diff` — the semantic summary for a PR body.
fn diff(input: &CodegenInput, output: &CodegenOutput) -> ExitCode {
    let old = match semantic::load_ir_dir(&output.generated_dir.join("ir")) {
        Ok(old) => old,
        Err(err) => return fail(err),
    };
    let artifacts = match s3gate_codegen::generate(input, output) {
        Ok(artifacts) => artifacts,
        Err(err) => return fail(err),
    };
    let new = artifacts
        .operations
        .iter()
        .map(|ir| (ir.operation.clone(), s3gate_model::ir::emit::to_json(ir)))
        .collect();
    print!("{}", semantic::compare_sets(&old, &new).render());
    ExitCode::SUCCESS
}

/// `cargo xtask why <quirk-id | operation | error-code | header | query-key>`.
pub(crate) fn why(args: &[String]) -> ExitCode {
    let Some(argument) = args.first() else {
        eprintln!("usage: cargo xtask why <quirk-id | operation | error-code | header | query-key>");
        return ExitCode::FAILURE;
    };
    let root = repo_root();
    let artifacts = match s3gate_codegen::generate(&CodegenInput::at(&root), &CodegenOutput::at(&root)) {
        Ok(artifacts) => artifacts,
        Err(err) => return fail(err),
    };
    match why::why(&artifacts.operations, argument) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(err) => fail(err),
    }
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
    eprintln!("error: {err}");
    ExitCode::FAILURE
}
