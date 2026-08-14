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

//! Bounded repository verification commands.
//!
//! Responsible for: selecting a meaningful test scope and enforcing the documented feedback
//! budget. NOT responsible for: defining crate-local tests.
//! Upstream: the `verify` command. Downstream: Cargo and the operation catalog.

mod process;

use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::process::{Command, ExitCode, Output};
use std::time::{Duration, Instant};

use serde::Deserialize;

#[cfg(feature = "full")]
use crate::{catalog, codegen};

#[cfg(not(feature = "full"))]
pub(crate) fn is_crate_request(args: &[String]) -> bool {
    let (args, _) = take_json(args);
    matches!(args.as_slice(), [flag, _] if flag == "--crate")
}

pub(crate) fn verify(args: &[String]) -> ExitCode {
    let (args, json) = take_json(args);
    match args.as_slice() {
        [flag, name] if flag == "--crate" => return verify_crate(name, json),
        _ => {}
    }
    #[cfg(feature = "full")]
    {
        verify_full(&args, json)
    }
    #[cfg(not(feature = "full"))]
    {
        usage()
    }
}

fn verify_crate(name: &str, json: bool) -> ExitCode {
    let package = match resolve_workspace_package(name) {
        Ok(package) => package,
        Err(error) => {
            if json {
                println!("{}", package_resolution_failure_json(name, &error));
                return ExitCode::FAILURE;
            }
            return diagnostic("workspace package could not be resolved", &format!("crate {name}"), &error.to_string());
        }
    };
    let steps = crate_steps(&package);
    let subject = if matches!(package.as_str(), "rustfs-gateway-core" | "rustfs-gateway") {
        format!("crate {package} runtime scope; compile-time contracts remain in cargo test --workspace")
    } else if package == "rustfs-gateway-conformance" {
        format!("crate {package} library scope; integration contracts remain in cargo test --workspace")
    } else {
        format!("crate {package}")
    };
    run_steps(
        &steps,
        Duration::from_secs(30),
        &subject,
        "a crate verification loop must finish within 30 seconds",
        RunOptions {
            json,
            operation_cases: None,
            started: None,
            conformance_case: crate_case(&package),
        },
    )
}

fn crate_steps(package: &str) -> Vec<Vec<String>> {
    let mut test_step = vec!["test".to_owned(), "-p".to_owned(), package.to_owned()];
    if package == "rustfs-gateway-core" {
        test_step.extend([
            "--".to_owned(),
            "--skip".to_owned(),
            "compile_fail::compile_time_contracts_are_not_openable".to_owned(),
        ]);
    } else if package == "rustfs-gateway" {
        test_step.extend([
            "--".to_owned(),
            "--skip".to_owned(),
            "compile_fail::gateway_compile_fail_contracts_are_enforced".to_owned(),
        ]);
    } else if package == "rustfs-gateway-conformance" {
        test_step.push("--lib".to_owned());
    }
    vec![
        test_step,
        vec![
            "clippy".to_owned(),
            "-p".to_owned(),
            package.to_owned(),
            "--all-targets".to_owned(),
            "--".to_owned(),
            "-D".to_owned(),
            "warnings".to_owned(),
        ],
    ]
}

#[cfg(feature = "full")]
fn verify_full(args: &[String], json: bool) -> ExitCode {
    match args {
        [] => run(
            &["test", "--workspace"],
            Duration::from_secs(600),
            "workspace",
            "the full gate must finish within 10 minutes",
            json,
        ),
        [flag] if flag == "--all" => run_all(json),
        [flag, name] if flag == "--op" => verify_operation(name, json),
        _ => usage(),
    }
}

#[cfg(feature = "full")]
fn verify_operation(name: &str, json: bool) -> ExitCode {
    let started = Instant::now();
    let operations = match catalog::operations() {
        Ok(operations) => operations,
        Err(error) => return diagnostic("operation catalog could not be loaded", "model and overlays", &error),
    };
    if !operations.iter().any(|operation| operation.operation == name) {
        match catalog::scaffold_entry(name) {
            Ok(Some(entry)) => return verify_scaffold(&entry, json),
            Ok(None) => {}
            Err(error) => return diagnostic("scaffold manifest could not be loaded", "xtask/scaffolds", &error),
        }
        let suggestion = catalog::nearest(&operations, name).unwrap_or_else(|| "none".to_owned());
        eprintln!("unknown operation `{name}`; nearest: {suggestion}");
        return ExitCode::from(2);
    }
    let entry = match catalog::verify_entry(name) {
        Ok(entry) => entry,
        Err(error) => return diagnostic("generated verification mapping is unavailable", "xtask/verify-map.toml", &error),
    };
    if let Err(error) = run_operation_contract(name) {
        return diagnostic(
            "operation-specific unit contract failed",
            &format!("runtime route and generated mapping for {name}"),
            &format!("a-xt-0002 requires one matching operation unit test; {error}"),
        );
    }
    if codegen::verify_generated().is_err() {
        return diagnostic(
            "operation spec differs from generated output",
            &format!("spec/operations/{name}.toml"),
            "a-xt-0006 spec must regenerate with zero diff",
        );
    }
    let representative = match run_representative_case(name, &entry.cases, json) {
        Ok(representative) => representative,
        Err(code) => return code,
    };
    run_steps(
        &[],
        Duration::from_secs(30),
        &format!("operation {name}"),
        "a-xt-0002 operation unit and conformance checks must finish within 30 seconds",
        RunOptions {
            json,
            operation_cases: Some((representative.as_deref(), entry.cases.len())),
            started: Some(started),
            conformance_case: None,
        },
    )
}

#[cfg(feature = "full")]
fn run_representative_case(name: &str, cases: &[String], json: bool) -> Result<Option<String>, ExitCode> {
    for case in cases {
        let output = Command::new(env!("CARGO")).args(conformance_step("run", case)).output();
        match output {
            Ok(output) if output.status.success() => return Ok(Some(case.clone())),
            Ok(output) if output.status.code() == Some(3) => continue,
            Ok(output) => {
                print_cargo_failure(&output);
                print_json_failure(json, "operation conformance case failed", case);
                return Err(diagnostic(
                    "operation conformance case failed",
                    case,
                    &format!("a-xt-0002 requires {name} conformance evidence; cargo exited with {}", output.status),
                ));
            }
            Err(error) => {
                return Err(diagnostic(
                    "cargo could not be started",
                    case,
                    &format!("a-xt-0002 requires {name} conformance evidence; {error}"),
                ));
            }
        }
    }
    if cases.is_empty() {
        return Ok(None);
    }
    print_json_failure(json, "no mapped conformance case could execute", name);
    Err(diagnostic(
        "no mapped conformance case could execute",
        name,
        "a-xt-0002 requires an observed conformance result, not a skipped case",
    ))
}

#[cfg(feature = "full")]
fn run_operation_contract(name: &str) -> Result<(), String> {
    let output = Command::new(env!("CARGO"))
        .env("RUSTFS_GATEWAY_VERIFY_OPERATION", name)
        .args([
            "test",
            "-p",
            "xtask",
            "--bin",
            "xtask",
            "catalog::tests::selected_operation_has_runtime_route_contract",
            "--",
            "--exact",
        ])
        .output()
        .map_err(|error| format!("cargo could not start: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        print_cargo_failure(&output);
        return Err(format!("cargo exited with {}", output.status));
    }
    if !stdout.contains("running 1 test") || !stdout.contains("1 passed") {
        return Err("the exact filter matched zero tests".to_owned());
    }
    Ok(())
}

#[cfg(feature = "full")]
fn verify_scaffold(entry: &catalog::ScaffoldEntry, json: bool) -> ExitCode {
    let snake = snake_case(&entry.name);
    let output = Command::new(env!("CARGO"))
        .args([
            "test",
            "-p",
            "rustfs-gateway-core",
            "--test",
            &format!("scaffold_{snake}"),
            &entry.test,
            "--",
            "--exact",
        ])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            print_json_failure(json, "scaffold test unexpectedly passed", &entry.name);
            diagnostic(
                "scaffold test unexpectedly passed",
                &format!("crates/core/tests/scaffold_{snake}.rs"),
                "a-xt-0010 new-op must stay red until its todo!() is replaced with tested behaviour",
            )
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stderr.contains("SCAFFOLD handler is not implemented") || stdout.contains("SCAFFOLD handler is not implemented") {
                print_json_failure(json, "scaffold is intentionally unimplemented", &entry.name);
                diagnostic(
                    "scaffold is intentionally unimplemented",
                    &format!("crates/core/src/ops/{snake}.rs"),
                    "a-xt-0010 todo!() and its conformance case must remain red before implementation",
                )
            } else {
                diagnostic(
                    "scaffold verification failed for the wrong reason",
                    &format!("crates/core/tests/scaffold_{snake}.rs"),
                    "a-xt-0010 the observed failure must be the generated todo!() handler",
                )
            }
        }
        Err(error) => diagnostic(
            "cargo could not be started",
            &format!("crates/core/tests/scaffold_{snake}.rs"),
            &format!("a-xt-0010 must-red scaffold; {error}"),
        ),
    }
}

fn package_name(name: &str) -> String {
    if name == "rustfs-gateway" || name == "s3gate" {
        "rustfs-gateway".to_owned()
    } else if name == "xtask" || name.starts_with("rustfs-gateway-") {
        name.to_owned()
    } else if let Some(suffix) = name.strip_prefix("s3gate-") {
        format!("rustfs-gateway-{suffix}")
    } else {
        format!("rustfs-gateway-{name}")
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PackageResolutionError {
    Metadata(String),
    Missing { requested: String, compatible: String },
    Ambiguous { requested: String, matches: Vec<String> },
}

impl fmt::Display for PackageResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(error) => formatter.write_str(error),
            Self::Missing { requested, compatible } => write!(
                formatter,
                "no exact workspace package `{requested}` and no compatible package `{compatible}`"
            ),
            Self::Ambiguous { requested, matches } => {
                write!(
                    formatter,
                    "workspace package `{requested}` matched more than once: {}",
                    matches.join(", ")
                )
            }
        }
    }
}

fn resolve_workspace_package(name: &str) -> Result<String, PackageResolutionError> {
    let packages = workspace_package_names().map_err(PackageResolutionError::Metadata)?;
    resolve_package_name(name, &packages)
}

fn package_resolution_failure_json(name: &str, _error: &PackageResolutionError) -> String {
    json_failure_line("workspace package could not be resolved", &format!("crate {name}"))
}

fn resolve_package_name(name: &str, packages: &[String]) -> Result<String, PackageResolutionError> {
    let exact = matching_packages(name, packages);
    match exact.as_slice() {
        [package] => return Ok(package.clone()),
        [] => {}
        _ => {
            return Err(PackageResolutionError::Ambiguous {
                requested: name.to_owned(),
                matches: exact,
            });
        }
    }

    let compatible = package_name(name);
    let matches = matching_packages(&compatible, packages);
    match matches.as_slice() {
        [package] => Ok(package.clone()),
        [] => Err(PackageResolutionError::Missing {
            requested: name.to_owned(),
            compatible,
        }),
        _ => Err(PackageResolutionError::Ambiguous {
            requested: name.to_owned(),
            matches,
        }),
    }
}

fn matching_packages(name: &str, packages: &[String]) -> Vec<String> {
    packages.iter().filter(|package| package.as_str() == name).cloned().collect()
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: HashSet<String>,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
}

fn workspace_package_names() -> Result<Vec<String>, String> {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .map_err(|error| format!("cargo metadata could not start: {error}"))?;
    if !output.status.success() {
        return Err(format!("cargo metadata exited with {}", output.status));
    }
    let metadata: CargoMetadata =
        serde_json::from_slice(&output.stdout).map_err(|error| format!("cargo metadata returned invalid JSON: {error}"))?;
    Ok(metadata
        .packages
        .into_iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| package.name)
        .collect())
}

#[cfg(feature = "full")]
fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (index, byte) in name.bytes().enumerate() {
        if index != 0 && byte.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(char::from(byte.to_ascii_lowercase()));
    }
    out
}

fn crate_case(package: &str) -> Option<&'static str> {
    match package {
        "rustfs-gateway-sig" => Some("c-sig-0001"),
        "rustfs-gateway-http" => Some("c-chunked-0001"),
        "rustfs-gateway-core" | "rustfs-gateway" => Some("c-object-0001"),
        _ => None,
    }
}

#[cfg(feature = "full")]
fn conformance_step(command: &str, case: &str) -> Vec<String> {
    vec![
        "run".to_owned(),
        "--quiet".to_owned(),
        "-p".to_owned(),
        "rustfs-gateway-conformance".to_owned(),
        "--bin".to_owned(),
        "rustfs-gateway-conformance".to_owned(),
        "--".to_owned(),
        command.to_owned(),
        "--filter".to_owned(),
        case.to_owned(),
    ]
}

fn conformance_test_step(case: &str) -> Vec<String> {
    vec![
        "test".to_owned(),
        "-p".to_owned(),
        "rustfs-gateway-conformance".to_owned(),
        "--lib".to_owned(),
        format!("cli::tests::feedback_case_{}", case.replace('-', "_")),
        "--".to_owned(),
        "--exact".to_owned(),
    ]
}

fn run_steps(steps: &[Vec<String>], budget: Duration, subject: &str, rule: &str, options: RunOptions<'_>) -> ExitCode {
    let RunOptions {
        json,
        operation_cases,
        started,
        conformance_case,
    } = options;
    let started = started.unwrap_or_else(Instant::now);
    let commands: Vec<GateCommand> = steps
        .iter()
        .enumerate()
        .map(|(index, step)| (env!("CARGO").to_owned(), step.clone(), format!("{subject} step {}", index + 1)))
        .collect::<Vec<_>>();
    let mut command_batches = vec![commands];
    if let Some(case) = conformance_case {
        command_batches.push(vec![(
            env!("CARGO").to_owned(),
            conformance_test_step(case),
            format!("{subject} conformance case {case}"),
        )]);
    }
    for commands in command_batches {
        let batch = process::run(&commands, Path::new("."), Some(started + budget));
        if batch.interrupted {
            return diagnostic("verification interrupted", subject, rule);
        }
        if batch.timed_out {
            return diagnostic(
                "verification exceeded its feedback budget",
                subject,
                &format!("{rule}; observed {:.2}s", started.elapsed().as_secs_f64()),
            );
        }
        for (_, output) in batch.results {
            match output {
                Ok(output) if output.status.success() => {}
                Ok(output) => {
                    print_cargo_failure(&output);
                    print_json_failure(json, "verification command failed", subject);
                    return diagnostic(
                        "verification command failed",
                        subject,
                        &format!("{rule}; cargo exited with {}", output.status),
                    );
                }
                Err(error) => return diagnostic("cargo could not be started", subject, &format!("{rule}; {error}")),
            }
        }
    }
    let elapsed = started.elapsed();
    if elapsed > budget {
        return diagnostic(
            "verification exceeded its feedback budget",
            subject,
            &format!("{rule}; observed {:.2}s", elapsed.as_secs_f64()),
        );
    }
    print_success(subject, elapsed, json, operation_cases);
    ExitCode::SUCCESS
}

struct RunOptions<'a> {
    json: bool,
    operation_cases: Option<(Option<&'a str>, usize)>,
    started: Option<Instant>,
    conformance_case: Option<&'a str>,
}

#[cfg(feature = "full")]
fn run_all(json: bool) -> ExitCode {
    let root = codegen::repo_root();
    let scripts = root.join("scripts");
    let setup = (
        env!("CARGO").to_owned(),
        vec!["test".to_owned(), "--workspace".to_owned(), "--no-run".to_owned()],
        "workspace test build".to_owned(),
    );
    let commands = vec![
        (
            env!("CARGO").to_owned(),
            vec!["test".to_owned(), "--workspace".to_owned()],
            "workspace tests".to_owned(),
        ),
        (
            "bash".to_owned(),
            vec![scripts.join("test_guard_scripts.sh").display().to_string()],
            "guard self-test".to_owned(),
        ),
    ];

    let started = Instant::now();
    for (step, output) in run_setup_then_concurrently(&setup, &commands, &root) {
        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                print_cargo_failure(&output);
                print_json_failure(json, "verification command failed", &step);
                return diagnostic(
                    "verification command failed",
                    &step,
                    &format!("the full gate must finish within 10 minutes; command exited with {}", output.status),
                );
            }
            Err(error) => {
                return diagnostic(
                    "verification command could not start",
                    &step,
                    &format!("the full gate must finish within 10 minutes; {error}"),
                );
            }
        }
    }
    let elapsed = started.elapsed();
    if elapsed > Duration::from_secs(600) {
        return diagnostic(
            "verification exceeded its feedback budget",
            "workspace tests and build guards",
            &format!("the full gate must finish within 10 minutes; observed {:.2}s", elapsed.as_secs_f64()),
        );
    }
    print_success("workspace tests and build guards", elapsed, json, None);
    ExitCode::SUCCESS
}

type GateCommand = (String, Vec<String>, String);
type GateResult = (String, std::io::Result<Output>);

#[cfg(feature = "full")]
fn run_setup_then_concurrently(setup: &GateCommand, commands: &[GateCommand], current_dir: &Path) -> Vec<GateResult> {
    let (program, args, step) = setup;
    let output = Command::new(program).args(args).current_dir(current_dir).output();
    let succeeded = output.as_ref().is_ok_and(|output| output.status.success());
    let mut outputs = vec![(step.clone(), output)];
    if succeeded {
        outputs.extend(run_commands_concurrently(commands, current_dir));
    }
    outputs
}

#[cfg(feature = "full")]
fn run_commands_concurrently(commands: &[GateCommand], current_dir: &Path) -> Vec<GateResult> {
    let batch = process::run(commands, current_dir, None);
    if batch.interrupted {
        vec![(
            "verification interrupted".to_owned(),
            Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "verification interrupted")),
        )]
    } else {
        batch.results
    }
}

#[cfg(feature = "full")]
fn run(args: &[&str], budget: Duration, subject: &str, rule: &str, json: bool) -> ExitCode {
    let started = Instant::now();
    let status = Command::new(env!("CARGO")).args(args).output();
    let elapsed = started.elapsed();
    match status {
        Ok(output) if !output.status.success() => {
            print_cargo_failure(&output);
            print_json_failure(json, "verification command failed", subject);
            diagnostic(
                "verification command failed",
                subject,
                &format!("{rule}; cargo exited with {}", output.status),
            )
        }
        Err(error) => diagnostic("cargo could not be started", subject, &format!("{rule}; {error}")),
        Ok(_) if elapsed > budget => diagnostic(
            "verification exceeded its feedback budget",
            subject,
            &format!("{rule}; observed {:.2}s", elapsed.as_secs_f64()),
        ),
        Ok(_) => {
            print_success(subject, elapsed, json, None);
            ExitCode::SUCCESS
        }
    }
}

fn take_json(args: &[String]) -> (Vec<String>, bool) {
    let mut args = args.to_vec();
    let index = args.iter().position(|argument| argument == "--json");
    if let Some(index) = index {
        args.remove(index);
    }
    (args, index.is_some())
}

fn print_success(subject: &str, elapsed: Duration, json: bool, operation_cases: Option<(Option<&str>, usize)>) {
    if json {
        match operation_cases {
            Some((Some(case), count)) => println!(
                "{{\"command\":\"verify\",\"subject\":\"{}\",\"ok\":true,\"elapsed_seconds\":{:.3},\"mapped_cases\":{count},\"representative_case\":\"{}\"}}",
                escape(subject),
                elapsed.as_secs_f64(),
                escape(case)
            ),
            Some((None, count)) => println!(
                "{{\"command\":\"verify\",\"subject\":\"{}\",\"ok\":true,\"elapsed_seconds\":{:.3},\"mapped_cases\":{count},\"representative_case\":null}}",
                escape(subject),
                elapsed.as_secs_f64()
            ),
            None => println!(
                "{{\"command\":\"verify\",\"subject\":\"{}\",\"ok\":true,\"elapsed_seconds\":{:.3}}}",
                escape(subject),
                elapsed.as_secs_f64()
            ),
        }
    } else {
        println!("verify: {subject} passed in {:.2}s", elapsed.as_secs_f64());
        match operation_cases {
            Some((Some(case), count)) => println!("verify: conformance representative {case} (1/{count} mapped cases)"),
            Some((None, _)) => println!("verify: conformance skipped; no case is mapped for this operation"),
            None => {}
        }
    }
}

fn print_json_failure(json: bool, what: &str, where_: &str) {
    if json {
        println!("{}", json_failure_line(what, where_));
    }
}

fn json_failure_line(what: &str, where_: &str) -> String {
    format!(
        "{{\"command\":\"verify\",\"ok\":false,\"what\":\"{}\",\"where\":\"{}\"}}",
        escape(what),
        escape(where_)
    )
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn print_cargo_failure(output: &Output) {
    eprint!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo xtask verify [--all | --crate <name> | --op <operation>]");
    ExitCode::from(2)
}

fn diagnostic(what: &str, where_: &str, rule: &str) -> ExitCode {
    eprintln!("what: {what}");
    eprintln!("where: {where_}");
    eprintln!("rule: {rule}");
    ExitCode::FAILURE
}

#[cfg(all(test, feature = "full"))]
mod tests;
