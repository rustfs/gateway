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
//! Responsible for: selecting a meaningful test scope, building its artifacts ahead of the
//! deadline, and enforcing the documented feedback budget over the work that is left.
//! NOT responsible for: defining crate-local tests.
//! Upstream: the `verify` command. Downstream: Cargo and the operation catalog.

mod budget;
#[cfg(feature = "full")]
mod full_gate;
mod launcher;
mod prebuild;
mod process;
mod selection;

use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::process::{Command, ExitCode, Output};
use std::time::{Duration, Instant};

use serde::Deserialize;

use budget::{BudgetFailure, KilledStep, builds_inside_budget};
use launcher::launcher_started;
use prebuild::{prebuild_commands, run_prebuild};
use process::CancelledStep;
use selection::crate_steps;

use crate::nested_cargo::without_package_environment;
#[cfg(feature = "operation")]
use crate::{catalog, codegen};

const GATEWAY_RSS_TEST: &str = "cors_runtime::a_million_unique_keys_keep_rss_within_the_entry_budget";
const GATEWAY_ADDRESS_TABLE_TEST: &str = "ext::governor::allocation_tests::c_gov_0013_a_million_addresses_do_not_grow_memory";

#[cfg(not(feature = "full"))]
pub(crate) fn is_available_request(args: &[String]) -> bool {
    let (args, _) = take_json(args);
    matches!(args.as_slice(), [flag, _] if flag == "--crate")
        || cfg!(feature = "operation") && matches!(args.as_slice(), [flag, _] if flag == "--op")
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
        #[cfg(feature = "operation")]
        if let [flag, name] = args.as_slice()
            && flag == "--op"
        {
            return verify_operation(name, json);
        }
        usage()
    }
}

fn verify_crate(name: &str, json: bool) -> ExitCode {
    let started = match launcher_started() {
        Ok(started) => started,
        Err(error) => return diagnostic("xtask launcher timestamp is invalid", "crate verification", &error),
    };
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
    let step_batches = crate_step_batches(&package);
    let conformance_case = standalone_crate_case(&package);
    let subject = if package == "rustfs-gateway" {
        format!(
            "crate {package} fast runtime scope; compile-time, representative conformance, and million-key RSS contracts remain in cargo test --workspace"
        )
    } else if package == "rustfs-gateway-core" {
        format!("crate {package} runtime scope; compile-time contracts remain in cargo test --workspace")
    } else if package == "rustfs-gateway-conformance" {
        format!("crate {package} library and allocation scope; ordinary integration contracts remain in cargo test --workspace")
    } else if package == "rustfs-gateway-server" {
        format!("crate {package} runtime scope; thousand-connection load contracts remain in cargo test --workspace")
    } else {
        format!("crate {package}")
    };
    let build = match run_prebuild(&prebuild_commands(&step_batches, conformance_case), &subject) {
        Ok(build) => build,
        Err(exit) => return exit,
    };
    eprintln!(
        "verify: {subject} build compiled {} crate(s) in {:.2}s outside the budget",
        build.compiled_crates,
        build.elapsed.as_secs_f64()
    );
    run_step_batches(
        &step_batches,
        Duration::from_secs(30),
        &subject,
        "a crate verification loop must finish within 30 seconds",
        RunOptions {
            json,
            operation_cases: None,
            started: started.and_then(|started| started.checked_add(build.elapsed)),
            conformance_case,
        },
    )
}

fn crate_step_batches(package: &str) -> Vec<Vec<Vec<String>>> {
    let mut steps = crate_steps(package);
    if package == "rustfs-gateway" {
        let mut test = steps.remove(0);
        test.extend([
            "--skip".to_owned(),
            GATEWAY_RSS_TEST.to_owned(),
            "--skip".to_owned(),
            GATEWAY_ADDRESS_TABLE_TEST.to_owned(),
        ]);
        let clippy = steps.remove(0);
        return vec![vec![test, clippy]];
    }
    if package == "rustfs-gateway-server" {
        let mut test = steps.remove(0);
        test.extend([
            "--".to_owned(),
            "--skip".to_owned(),
            "c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget".to_owned(),
            "--skip".to_owned(),
            "c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic".to_owned(),
            "--skip".to_owned(),
            "c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99".to_owned(),
        ]);
        let clippy = steps.remove(0);
        return vec![vec![test, clippy]];
    }
    vec![steps]
}

fn standalone_crate_case(package: &str) -> Option<&'static str> {
    (package != "rustfs-gateway").then(|| crate_case(package)).flatten()
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

#[cfg(feature = "operation")]
fn verify_operation(name: &str, json: bool) -> ExitCode {
    let started = Instant::now();
    let operations = match catalog::operations() {
        Ok(operations) => operations,
        Err(error) => return diagnostic("operation catalog could not be loaded", "model and overlays", &error),
    };
    let manual_operations = match catalog::manual_operations() {
        Ok(operations) => operations,
        Err(error) => return diagnostic("manual operation catalog could not be loaded", "model and overlays", &error),
    };
    let manual = manual_operations.iter().any(|operation| operation == name);
    if !manual && !operations.iter().any(|operation| operation.operation == name) {
        match catalog::scaffold_entry(name) {
            Ok(Some(entry)) => return verify_scaffold(&entry, json),
            Ok(None) => {}
            Err(error) => return diagnostic("scaffold manifest could not be loaded", "xtask/scaffolds", &error),
        }
        let suggestion = catalog::nearest(&operations, name).unwrap_or_else(|| "none".to_owned());
        eprintln!("unknown operation `{name}`; nearest: {suggestion}");
        return ExitCode::from(2);
    }
    let entry = if manual {
        // A manual operation has no generated verify-map row; the corpus is its case list, so the
        // mapping check holds and a representative case runs (rustfs/gateway#1167 found it empty).
        match catalog::corpus_cases(name) {
            Ok(cases) => catalog::VerifyEntry {
                name: name.to_owned(),
                cases,
            },
            Err(error) => return diagnostic("conformance corpus could not be read", "conformance/cases", &error),
        }
    } else {
        match catalog::verify_entry(name) {
            Ok(entry) => entry,
            Err(error) => return diagnostic("generated verification mapping is unavailable", "xtask/verify-map.toml", &error),
        }
    };
    if let Err(error) = run_operation_contract(name, &entry.cases) {
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

#[cfg(feature = "operation")]
fn run_representative_case(name: &str, cases: &[String], json: bool) -> Result<Option<String>, ExitCode> {
    for case in cases {
        let report = match rustfs_gateway_conformance::cli::run_filtered(case) {
            Ok(report) => report,
            Err(_) => continue,
        };
        match rustfs_gateway_conformance::cli::status_code(&report, None, rustfs_gateway_conformance::cli::Command::Run) {
            rustfs_gateway_conformance::cli::exit::SUCCESS => return Ok(Some(case.clone())),
            rustfs_gateway_conformance::cli::exit::ENVIRONMENT => continue,
            code => {
                eprint!("{}", report.render_text(None));
                print_json_failure(json, "operation conformance case failed", case);
                return Err(diagnostic(
                    "operation conformance case failed",
                    case,
                    &format!("a-xt-0002 requires {name} conformance evidence; conformance exited with {code}"),
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

#[cfg(feature = "operation")]
fn run_operation_contract(name: &str, mapped_cases: &[String]) -> Result<(), String> {
    catalog::verify_operation_contract(name, mapped_cases)
}

#[cfg(feature = "operation")]
fn verify_scaffold(entry: &catalog::ScaffoldEntry, json: bool) -> ExitCode {
    let snake = snake_case(&entry.name);
    let output = without_package_environment(&mut Command::new(env!("CARGO")))
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
    let output = without_package_environment(&mut Command::new(env!("CARGO")))
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

#[cfg(feature = "operation")]
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

/// The one conformance case each crate's 30-second loop reports by name.
///
/// Every case here must *execute*: the loop runs it rather than validating it, and a case that
/// cannot reach a target reports the crate as verified over a case no target answered.
/// `rustfs-gateway-http` named `c-chunked-0001` while that case was skipped on both transports —
/// streaming-trailer signing is not wired — so it names the checksum case, which runs.
fn crate_case(package: &str) -> Option<&'static str> {
    match package {
        "rustfs-gateway-sig" => Some("c-sig-0001"),
        "rustfs-gateway-http" => Some("c-checksum-0001"),
        "rustfs-gateway-core" | "rustfs-gateway" => Some("c-object-0001"),
        _ => None,
    }
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

#[cfg(feature = "operation")]
fn run_steps(steps: &[Vec<String>], budget: Duration, subject: &str, rule: &str, options: RunOptions<'_>) -> ExitCode {
    run_step_batches(&[steps.to_vec()], budget, subject, rule, options)
}

fn run_step_batches(
    step_batches: &[Vec<Vec<String>>],
    budget: Duration,
    subject: &str,
    rule: &str,
    options: RunOptions<'_>,
) -> ExitCode {
    let RunOptions {
        json,
        operation_cases,
        started,
        conformance_case,
    } = options;
    let started = started.unwrap_or_else(Instant::now);
    let mut command_batches = Vec::new();
    if let Some(case) = conformance_case {
        command_batches.push(vec![(
            env!("CARGO").to_owned(),
            conformance_test_step(case),
            format!("{subject} conformance case {case}"),
        )]);
    }
    let mut step_number = 0;
    for steps in step_batches {
        let commands = steps
            .iter()
            .map(|step| {
                step_number += 1;
                (env!("CARGO").to_owned(), step.clone(), format!("{subject} step {step_number}"))
            })
            .collect();
        command_batches.push(commands);
    }
    for commands in command_batches {
        let batch = process::run(&commands, Path::new("."), Some(started + budget));
        if batch.interrupted {
            return diagnostic("verification interrupted", subject, rule);
        }
        if batch.timed_out {
            let killed = killed_steps(&commands, &batch.cancelled);
            return budget_diagnostic(BudgetFailure::KilledAtDeadline { budget, killed: &killed }, subject, rule);
        }
        for note in builds_inside_budget(&commands, &batch.results) {
            eprintln!("verify: {note}");
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
        return budget_diagnostic(BudgetFailure::Overran { elapsed }, subject, rule);
    }
    print_success(subject, elapsed, json, operation_cases);
    ExitCode::SUCCESS
}

/// Pairs each killed command with the label and rerun command a reader needs to measure it.
fn killed_steps(commands: &[GateCommand], cancelled: &[CancelledStep]) -> Vec<KilledStep> {
    cancelled
        .iter()
        .filter_map(|cancelled| {
            commands.get(cancelled.index).map(|(program, args, step)| KilledStep {
                step: step.clone(),
                command: rerun_command(program, args),
                compiled_crates: cancelled.compiled_crates,
            })
        })
        .collect()
}

/// Renders a supervised command as the line a reader can paste to run it with no deadline over it.
fn rerun_command(program: &str, args: &[String]) -> String {
    let program = if program == env!("CARGO") { "cargo" } else { program };
    std::iter::once(program.to_owned())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn budget_diagnostic(failure: BudgetFailure<'_>, subject: &str, rule: &str) -> ExitCode {
    for note in failure.notes() {
        eprintln!("verify: {note}");
    }
    diagnostic(failure.what(), subject, &failure.rule(rule))
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
    let stages = full_gate_stages(&root);
    full_gate::verify(
        &stages,
        &root,
        "workspace tests and build guards",
        "each full-gate stage must finish within its own budget",
        json,
    )
}

/// The full gate's stages, in the order they run, each with the deadline it runs under.
///
/// Each stage is held to the budget CI gives it, not to a share of one deadline (rustfs/gateway#1247):
/// CI runs the workspace tests and the guard self-test as separate jobs, and summed in sequence on
/// one host they cost 500-900s, so a single 600s deadline failed by construction. The build opens
/// the workspace budget and the tests inherit it, because CI's `cargo test` compiles inside its
/// own 480s; the guard self-test gets a fresh 480s, the budget the suite already declares for itself.
#[cfg(feature = "full")]
fn full_gate_stages(root: &Path) -> [full_gate::Stage; 3] {
    use full_gate::Deadline;
    let scripts = root.join("scripts");
    [
        full_gate::Stage {
            name: "workspace test build".to_owned(),
            commands: vec![(
                env!("CARGO").to_owned(),
                vec!["test".to_owned(), "--workspace".to_owned(), "--no-run".to_owned()],
                "workspace test build".to_owned(),
            )],
            deadline: Deadline::Own(Duration::from_secs(480)),
        },
        // The guard self-test used to share this stage with the workspace tests and run beside
        // them. Both are the heaviest work the gate does, and the guard suite watches its own clock:
        // beside `cargo test --workspace` it stopped itself at case 784 of 1402 on a ten-core host
        // with every case still printing ok (rustfs/gateway#563), and the server timing suites it
        // was competing with reported the contention as protocol observations (rustfs/gateway#611
        // and the class it names). One stage each, in sequence: no check is skipped, and each suite
        // is judged on a host it is not itself loading.
        //
        // The tests run with libtest's default parallelism, the configuration CI's workspace shards
        // run and judge them under. The `--test-threads=1` this stage used to pass had no recorded
        // reason; measured in sequence it cost 438s and rustfs/gateway#708 records the allocation
        // probes failing under one thread.
        full_gate::Stage {
            name: "workspace tests".to_owned(),
            commands: vec![(
                env!("CARGO").to_owned(),
                vec!["test".to_owned(), "--workspace".to_owned()],
                "workspace tests".to_owned(),
            )],
            deadline: Deadline::Previous,
        },
        full_gate::Stage {
            name: "guard self-test".to_owned(),
            commands: vec![(
                "bash".to_owned(),
                vec![scripts.join("test_guard_scripts.sh").display().to_string()],
                "guard self-test".to_owned(),
            )],
            deadline: Deadline::Own(Duration::from_secs(480)),
        },
    ]
}

#[cfg(all(test, feature = "full"))]
mod full_gate_shape_tests {
    use std::time::Duration;

    use super::full_gate::Deadline;
    use super::full_gate_stages;

    /// The guard self-test runs in a stage of its own, after the workspace tests, never beside
    /// them: run together they load the host they are both judged on (rustfs/gateway#563).
    #[test]
    fn n_the_guard_self_test_never_shares_a_stage_with_the_workspace_tests() {
        let stages = full_gate_stages(std::path::Path::new("/repo"));
        let names: Vec<&str> = stages.iter().map(|stage| stage.name.as_str()).collect();
        assert_eq!(names, ["workspace test build", "workspace tests", "guard self-test"]);
        for stage in &stages {
            assert_eq!(stage.commands.len(), 1, "{}: one command per stage", stage.name);
        }
        let guard = &stages[2].commands[0];
        assert!(
            guard
                .1
                .iter()
                .any(|argument| argument.ends_with("scripts/test_guard_scripts.sh")),
            "the last stage is the guard suite: {guard:?}"
        );
        assert_eq!(stages[1].commands[0].1, ["test", "--workspace"], "default parallelism, as CI runs it");
    }

    /// The build and the tests share CI's 480s workspace budget; the guard suite has its own 480s
    /// and is neither charged for nor handed the time the workspace stages took (rustfs/gateway#1247).
    #[test]
    fn n_each_suite_runs_under_its_own_480_second_budget() {
        let deadlines = full_gate_stages(std::path::Path::new("/repo")).map(|stage| stage.deadline);
        let budget = Deadline::Own(Duration::from_secs(480));
        assert_eq!(deadlines, [budget, Deadline::Previous, budget]);
    }
}

type GateCommand = (String, Vec<String>, String);
type GateResult = (String, std::io::Result<Output>);

#[cfg(feature = "full")]
fn run(args: &[&str], budget: Duration, subject: &str, rule: &str, json: bool) -> ExitCode {
    let stages = [full_gate::Stage {
        name: subject.to_owned(),
        commands: vec![(
            env!("CARGO").to_owned(),
            args.iter().map(|argument| (*argument).to_owned()).collect(),
            subject.to_owned(),
        )],
        deadline: full_gate::Deadline::Own(budget),
    }];
    full_gate::verify(&stages, Path::new("."), subject, rule, json)
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
