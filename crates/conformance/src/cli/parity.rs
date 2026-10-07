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

//! Process isolation and report comparison for the production transport parity command.
//!
//! Responsible for: running both production drivers in isolated child processes, comparing their
//! serialized reports, and turning a failure shared by both drivers into a regression exit: two
//! identical wrong answers are parity, not success (rustfs/gateway#1378). NOT responsible for:
//! argument parsing or case assertions. Upstream: `super`. Downstream: `crate::parity`.

use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use crate::sut::Transport;

use super::{Options, exit};

pub(super) fn execute_transport_diff(options: &Options, root: PathBuf) -> ExitCode {
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            eprintln!("conformance: cannot locate this executable: {error}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    execute_transport_diff_with_executable(options, root, &executable)
}

fn execute_transport_diff_with_executable(options: &Options, root: PathBuf, executable: &Path) -> ExitCode {
    let corpus = match crate::runner::prepare_corpus(&root) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("conformance: {error}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    let run_options = crate::runner::RunOptions {
        filter: options.filter.clone(),
        transport: Transport::Hyper,
        profile: options.profile,
        include_slow: !options.exclude_slow,
        shard: options.shard,
        validate_only: false,
    };
    let selected = match selected_capabilities(corpus.cases(), &run_options) {
        Ok(selected) => selected,
        Err(error) => {
            eprintln!("conformance: {error}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    let temporary = match parity_directory() {
        Ok(path) => path,
        Err(message) => {
            eprintln!("conformance: {message}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    let hyper_path = temporary.join("hyper.json");
    let conn_path = temporary.join("conn.json");
    let hyper_args = transport_child_args(options, &root, Transport::Hyper, hyper_path.clone());
    let conn_args = transport_child_args(options, &root, Transport::Conn, conn_path.clone());
    let (hyper, conn) = std::thread::scope(|scope| {
        let hyper = scope.spawn(|| run_transport_child(executable, &hyper_args, &hyper_path));
        let conn = scope.spawn(|| run_transport_child(executable, &conn_args, &conn_path));
        (hyper.join(), conn.join())
    });
    let hyper = child_result("hyper", hyper);
    let conn = child_result("self-held", conn);
    let _ = std::fs::remove_file(&hyper_path);
    let _ = std::fs::remove_file(&conn_path);
    let _ = std::fs::remove_dir(&temporary);
    let (hyper, conn) = match (hyper, conn) {
        (Ok(hyper), Ok(conn)) => (hyper, conn),
        (Err(message), _) | (_, Err(message)) => {
            eprintln!("conformance: {message}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    let comparison = match crate::parity::compare_selected_json(&hyper.report, &conn.report, &selected) {
        Ok(comparison) => comparison,
        Err(message) => {
            eprintln!("conformance: {message}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    for (child, transport) in [(&hyper, Transport::Hyper), (&conn, Transport::Conn)] {
        if let Err(message) = validate_child_exit(child.status, transport, &comparison) {
            eprintln!("conformance: {message}: {}", child.stderr.trim());
            return ExitCode::from(exit::ENVIRONMENT);
        }
    }
    println!(
        "transport parity: {} selected case(s); {} identical; {} common failure(s); {} capability difference(s)",
        comparison.case_count,
        comparison.identical_count,
        comparison.common_failures.len(),
        comparison.capability_differences.len(),
    );
    for difference in &comparison.capability_differences {
        println!("  capability difference: {}", difference.id);
        println!("    hyper: {:?}", difference.hyper);
        println!("    conn:  {:?}", difference.conn);
    }
    if comparison.differences.is_empty() && comparison.common_failures.is_empty() {
        return ExitCode::from(exit::SUCCESS);
    }
    if !comparison.common_failures.is_empty() {
        eprintln!(
            "transport parity: {} case(s) failed identically on both production drivers",
            comparison.common_failures.len()
        );
        for failure in &comparison.common_failures {
            eprintln!("  {}", failure.id);
            eprintln!("    hyper: {:?}", failure.hyper);
            eprintln!("    conn:  {:?}", failure.conn);
        }
    }
    if !comparison.differences.is_empty() {
        eprintln!("transport parity: {} case result(s) differ", comparison.differences.len());
        for difference in &comparison.differences {
            eprintln!("  {}", difference.id);
            eprintln!("    hyper: {:?}", difference.hyper);
            eprintln!("    conn:  {:?}", difference.conn);
        }
    }
    ExitCode::from(exit::REGRESSION)
}

pub(super) fn transport_child_args(options: &Options, root: &Path, transport: Transport, report: PathBuf) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--transport".to_owned(),
        transport.as_str().to_owned(),
        "--profile".to_owned(),
        options.profile.as_str().to_owned(),
        "--root".to_owned(),
        root.to_string_lossy().into_owned(),
        "--json".to_owned(),
        report.to_string_lossy().into_owned(),
    ];
    if let Some(filter) = &options.filter {
        args.extend(["--filter".to_owned(), filter.clone()]);
    }
    if options.exclude_slow {
        args.push("--exclude-slow".to_owned());
    }
    if let Some(shard) = options.shard {
        args.extend(["--shard".to_owned(), format!("{}/{}", shard.index, shard.count)]);
    }
    args
}

struct ChildReport {
    status: Option<i32>,
    report: String,
    stderr: String,
}

fn run_transport_child(executable: &Path, args: &[String], report: &Path) -> Result<ChildReport, String> {
    let output = ProcessCommand::new(executable)
        .args(args)
        .output()
        .map_err(|error| format!("cannot start child process: {error}"))?;
    if !matches!(output.status.code(), Some(0 | 1 | 3)) {
        return Err(format!(
            "child exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let report = std::fs::read_to_string(report).map_err(|error| format!("cannot read {}: {error}", report.display()))?;
    Ok(ChildReport {
        status: output.status.code(),
        report,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn child_result(name: &str, result: std::thread::Result<Result<ChildReport, String>>) -> Result<ChildReport, String> {
    match result {
        Ok(result) => result.map_err(|message| format!("{name} transport could not run: {message}")),
        Err(_) => Err(format!("{name} transport child controller panicked")),
    }
}

fn parity_directory() -> Result<PathBuf, String> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_nanos();
    for attempt in 0..16 {
        let path =
            std::env::temp_dir().join(format!("rustfs-gateway-conformance-parity-{}-{nonce}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create {}: {error}", path.display())),
        }
    }
    Err("cannot allocate an isolated transport parity directory".to_owned())
}

// Exit 3 remains an environment failure unless the complete paired comparison proves
// that every selected case passed on Hyper and was explicitly unsupported on conn.
fn validate_child_exit(
    status: Option<i32>,
    transport: Transport,
    comparison: &crate::parity::SelectedComparison,
) -> Result<(), String> {
    if matches!(status, Some(0 | 1))
        || (status == Some(3)
            && matches!(transport, Transport::Conn)
            && comparison.case_count > 0
            && comparison.identical_count == 0
            && comparison.common_failures.is_empty()
            && comparison.differences.is_empty()
            && comparison.capability_differences.len() == comparison.case_count)
    {
        Ok(())
    } else {
        Err(format!("unverified {transport:?} child exit: {status:?}"))
    }
}

fn selected_capabilities(
    cases: &[crate::corpus::Case],
    options: &crate::runner::RunOptions,
) -> Result<std::collections::BTreeMap<String, crate::parity::ExpectedCapability>, String> {
    use crate::diagnostic::Severity;
    use crate::parity::ExpectedCapability::{HyperScriptedH2, Shared};

    let target = crate::conn::Conn::production(PathBuf::new(), crate::production::ProductionDriver::Hyper);
    let mut selected = std::collections::BTreeMap::new();
    for (ordinal, case) in cases.iter().filter(|case| crate::runner::selected(case, options)).enumerate() {
        if options.shard.is_some_and(|shard| !shard.owns(ordinal)) {
            continue;
        }
        let capability = if case.document.is_some()
            && !case
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Deny)
            && !options.validate_only
            && crate::runner::inapplicable(case, options, &target).is_none()
            && case.exchanges().iter().any(|exchange| {
                exchange
                    .request
                    .is_some_and(|request| request.read("requestSpec.h2_frames").is_some())
            }) {
            HyperScriptedH2
        } else {
            Shared
        };
        if selected.insert(case.id.clone(), capability).is_some() {
            return Err(format!("duplicate selected case identifier: {}", case.id));
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod exit_tests;

#[cfg(test)]
mod selection_tests;

#[cfg(all(test, unix))]
mod integration_tests;
