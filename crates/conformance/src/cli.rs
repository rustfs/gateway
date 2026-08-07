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

//! The command surface, as a library function.
//!
//! Responsible for: argument parsing, wiring a target, writing the report, and the exit codes.
//! It lives here rather than in `xtask` because the layering allows `xtask` no dependency on this
//! crate — and because this suite is meant to be run against foreign servers, where `xtask` does
//! not exist. `xtask conformance` therefore shells out to the binary this module backs.
//! NOT responsible for: any assertion (`crate::expect`) or verdict (`crate::runner`).
//! Upstream: `crate::runner`, `crate::report`. Downstream: `src/bin/rustfs-gateway-conformance.rs`.

use crate::corpus::Corpus;
use crate::inprocess::InProcess;
use crate::keys;
use crate::report::{Baseline, Report, Verdict};
use crate::runner::{self, RunOptions};
use crate::sut::{Profile, Sut, Transport};
use std::path::PathBuf;
use std::process::ExitCode;

/// Exit codes. An environment problem is deliberately not exit 1: a run that could not reach the
/// target must never look like a run whose assertions failed, or the first such run poisons the
/// baseline.
pub mod exit {
    /// Everything the run could check held.
    pub const SUCCESS: u8 = 0;
    /// At least one case regressed against the baseline.
    pub const REGRESSION: u8 = 1;
    /// The command line was wrong.
    pub const USAGE: u8 = 2;
    /// The corpus or the target could not be reached.
    pub const ENVIRONMENT: u8 = 3;
}

/// The usage text, also printed on a command-line error.
pub const USAGE: &str = "\
usage: rustfs-gateway-conformance <command> [options]

commands:
  run                       load the corpus and run it against a target
  validate                  load the corpus and check it against the frozen schema and the
                            conventions, without touching a target
  baseline                  print a baseline document for the current results
  audit-keys                run the corpus, then check that every key the frozen schema declares
                            is one this harness actually reads

options:
  --filter <glob>           select cases whose path or id matches (`etag/`, `*mpu*`, `c-sig-0001`)
  --transport <hyper|conn>  assembly path to inject (default hyper)
  --profile <aws|minio|strict>
                            the profile the target claims (default aws)
  --root <dir>              corpus directory holding case.schema.json
  --endpoint <url>          target to run against
  --baseline <file>         tolerate the failures this file records; fail only on a regression
  --json <file>             write the machine-readable report
  --junit <file>            write a JUnit document
  --exclude-slow            leave `slow` cases out, as the pull-request gate does
  -h, --help                print this text

exit codes: 0 ok, 1 regression against the baseline, 2 usage, 3 environment
";

/// Runs the command line.
///
/// `args` excludes the program name.
#[must_use]
pub fn main(args: &[String]) -> ExitCode {
    let options = match Options::parse(args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::from(exit::SUCCESS);
        }
        Err(message) => {
            eprintln!("{message}\n\n{USAGE}");
            return ExitCode::from(exit::USAGE);
        }
    };
    // `--endpoint` is refused rather than ignored. A run that silently measured a service in this
    // process while the operator believed it was measuring a server on a socket is the single
    // worst thing this binary could do.
    if let Some(endpoint) = &options.endpoint {
        eprintln!(
            "conformance: `--endpoint {endpoint}` has no transport behind it. The wired target is \
             assembled in process from the `rustfs-gateway` facade; a socket transport is a \
             separate piece of work and this run will not pretend to be one."
        );
        return ExitCode::from(exit::ENVIRONMENT);
    }
    // `--transport conn` is refused for the same reason as `--endpoint`, and it used to be worse:
    // the flag parsed, the report printed `transport conn`, and every case ran in process. A run
    // that names one assembly path in its header while measuring the other is the single worst
    // thing this binary can do, and it was doing it silently.
    //
    // `crate::socket` now has the pieces — a listener on a kernel-chosen port, a raw client, and a
    // socket-observed `connection_after` — but no `Sut` is wired to them yet, because two of the
    // things a socket run must report cannot be reported honestly until they are built: a paced
    // request body (without it `request_progress` measures the socket buffer rather than the
    // server, and every early-refusal assertion silently inverts) and the close rule that separates
    // `c-object-0013` from `c-sig-0001`, which is issue #20's open question. Refusing is the honest
    // state until then.
    if options.transport == Transport::Conn {
        eprintln!(
            "conformance: `--transport conn` has no target behind it yet. `crate::socket` provides \
             the listener, the raw client and the socket observation, and no `Sut` is wired to \
             them; running this flag against the in-process target would print `transport conn` \
             over a run that never opened a socket. See issue #20."
        );
        return ExitCode::from(exit::ENVIRONMENT);
    }
    let root = match resolve_root(&options) {
        Ok(root) => root,
        Err(message) => {
            eprintln!("conformance: {message}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    execute(&options, &mut InProcess::new(root))
}

/// The corpus directory this run reads, from `--root` or by discovery.
fn resolve_root(options: &Options) -> Result<PathBuf, String> {
    options
        .root
        .clone()
        .map_or_else(Corpus::discover_root, Ok)
        .map_err(|error| error.to_string())
}

/// Runs the command line against a caller-supplied target.
///
/// This is the entry point an embedder uses once the facade can assemble a service; `main` is the
/// same thing with the target that does not exist yet.
#[must_use]
pub fn execute(options: &Options, sut: &mut dyn Sut) -> ExitCode {
    let root = match options.root.clone().map_or_else(Corpus::discover_root, Ok) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("conformance: {error}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    let corpus = match runner::prepare_corpus(&root) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("conformance: {error}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    let baseline = match options.baseline.as_ref().map(read_baseline) {
        None => None,
        Some(Ok(baseline)) => Some(baseline),
        Some(Err(message)) => {
            eprintln!("conformance: {message}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };

    let run_options = RunOptions {
        filter: options.filter.clone(),
        transport: options.transport,
        profile: options.profile,
        include_slow: !options.exclude_slow,
        validate_only: options.command == Command::Validate,
    };
    let report = runner::run(&corpus, sut, &run_options);

    if options.command == Command::Baseline {
        print!("{}", Baseline::render(&report));
        return ExitCode::from(exit::SUCCESS);
    }
    // Taken after the run, never before: the ledger is filled by the harness reading cases, so an
    // audit of a corpus that has not been executed would report that nothing is read.
    if options.command == Command::AuditKeys {
        let (findings, rendered) = keys::report(&corpus);
        print!("{rendered}");
        return ExitCode::from(if findings.is_empty() {
            exit::SUCCESS
        } else {
            exit::REGRESSION
        });
    }

    print!("{}", report.render_text(baseline.as_ref()));
    if let Some(path) = &options.json
        && let Err(error) = std::fs::write(path, report.render_json())
    {
        eprintln!("conformance: cannot write {}: {error}", path.display());
        return ExitCode::from(exit::ENVIRONMENT);
    }
    if let Some(path) = &options.junit
        && let Err(error) = std::fs::write(path, report.render_junit())
    {
        eprintln!("conformance: cannot write {}: {error}", path.display());
        return ExitCode::from(exit::ENVIRONMENT);
    }
    ExitCode::from(status(&report, baseline.as_ref(), options.command))
}

fn status(report: &Report, baseline: Option<&Baseline>, command: Command) -> u8 {
    let regressions = report.regressions(baseline).len();
    if regressions > 0 {
        return exit::REGRESSION;
    }
    // A run in which nothing executed is an environment problem, not a pass. Reporting it as
    // success is how a suite quietly stops asserting anything.
    if command == Command::Run
        && !report.outcomes.is_empty()
        && report.outcomes.iter().all(|outcome| outcome.verdict == Verdict::Skipped)
    {
        eprintln!(
            "conformance: no case executed — every case was skipped. \
             The corpus loaded and validated, but nothing was measured."
        );
        return exit::ENVIRONMENT;
    }
    exit::SUCCESS
}

fn read_baseline(path: &PathBuf) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Baseline::from_json(&text).map_err(|message| format!("{}: {message}", path.display()))
}

/// Which command was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Run the corpus against a target.
    Run,
    /// Check the corpus only.
    Validate,
    /// Print a baseline document.
    Baseline,
    /// Check the harness against the frozen schema's list of declarations.
    AuditKeys,
}

/// A parsed command line.
#[derive(Debug, Clone)]
pub struct Options {
    /// The command.
    pub command: Command,
    /// Case selector.
    pub filter: Option<String>,
    /// Assembly path.
    pub transport: Transport,
    /// Claimed profile.
    pub profile: Profile,
    /// Corpus directory.
    pub root: Option<PathBuf>,
    /// Target endpoint, when one is given.
    pub endpoint: Option<String>,
    /// Baseline document.
    pub baseline: Option<PathBuf>,
    /// Where to write the JSON report.
    pub json: Option<PathBuf>,
    /// Where to write the JUnit report.
    pub junit: Option<PathBuf>,
    /// Whether to leave `slow` cases out.
    pub exclude_slow: bool,
}

impl Options {
    /// Parses the command line.
    ///
    /// Returns `Ok(None)` when help was requested.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending argument.
    pub fn parse(args: &[String]) -> Result<Option<Options>, String> {
        let mut options = Options {
            command: Command::Run,
            filter: None,
            transport: Transport::Hyper,
            profile: Profile::Aws,
            root: None,
            endpoint: None,
            baseline: None,
            json: None,
            junit: None,
            exclude_slow: false,
        };
        let mut iter = args.iter();
        let Some(first) = iter.next() else {
            return Err("no command given".to_owned());
        };
        options.command = match first.as_str() {
            "run" => Command::Run,
            "validate" => Command::Validate,
            "baseline" => Command::Baseline,
            "audit-keys" => Command::AuditKeys,
            "-h" | "--help" => return Ok(None),
            other => return Err(format!("unknown command `{other}`")),
        };
        while let Some(flag) = iter.next() {
            let mut value = || iter.next().cloned().ok_or_else(|| format!("`{flag}` needs a value"));
            match flag.as_str() {
                "-h" | "--help" => return Ok(None),
                "--exclude-slow" => options.exclude_slow = true,
                "--filter" => options.filter = Some(value()?),
                "--root" => options.root = Some(PathBuf::from(value()?)),
                "--endpoint" => options.endpoint = Some(value()?),
                "--baseline" => options.baseline = Some(PathBuf::from(value()?)),
                "--json" => options.json = Some(PathBuf::from(value()?)),
                "--junit" => options.junit = Some(PathBuf::from(value()?)),
                "--transport" => {
                    let text = value()?;
                    options.transport = Transport::parse(&text).ok_or_else(|| format!("unknown transport `{text}`"))?;
                }
                "--profile" => {
                    let text = value()?;
                    options.profile = Profile::parse(&text).ok_or_else(|| format!("unknown profile `{text}`"))?;
                }
                other => return Err(format!("unknown option `{other}`")),
            }
        }
        Ok(Some(options))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn a_run_command_with_a_filter_parses() {
        let options = Options::parse(&args(&["run", "--filter", "etag/"]))
            .expect("parses")
            .expect("not help");
        assert_eq!(options.command, Command::Run);
        assert_eq!(options.filter.as_deref(), Some("etag/"));
    }

    #[test]
    fn transport_and_profile_are_validated_at_the_boundary() {
        let options = Options::parse(&args(&["run", "--transport", "conn", "--profile", "minio"]))
            .expect("parses")
            .expect("not help");
        assert_eq!(options.transport, Transport::Conn);
        assert_eq!(options.profile, Profile::Minio);
    }

    #[test]
    fn an_unknown_command_is_a_usage_error() {
        assert!(Options::parse(&args(&["mutate"])).is_err());
    }

    #[test]
    fn an_unknown_option_is_a_usage_error() {
        assert!(Options::parse(&args(&["run", "--fast"])).is_err());
    }

    #[test]
    fn an_option_without_its_value_is_a_usage_error() {
        assert!(Options::parse(&args(&["run", "--filter"])).is_err());
    }

    #[test]
    fn an_unknown_transport_is_a_usage_error() {
        assert!(Options::parse(&args(&["run", "--transport", "h3"])).is_err());
    }

    /// Negative — `conn` parses, and `main` refuses to run it rather than measuring the in-process
    /// target under its name. Parsing and running are two different questions and the flag being
    /// spelled correctly is not permission to answer the second one with the wrong path.
    #[test]
    fn a_conn_run_is_refused_rather_than_answered_in_process() {
        let options = Options::parse(&args(&["run", "--transport", "conn"]))
            .expect("parses")
            .expect("not help");
        assert_eq!(options.transport, Transport::Conn);
        assert_eq!(main(&args(&["run", "--transport", "conn"])), ExitCode::from(exit::ENVIRONMENT));
    }

    #[test]
    fn help_is_not_an_error() {
        assert!(Options::parse(&args(&["--help"])).expect("parses").is_none());
    }

    #[test]
    fn no_arguments_is_a_usage_error() {
        assert!(Options::parse(&[]).is_err());
    }

    #[test]
    fn a_run_where_nothing_executed_is_an_environment_failure_not_a_pass() {
        let report = Report {
            target: "none".to_owned(),
            transport: "hyper".to_owned(),
            profile: "aws".to_owned(),
            outcomes: vec![crate::report::CaseOutcome {
                id: "c-etag-0001".to_owned(),
                domain: "etag".to_owned(),
                relative: "cases/etag/c-etag-0001.toml".to_owned(),
                title: None,
                verdict: Verdict::Skipped,
                phase: crate::report::Phase::Execute,
                skip_reason: Some("no target".to_owned()),
                diagnostics: Vec::new(),
                quirks: Vec::new(),
                evidence: Vec::new(),
            }],
            filtered_out: 0,
            notes: Vec::new(),
            polarity: (1, 0),
        };
        assert_eq!(status(&report, None, Command::Run), exit::ENVIRONMENT);
        assert_eq!(status(&report, None, Command::Validate), exit::SUCCESS);
    }
}
