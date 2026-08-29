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

#[cfg(feature = "production-transports")]
mod parity;

#[cfg(feature = "production-transports")]
use self::parity::execute_transport_diff;
use crate::conn::Conn;
use crate::corpus::Corpus;
use crate::inprocess::InProcess;
use crate::keys;
#[cfg(feature = "production-transports")]
use crate::production::ProductionDriver;
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
  diff-transports           run both production drivers in parallel and compare every case result
  validate                  load the corpus and check it against the frozen schema and the
                            conventions, without touching a target; every case it accepts is
                            reported `validated`, never `passed`, because nothing was executed
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
    let root = match resolve_root(&options) {
        Ok(root) => root,
        Err(message) => {
            eprintln!("conformance: {message}");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    };
    if options.command == Command::DiffTransports {
        #[cfg(feature = "production-transports")]
        return execute_transport_diff(&options, root);
        #[cfg(not(feature = "production-transports"))]
        {
            eprintln!("conformance: diff-transports requires the production-transports feature");
            return ExitCode::from(exit::ENVIRONMENT);
        }
    }
    // Both choices start a production server and observe it through a socket. The transport name
    // selects only the production connection driver, so `diff-transports` can require their
    // per-case observations to agree.
    execute(&options, target(options.transport, root).as_mut())
}

fn target(transport: Transport, root: PathBuf) -> Box<dyn Sut> {
    #[cfg(feature = "production-transports")]
    match transport {
        Transport::Hyper => Box::new(Conn::production(root, ProductionDriver::Hyper)),
        Transport::Conn => Box::new(Conn::production(root, ProductionDriver::SelfHeld)),
    }
    #[cfg(not(feature = "production-transports"))]
    match transport {
        Transport::Hyper => Box::new(InProcess::new(root)),
        Transport::Conn => Box::new(Conn::new(root)),
    }
}

/// Runs a filtered case selection against the bundled in-process target without rendering it.
///
/// This quiet library boundary uses the same corpus, runner, target, transport, profile, and
/// slow-case policy as `run --filter <filter>`, while the caller retains control of stdout and
/// decides how to render the returned report.
///
/// # Errors
///
/// Returns an environment diagnostic when the corpus cannot be discovered or prepared.
pub fn run_filtered(filter: &str) -> Result<Report, String> {
    let root = Corpus::discover_root().map_err(|error| error.to_string())?;
    let corpus = runner::prepare_corpus(&root).map_err(|error| error.to_string())?;
    let options = RunOptions {
        filter: Some(filter.to_owned()),
        transport: Transport::Hyper,
        profile: Profile::Aws,
        include_slow: true,
        validate_only: false,
    };
    Ok(runner::run(&corpus, &mut InProcess::new(root), &options))
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
    execute_prepared(options, sut, &corpus, baseline.as_ref())
}

fn execute_prepared(options: &Options, sut: &mut dyn Sut, corpus: &Corpus, baseline: Option<&Baseline>) -> ExitCode {
    let run_options = RunOptions {
        filter: options.filter.clone(),
        transport: options.transport,
        profile: options.profile,
        include_slow: !options.exclude_slow,
        validate_only: options.command == Command::Validate,
    };
    let report = runner::run(corpus, sut, &run_options);

    if options.command == Command::Baseline {
        print!("{}", Baseline::render(&report));
        return ExitCode::from(exit::SUCCESS);
    }
    // Taken after the run, never before: the ledger is filled by the harness reading cases, so an
    // audit of a corpus that has not been executed would report that nothing is read.
    if options.command == Command::AuditKeys {
        let (findings, rendered) = keys::report(corpus);
        print!("{rendered}");
        return ExitCode::from(if findings.is_empty() {
            exit::SUCCESS
        } else {
            exit::REGRESSION
        });
    }

    print!("{}", report.render_text(baseline));
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
    ExitCode::from(status(&report, baseline, options.command))
}

fn status(report: &Report, baseline: Option<&Baseline>, command: Command) -> u8 {
    let code = status_code(report, baseline, command);
    if code != exit::ENVIRONMENT {
        return code;
    }
    if report.outcomes.is_empty() {
        eprintln!(
            "conformance: no case was selected — {} case(s) were excluded. \
             Nothing was checked, so this run asserts nothing.",
            report.filtered_out
        );
    } else {
        eprintln!(
            "conformance: no case executed — every case was skipped. \
             The corpus loaded and validated, but nothing was measured."
        );
    }
    code
}

/// Classifies a report without rendering diagnostics or mutating output streams.
///
/// This is the exit classification used by [`execute`]. Embedders use it to retain the command's
/// fail-closed distinction between a regression, an empty selection, and an all-skipped run.
#[must_use]
pub fn status_code(report: &Report, baseline: Option<&Baseline>, command: Command) -> u8 {
    let regressions = report.regressions(baseline).len();
    if regressions > 0 {
        return exit::REGRESSION;
    }
    // A selector that named no case is an environment problem for every command, `validate`
    // included. `--filter '<case-id>'` is how the feedback-loop table selects one case, so a typo
    // in the id checked nothing and exited 0 — the same shape as a command that checked something.
    if report.outcomes.is_empty() {
        return exit::ENVIRONMENT;
    }
    // A run in which nothing executed is an environment problem, not a pass. Reporting it as
    // success is how a suite quietly stops asserting anything.
    if command == Command::Run
        && !report.outcomes.is_empty()
        && report.outcomes.iter().all(|outcome| outcome.verdict == Verdict::Skipped)
    {
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
    /// Run and compare both production connection drivers.
    DiffTransports,
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
            "diff-transports" => Command::DiffTransports,
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
    use std::sync::OnceLock;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    fn corpus() -> &'static (PathBuf, Corpus) {
        static CORPUS: OnceLock<(PathBuf, Corpus)> = OnceLock::new();
        CORPUS.get_or_init(|| {
            let root = Corpus::discover_root().expect("the repository corpus");
            let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
            (root, corpus)
        })
    }

    /// The feedback-loop evidence for one crate, and it must be an execution.
    ///
    /// This used to invoke `validate`, which reaches the corpus checks and stops. `xtask verify
    /// --crate` prints the result as "{crate} conformance case {id}", so the one command AGENTS.md
    /// sends an agent to after a crate change named a case no target had answered. Switching to
    /// `run` turned two of the three red at once: `c-sig-0001` asserts a closed connection, which
    /// only the socket transport can observe, and `c-chunked-0001` executes on neither transport
    /// because streaming-trailer signing is not wired — it is skipped with its reason on both, so
    /// it is no longer this crate's evidence.
    ///
    /// Exit 0 is sufficient evidence on its own: an all-skipped run exits `ENVIRONMENT`, a filter
    /// naming no case exits `ENVIRONMENT`, and a failed assertion exits `REGRESSION`.
    fn assert_feedback_case(case: &str, transport: &str) {
        let (root, corpus) = corpus();
        let selected_transport = Transport::parse(transport).expect("the declared transport exists");
        let options = RunOptions {
            filter: Some(case.to_owned()),
            transport: selected_transport,
            profile: Profile::Aws,
            include_slow: true,
            validate_only: false,
        };
        let report = runner::run(corpus, target(selected_transport, root.clone()).as_mut(), &options);
        assert_eq!(
            status_code(&report, None, Command::Run),
            exit::SUCCESS,
            "{case} is a crate's feedback evidence and did not execute green over {transport}"
        );
    }

    #[test]
    fn feedback_case_c_sig_0001() {
        assert_feedback_case("c-sig-0001", "conn");
    }

    #[test]
    fn feedback_case_c_checksum_0001() {
        assert_feedback_case("c-checksum-0001", "hyper");
    }

    #[test]
    fn feedback_case_c_object_0001() {
        assert_feedback_case("c-object-0001", "hyper");
    }

    /// One set of options, so the two commands are compared on the same case and the same target.
    fn one_case(command: Command) -> Options {
        Options {
            command,
            filter: Some("c-object-0001".to_owned()),
            transport: Transport::Hyper,
            profile: Profile::Aws,
            root: None,
            endpoint: None,
            baseline: None,
            json: None,
            junit: None,
            exclude_slow: false,
        }
    }

    #[cfg(feature = "production-transports")]
    #[test]
    fn transport_diff_children_receive_the_same_selection() {
        let mut options = one_case(Command::DiffTransports);
        options.exclude_slow = true;
        let arguments = parity::transport_child_args(&options, &corpus().0, Transport::Conn, PathBuf::from("report.json"));
        assert_eq!(
            arguments,
            args(&[
                "run",
                "--transport",
                "conn",
                "--profile",
                "aws",
                "--root",
                corpus().0.to_str().expect("UTF-8 repository path"),
                "--json",
                "report.json",
                "--filter",
                "c-object-0001",
                "--exclude-slow",
            ])
        );
    }

    /// Negative — `validate` stays green on a case a target answered wrongly, and `run` does not.
    ///
    /// rustfs/gateway#245 asked for exactly this assertion: a case that is red under `run` must not
    /// produce a success under the documented single-case workflow, "otherwise the fix is itself
    /// unfalsifiable". Both halves run against one target that answers `c-object-0001` with a 500
    /// and the wrong body, so the difference between the two exit codes is the difference between
    /// the two commands and not between two cases.
    ///
    /// This is the reason the feedback-loop table in `AGENTS.md` now names `run`: no wording change
    /// to `validate`'s report can make it detect a wrong assertion, because it evaluates none.
    #[test]
    fn validate_stays_green_on_a_case_run_finds_red_which_is_why_the_table_names_run() {
        let wrong = crate::observation::Observation::response(
            500,
            vec![("content-type".to_owned(), "application/xml".to_owned())],
            b"<Error><Code>InternalError</Code></Error>".to_vec(),
        );
        let mut under_run = crate::sut::Scripted::new().with("c-object-0001", 0, wrong.clone());
        assert_eq!(
            execute_prepared(&one_case(Command::Run), &mut under_run, &corpus().1, None),
            ExitCode::from(exit::REGRESSION),
            "the documented command did not go red on a case whose target answered wrongly"
        );
        let mut under_validate = crate::sut::Scripted::new().with("c-object-0001", 0, wrong);
        assert_eq!(
            execute_prepared(&one_case(Command::Validate), &mut under_validate, &corpus().1, None),
            ExitCode::SUCCESS,
            "validate is a corpus check and this case is internally consistent"
        );
        assert!(
            under_validate.seen.is_empty(),
            "validate handed a request to the target: {:?}",
            under_validate.seen
        );
    }

    /// Negative — a filter that names no case must not exit green.
    ///
    /// `--filter '<case-id>'` is how the feedback-loop table selects one case. A typo in the id
    /// selected nothing, printed `conformance: 0 cases`, and exited 0 — a command that cannot
    /// fail, reported in the same shape as one that checked something.
    #[test]
    fn a_filter_that_selects_no_case_is_an_environment_failure_not_a_pass() {
        for command in [Command::Validate, Command::Run] {
            let mut options = one_case(command);
            options.filter = Some("c-no-such-case-9999".to_owned());
            let mut sut = crate::sut::Scripted::new();
            assert_eq!(execute_prepared(&options, &mut sut, &corpus().1, None), ExitCode::from(exit::ENVIRONMENT));
        }
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

    /// Negative — the two transports are two different targets, and the report says which one ran.
    ///
    /// The defect this pins is the one `--transport conn` shipped with: the flag parsed, the header
    /// printed `transport conn`, and every case ran in process. A description that does not move
    /// when the transport does is a report that cannot be read.
    #[cfg(feature = "production-transports")]
    #[test]
    fn each_transport_names_the_target_it_actually_ran() {
        let hyper = target(Transport::Hyper, PathBuf::from(".")).describe();
        let self_held = target(Transport::Conn, PathBuf::from(".")).describe();
        assert_ne!(hyper, self_held);
        assert!(hyper.contains("production"), "{hyper}");
        assert!(self_held.contains("production"), "{self_held}");
    }

    /// Negative — a transport label must select the production driver it names, not either local
    /// test substitute.
    #[cfg(feature = "production-transports")]
    #[test]
    fn each_transport_selects_its_production_driver() {
        let hyper = target(Transport::Hyper, PathBuf::from(".")).describe();
        let self_held = target(Transport::Conn, PathBuf::from(".")).describe();
        assert!(hyper.contains("production Hyper"), "{hyper}");
        assert!(self_held.contains("production self-held"), "{self_held}");
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
            validate_only: false,
        };
        assert_eq!(status(&report, None, Command::Run), exit::ENVIRONMENT);
        assert_eq!(status_code(&report, None, Command::Run), exit::ENVIRONMENT);
        assert_eq!(status(&report, None, Command::Validate), exit::SUCCESS);
    }

    #[test]
    fn quiet_status_rejects_an_empty_selection() {
        let report = Report {
            target: "none".to_owned(),
            transport: "hyper".to_owned(),
            profile: "aws".to_owned(),
            outcomes: Vec::new(),
            filtered_out: 1,
            notes: Vec::new(),
            polarity: (1, 0),
            validate_only: false,
        };
        assert_eq!(status_code(&report, None, Command::Run), exit::ENVIRONMENT);
    }

    #[test]
    fn quiet_status_rejects_a_failed_assertion() {
        let mut report = Report {
            target: "scripted".to_owned(),
            transport: "hyper".to_owned(),
            profile: "aws".to_owned(),
            outcomes: Vec::new(),
            filtered_out: 0,
            notes: Vec::new(),
            polarity: (1, 0),
            validate_only: false,
        };
        report.outcomes.push(crate::report::CaseOutcome {
            id: "c-object-0001".to_owned(),
            domain: "object".to_owned(),
            relative: "cases/object/c-object-0001.toml".to_owned(),
            title: None,
            verdict: Verdict::Failed,
            phase: crate::report::Phase::Execute,
            skip_reason: None,
            diagnostics: Vec::new(),
            quirks: Vec::new(),
            evidence: Vec::new(),
        });
        assert_eq!(status_code(&report, None, Command::Run), exit::REGRESSION);
    }

    #[test]
    fn quiet_filtered_run_executes_exactly_one_observed_case() {
        let report = run_filtered("c-object-0001").expect("the bundled target must run");
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].id, "c-object-0001");
        assert_eq!(report.outcomes[0].verdict, Verdict::Passed);
    }
}
