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

//! Command-line execution of all persistence rollback assertions.
//!
//! Responsible for: selecting the complete D1-D5 run, rendering observed family/sample counts,
//! and returning a failing process status for usage, assertion, or output errors.
//! Not responsible for: defining codecs, samples, coverage variants, or CI orchestration.
//! Upstream: the aggregate four-way library API.
//! Downstream: developers and the blocking migration gate.

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use rustfs_gateway_goldens::{FourWayRunReport, run_four_way_all};

fn render(report: &FourWayRunReport) -> String {
    let mut output = format!(
        "D1..D5 all clean, {} samples across {} families\n",
        report.sample_count,
        report.families.len()
    );
    for family in &report.families {
        output.push_str(&format!("{}: samples={}\n", family.kind.report_name(), family.sample_count));
    }
    output
}

fn run(
    args: &[String],
    execute: impl FnOnce() -> Result<FourWayRunReport, String>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    if args.len() != 1 || args[0] != "--all" {
        drop(writeln!(stderr, "usage: four-way --all"));
        return ExitCode::FAILURE;
    }
    match execute() {
        Ok(report) => match stdout.write_all(render(&report).as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                drop(writeln!(stderr, "four-way report write failed: {error}"));
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            drop(writeln!(stderr, "four-way validation failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    run(
        &args,
        || run_four_way_all().map_err(|error| error.to_string()),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::process::ExitCode;

    use rustfs_gateway_goldens::run_four_way_all;

    use super::run;

    struct RefusingWriter;

    impl Write for RefusingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("deliberate writer refusal"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn all_executes_thirteen_families_and_reports_observed_samples() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run(
            &["--all".to_owned()],
            || run_four_way_all().map_err(|error| error.to_string()),
            &mut stdout,
            &mut stderr,
        );
        let output = String::from_utf8(stdout).expect("the report is UTF-8");
        assert_eq!(status, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert!(output.starts_with("D1..D5 all clean, 173 samples across 13 families\n"));
        assert_eq!(output.lines().filter(|line| line.contains(": samples=")).count(), 13);
    }

    #[test]
    fn n_missing_all_is_a_usage_failure_without_execution() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run(&[], || panic!("usage failure must not execute assertions"), &mut stdout, &mut stderr);
        assert_eq!(status, ExitCode::FAILURE);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8(stderr).expect("UTF-8 diagnostic"), "usage: four-way --all\n");
    }

    #[test]
    fn n_unknown_argument_is_a_usage_failure_without_execution() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run(
            &["--partial".to_owned()],
            || panic!("usage failure must not execute assertions"),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(status, ExitCode::FAILURE);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8(stderr).expect("UTF-8 diagnostic"), "usage: four-way --all\n");
    }

    #[test]
    fn n_assertion_failure_exits_nonzero_without_partial_success_output() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run(
            &["--all".to_owned()],
            || Err("replication: D3 rollback refusal".to_owned()),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(status, ExitCode::FAILURE);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).expect("UTF-8 diagnostic"),
            "four-way validation failed: replication: D3 rollback refusal\n"
        );
    }

    #[test]
    fn n_standard_output_failure_exits_nonzero() {
        let mut stdout = RefusingWriter;
        let mut stderr = Vec::new();
        let status = run(
            &["--all".to_owned()],
            || run_four_way_all().map_err(|error| error.to_string()),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(status, ExitCode::FAILURE);
        assert_eq!(
            String::from_utf8(stderr).expect("UTF-8 diagnostic"),
            "four-way report write failed: deliberate writer refusal\n"
        );
    }
}
