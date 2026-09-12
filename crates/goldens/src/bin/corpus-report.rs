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

//! Command-line validation and rendering of the complete persisted XML corpus.
//!
//! Responsible for: validating all named persistence families, rendering their concrete counts,
//! rendering source and acceptance blockers, and offering an explicit strict closure mode.
//! NOT responsible for: defining corpus cases, persistence codecs, CI orchestration, or report
//! validation rules.
//! Upstream: `rustfs-gateway-goldens` corpus APIs. Downstream: developers and release automation
//! invoking the `corpus-report` binary.

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use rustfs_gateway_goldens::{
    CorpusCoverageError, CorpusReport, build_acceptance_census, build_persistence_corpus_report, build_persistence_source_report,
    require_acceptance_closure,
};

fn run(
    build: impl FnOnce() -> Result<CorpusReport, CorpusCoverageError>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    let result = build()
        .map_err(|error| format!("corpus validation failed: {error}"))
        .and_then(|report| {
            let sources = build_persistence_source_report(&report).map_err(|error| format!("source census failed: {error}"))?;
            let acceptance = build_acceptance_census().map_err(|error| format!("acceptance census failed: {error}"))?;
            Ok(format!("{}{}{}", report.render(), sources.render(), acceptance.render()))
        });
    match result {
        Ok(report) => match stdout.write_all(report.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                drop(writeln!(stderr, "corpus report write failed: {error}"));
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            drop(writeln!(stderr, "{error}"));
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    match args.as_slice() {
        [] => run(build_persistence_corpus_report, &mut stdout, &mut stderr),
        [arg] if arg == "--require-closure" => match require_acceptance_closure() {
            Ok(report) => match stdout.write_all(report.render().as_bytes()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    drop(writeln!(stderr, "migration closure report write failed: {error}"));
                    ExitCode::FAILURE
                }
            },
            Err(error) => {
                drop(writeln!(stderr, "migration closure failed: {error}"));
                ExitCode::FAILURE
            }
        },
        _ => {
            drop(writeln!(stderr, "usage: corpus-report [--require-closure]"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use rustfs_gateway_goldens::{ConfigKind, CorpusCoverageError};

    use super::{ExitCode, build_persistence_corpus_report, run};

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
    fn complete_report_prints_thirteen_real_families_counts_and_total_bytes() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run(build_persistence_corpus_report, &mut stdout, &mut stderr);
        let output = String::from_utf8(stdout).expect("the report is UTF-8");
        assert_eq!(status, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert!(output.contains("persisted XML corpus: 13/13 requested families covered"));
        for kind in ConfigKind::ALL {
            assert!(
                output
                    .lines()
                    .any(|line| line.starts_with(&format!("{}: accepted=", kind.report_name()))),
                "missing family row for {}",
                kind.report_name()
            );
        }
        assert!(
            output
                .lines()
                .any(|line| line.starts_with("total: families=13 accepted=") && line.contains(" bytes="))
        );
    }

    #[test]
    fn n_invalid_corpus_exits_nonzero_without_partial_standard_output() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run(
            || Err(CorpusCoverageError::MissingFamily(ConfigKind::Replication)),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(status, ExitCode::FAILURE);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).expect("the diagnostic is UTF-8"),
            "corpus validation failed: replication has no concrete corpus evidence\n"
        );
    }

    #[test]
    fn n_standard_output_failure_exits_nonzero() {
        let mut stdout = RefusingWriter;
        let mut stderr = Vec::new();
        let status = run(build_persistence_corpus_report, &mut stdout, &mut stderr);
        assert_eq!(status, ExitCode::FAILURE);
        assert_eq!(
            String::from_utf8(stderr).expect("the diagnostic is UTF-8"),
            "corpus report write failed: deliberate writer refusal\n"
        );
    }

    #[test]
    fn n_standard_error_failure_cannot_turn_validation_failure_green() {
        let mut stdout = Vec::new();
        let mut stderr = RefusingWriter;
        let status = run(
            || Err(CorpusCoverageError::MissingFamily(ConfigKind::Replication)),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(status, ExitCode::FAILURE);
        assert!(stdout.is_empty());
    }
}
