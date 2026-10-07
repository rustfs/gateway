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

//! The parsed command line: which command, and every option it carries.
//!
//! Responsible for: turning the argument list into [`Options`], and refusing the combinations
//! that cannot mean anything — a transport beside an endpoint, a CA without HTTPS, a rulings
//! ledger on a command that judges nothing, the `rustfs` profile without a candidate to measure.
//! NOT responsible for: running anything (`super`), or the usage text (`super::usage`).
//! Upstream: `crate::runner::Shard`, `crate::sut`. Downstream: `super`.

use crate::runner::Shard;
use crate::sut::{Profile, Transport};
use std::path::PathBuf;

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

impl Command {
    /// The command-line spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Command::Run => "run",
            Command::DiffTransports => "diff-transports",
            Command::Validate => "validate",
            Command::Baseline => "baseline",
            Command::AuditKeys => "audit-keys",
        }
    }
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
    /// Additional PEM-encoded roots for an HTTPS endpoint.
    pub ca_cert: Option<PathBuf>,
    /// Explicit permission to create and automatically remove external owned bucket/object fixtures.
    pub external_fixtures: bool,
    /// Baseline document.
    pub baseline: Option<PathBuf>,
    /// The rulings ledger the run is judged against, when it is judged against one.
    pub rulings: Option<PathBuf>,
    /// Where to write the JSON report.
    pub json: Option<PathBuf>,
    /// Where to write the JUnit report.
    pub junit: Option<PathBuf>,
    /// This worker's share of the selected cases, when the run is split across workers.
    pub shard: Option<Shard>,
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
            ca_cert: None,
            external_fixtures: false,
            baseline: None,
            rulings: None,
            json: None,
            junit: None,
            exclude_slow: false,
            shard: None,
        };
        let mut transport_explicit = false;
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
                "--shard" => options.shard = Some(Shard::parse(&value()?)?),
                "--filter" => options.filter = Some(value()?),
                "--root" => options.root = Some(PathBuf::from(value()?)),
                "--endpoint" => options.endpoint = Some(value()?),
                "--ca-cert" => options.ca_cert = Some(PathBuf::from(value()?)),
                "--allow-external-fixtures" => options.external_fixtures = true,
                "--baseline" => options.baseline = Some(PathBuf::from(value()?)),
                "--rulings" => options.rulings = Some(PathBuf::from(value()?)),
                "--json" => options.json = Some(PathBuf::from(value()?)),
                "--junit" => options.junit = Some(PathBuf::from(value()?)),
                "--transport" => {
                    transport_explicit = true;
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
        if options.endpoint.is_some() {
            if transport_explicit {
                return Err(
                    "`--transport` selects an in-process assembly path and cannot be combined with `--endpoint`".to_owned(),
                );
            }
            options.transport = Transport::Conn;
        }
        if let Some(endpoint) = options.endpoint.as_deref() {
            if options.ca_cert.is_some() && !endpoint.starts_with("https://") {
                return Err("`--ca-cert` requires an `https://` endpoint".to_owned());
            }
        } else if options.ca_cert.is_some() {
            return Err("`--ca-cert` requires `--endpoint`".to_owned());
        }
        if options.external_fixtures && options.endpoint.is_none() {
            return Err("`--allow-external-fixtures` requires `--endpoint`".to_owned());
        }
        if options.rulings.is_some() {
            // A ledger judges verdicts. `validate` evaluates no assertion, `baseline` and
            // `audit-keys` print something else, and `diff-transports` compares two runs rather
            // than judging one; none of them can owe a ruling.
            if options.command != Command::Run {
                return Err(format!(
                    "`--rulings` judges an executed run; `{}` {}",
                    options.command.as_str(),
                    if options.command == Command::Validate {
                        "evaluates no assertion, so it has nothing to judge"
                    } else {
                        "is not `run`"
                    }
                ));
            }
            if options.baseline.is_some() {
                return Err("`--rulings` and `--baseline` are two ledgers for one run; pass one of them".to_owned());
            }
        }
        if options.profile == Profile::Rustfs && options.endpoint.is_none() {
            return Err("`--profile rustfs` names an external RustFS candidate; pass `--endpoint`, because the \
                        bundled reference target does not run the RustFS preset and cannot claim the profile"
                .to_owned());
        }
        Ok(Some(options))
    }
}
