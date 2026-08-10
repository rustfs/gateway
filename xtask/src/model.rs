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

//! Pinned-model command adapter.
//!
//! Responsible for: parsing the `cargo xtask model` surface. NOT responsible for: model
//! verification or semantic-diff logic, which remains in `model/tools`. Upstream: CLI arguments.
//! Downstream: the repository model tools.

use std::process::{Command, ExitCode};

use crate::codegen;

#[derive(Debug, PartialEq)]
enum ModelCommand<'a> {
    Verify,
    Drift(&'a [String]),
}

fn parse(args: &[String]) -> Result<ModelCommand<'_>, &'static str> {
    match args {
        [subcommand] if subcommand == "verify" => Ok(ModelCommand::Verify),
        [subcommand, rest @ ..] if subcommand == "drift" => Ok(ModelCommand::Drift(rest)),
        [subcommand, ..] if subcommand == "verify" => Err("model verify accepts no arguments"),
        [] => Err("missing model subcommand"),
        _ => Err("unknown model subcommand"),
    }
}

pub(crate) fn model(args: &[String]) -> ExitCode {
    let (script, forwarded) = match parse(args) {
        Ok(ModelCommand::Verify) => ("model/tools/verify.py", &[][..]),
        Ok(ModelCommand::Drift(forwarded)) => ("model/tools/drift.py", forwarded),
        Err(error) => {
            eprintln!("{error}\n\nusage: cargo xtask model <verify|drift --against <path>>");
            return ExitCode::from(2);
        }
    };

    let root = codegen::repo_root();
    match Command::new("python3")
        .arg(root.join(script))
        .args(forwarded)
        .current_dir(root)
        .status()
    {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1)),
        Err(error) => {
            eprintln!("model: failed to run python3: {error}");
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ModelCommand, parse};

    #[test]
    fn parses_verify_without_arguments() {
        assert_eq!(parse(&["verify".into()]), Ok(ModelCommand::Verify));
    }

    #[test]
    fn parses_drift_and_forwards_arguments() {
        let args = vec!["drift".into(), "--against".into(), "/tmp/candidate".into()];
        assert_eq!(parse(&args), Ok(ModelCommand::Drift(&args[1..])));
    }

    #[test]
    fn rejects_missing_subcommand() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(parse(&["unknown".into()]).is_err());
    }

    #[test]
    fn rejects_verify_arguments() {
        assert!(parse(&["verify".into(), "extra".into()]).is_err());
    }
}
