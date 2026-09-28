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

//! aws-sdk-rust scenario driver: argument handling, client construction and the result line.
//!
//! Responsible for: turning the single command-line argument into either the linked SDK version or
//! one scenario run, building the S3 client every scenario shares (static credentials, path-style
//! addressing, one attempt), creating the bucket first, and printing exactly one result object on
//! stdout. NOT responsible for: judging wire facts; the system under test records those and
//! `ci/compat/report.py` evaluates them. The scenarios themselves live in `scenarios.rs` and the
//! plain HTTP client that redeems presigned URLs in `plain_http.rs`.
//!
//! Upstream: `ci/compat/run_matrix.sh` via `run.sh`. Downstream: `ci/compat/report.py`.
//!
//! `driver --client-version` prints `aws_sdk_s3::meta::PKG_VERSION`, the version of the aws-sdk-s3
//! crate this binary was compiled against, which is what the runner compares with the pin.

mod plain_http;
mod scenarios;

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_s3::Client;

/// How a scenario ended when it did not pass.
#[derive(Debug)]
pub enum Outcome {
    Fail(String),
    Unsupported(String),
}

pub type Step<T = ()> = Result<T, Outcome>;

pub fn fail<T>(detail: impl Into<String>) -> Step<T> {
    Err(Outcome::Fail(detail.into()))
}

/// Names the server's answer when there was one, and the client's error otherwise.
impl<E, R> From<SdkError<E, R>> for Outcome
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    fn from(err: SdkError<E, R>) -> Self {
        match (err.code(), err.message()) {
            (Some(code), message) => Outcome::Fail(format!("{code}: {}", message.unwrap_or(""))),
            (None, _) => Outcome::Fail(DisplayErrorContext(&err).to_string()),
        }
    }
}

impl From<std::io::Error> for Outcome {
    fn from(err: std::io::Error) -> Self {
        Outcome::Fail(err.to_string())
    }
}

impl From<aws_sdk_s3::error::BuildError> for Outcome {
    fn from(err: aws_sdk_s3::error::BuildError) -> Self {
        Outcome::Fail(DisplayErrorContext(&err).to_string())
    }
}

impl From<aws_sdk_s3::primitives::ByteStreamError> for Outcome {
    fn from(err: aws_sdk_s3::primitives::ByteStreamError) -> Self {
        Outcome::Fail(DisplayErrorContext(&err).to_string())
    }
}

/// What every scenario receives: the plaintext client, the bucket and a scratch directory.
pub struct Driver {
    pub s3: Client,
    pub bucket: String,
    pub work: String,
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

async fn client(endpoint: &str) -> Client {
    let shared = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(env("COMPAT_REGION")))
        .credentials_provider(Credentials::new(env("COMPAT_ACCESS_KEY"), env("COMPAT_SECRET_KEY"), None, None, "compat"))
        .endpoint_url(endpoint)
        .retry_config(RetryConfig::standard().with_max_attempts(1))
        .load()
        .await;
    let config = aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
    Client::from_conf(config)
}

const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "backup-restore",
        "aws-sdk-rust is an SDK, not a backup tool; it has no repository format to restore",
    ),
    ("sync-directory", "aws-sdk-rust offers no directory mirroring primitive"),
];

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!("usage: driver <scenario-id> | --client-version");
        return ExitCode::from(64);
    }
    let scenario = args[0].as_str();
    if scenario == "--client-version" {
        println!("{}", aws_sdk_s3::meta::PKG_VERSION);
        return ExitCode::SUCCESS;
    }
    if let Some((_, reason)) = UNSUPPORTED.iter().find(|(id, _)| *id == scenario) {
        print_result(scenario, "unsupported", reason);
        return ExitCode::SUCCESS;
    }
    if !scenarios::known(scenario) {
        eprintln!("driver: unknown scenario {scenario}");
        return ExitCode::from(64);
    }
    let driver = Driver {
        s3: client(&env("COMPAT_ENDPOINT")).await,
        bucket: env("COMPAT_BUCKET"),
        work: env("COMPAT_WORKDIR"),
    };
    let run = async {
        driver.s3.create_bucket().bucket(&driver.bucket).send().await?;
        scenarios::run(scenario, &driver).await
    };
    let outcome = match tokio::time::timeout(Duration::from_secs(240), run).await {
        Ok(outcome) => outcome,
        Err(_) => fail("the scenario did not finish within 4 minutes"),
    };
    match outcome {
        Ok(()) => print_result(scenario, "pass", ""),
        Err(Outcome::Fail(detail)) => print_result(scenario, "fail", &detail),
        Err(Outcome::Unsupported(reason)) => print_result(scenario, "unsupported", &reason),
    }
    ExitCode::SUCCESS
}

fn print_result(scenario: &str, status: &str, detail: &str) {
    println!(
        r#"{{"scenario": {}, "status": {}, "detail": {}, "evidence": {{}}}}"#,
        json_string(scenario),
        json_string(status),
        json_string(detail)
    );
}

/// A JSON string literal; the three values printed are plain text, so escaping is all that is needed.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", ch as u32); // writing to a String cannot fail
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
