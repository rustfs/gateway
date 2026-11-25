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

//! The `fuzz-endpoint-replay` binary: replays `decode_diff` or `encode_diff` fuzz corpora over
//! real HTTP/1.1 against an external `--endpoint` (rustfs/backlog#2781).
//!
//! Responsible for: calling `rustfs_gateway_difftest::endpoint_replay::main` and exiting with its
//! status code.
//! NOT responsible for: argument parsing, HTTP transport, corpus translation, or crash artifact
//! emission (`endpoint_replay.rs`).
//! Upstream: `rustfs_gateway_difftest::endpoint_replay`.
//! Downstream: `.github/workflows/fuzz-nightly.yml` and operators.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(rustfs_gateway_difftest::endpoint_replay::main())
}
