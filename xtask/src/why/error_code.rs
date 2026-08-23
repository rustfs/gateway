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

//! Error-code resolution and reverse-trace answers.
//!
//! Responsible for: joining the status authority to producing operations and referencing cases.
//! NOT responsible for: loading repository inputs or rendering the final text/JSON response.
//! Upstream: error-status overlays, operation IR and conformance cases. Downstream: `xtask why`.

use rustfs_gateway_model::ErrorStatus;
use rustfs_gateway_model::ir::OperationIr;

use super::{Answer, CaseRecord, WhyTarget, contains, contains_token, finish};

pub(super) fn resolve(statuses: &[ErrorStatus], argument: &str) -> Result<WhyTarget, String> {
    statuses
        .iter()
        .find(|status| status.name.eq_ignore_ascii_case(argument))
        .map(|status| WhyTarget::ErrorCode(status.name.clone()))
        .ok_or_else(|| format!("error code `{argument}` not found"))
}

pub(super) fn answer(statuses: &[ErrorStatus], operations: &[OperationIr], cases: &[CaseRecord], code: &str) -> Answer {
    let status = statuses.iter().find(|status| status.name == code);
    let producers: Vec<&OperationIr> = operations
        .iter()
        .filter(|operation| contains(&operation.errors.codes, code))
        .collect();
    let names: Vec<String> = producers.iter().map(|operation| operation.operation.clone()).collect();
    let cases = cases
        .iter()
        .filter(|case| contains_token(&case.source, code))
        .map(|case| case.line.clone())
        .collect();
    finish(Answer {
        id: code.to_owned(),
        summary: format!(
            "S3 error code status={} produced by {}",
            status.map_or_else(|| "unknown".to_owned(), |status| status.status.to_string()),
            names.join(", ")
        ),
        evidence: Vec::new(),
        cases,
        adrs: Vec::new(),
        spec: names
            .iter()
            .map(|name| format!("spec/operations/{name}.toml:errors"))
            .collect(),
        related: names,
        complete: status.is_some(),
    })
}
