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

//! Deferred construction of a required decoded Copy source.
//!
//! Responsible for: preserving ordinary binding and placeholder-check order before source parsing.
//! NOT responsible for: the source grammar, deployment validation or authorization proofs.
//! Upstream: the request emitter and DTO storage predicate. Downstream: the generated request codec.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::OperationIr;

use crate::emit::dto::{is_required_copy_source_header, naming, required_checks};

pub(super) fn prepare(out: &mut String, ir: &OperationIr) {
    if !ir.input.iter().any(is_required_copy_source_header) {
        return;
    }
    let owner = format!("{}Input", naming::type_name(&ir.operation));
    for check in required_checks(&owner, &ir.input, None, false, "", "rustfs_gateway_types") {
        // The nested placeholder call uses the repository's `fn_call_width` of 90.
        if check.len() > 90
            && let Some(args) = check
                .strip_prefix("rustfs_gateway_types::reject_placeholder(")
                .and_then(|args| args.strip_suffix(')'))
        {
            let _ = writeln!(out, "        value::exit(rustfs_gateway_types::reject_placeholder(");
            for arg in args.split(", ") {
                let _ = writeln!(out, "            {arg},");
            }
            let _ = writeln!(out, "        ))?;");
        } else {
            let _ = writeln!(out, "        value::exit({check})?;");
        }
    }
    for field in ir.input.iter().filter(|field| is_required_copy_source_header(field)) {
        let name = naming::field_name(&field.name);
        let _ = writeln!(
            out,
            "        let {name} = crate::ops::shared::copy_source::decode_value(&{name}, request.names())?;"
        );
    }
}
