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

//! The emitters, one module per artefact.
//!
//! Responsible for: turning IR into bytes, deterministically. Every emitter is a pure function of
//! the IR: no clock, no host name, no generator version, no hash-map iteration order.
//! NOT responsible for: writing files (that is [`crate::write()`]) or deciding content.
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: the checked-in artefacts.

pub mod codec;
pub mod dto;
pub mod error_status;
pub mod naming_contracts;
pub mod operations_json;
pub mod operations_md;
pub mod quirk_toml;
pub mod range_contracts;
pub mod runtime_contracts;
pub mod rust_files;
pub mod spec_toml;

use rustfs_gateway_model::json::Value;

/// Quotes a string for the TOML subset the overlays use.
pub fn quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Renders a list of strings on one line.
pub fn string_list(items: &[String]) -> String {
    let inner = items.iter().map(|i| quote(i)).collect::<Vec<_>>().join(", ");
    format!("[{inner}]")
}

/// Renders an IR default value in TOML.
pub fn json_scalar(value: &Value) -> String {
    match value {
        Value::Str(s) => quote(s),
        Value::Int(i) => i.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Null => "\"\"".to_owned(),
        other => quote(&format!("{other:?}")),
    }
}
