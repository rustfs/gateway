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

//! Tests for the generator.
//!
//! Responsible for: end-to-end generation against the pinned model, determinism, the zero-diff
//! gate, the golden comparison, the XML element names a list is written and read through, which
//! members may drop their own empty value, and `why`.
//! NOT responsible for: the parsers, which are tested in `rustfs-gateway-model`.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.

mod all_unknown_tests;
mod authorization_tests;
mod boolean_tests;
mod bounds_tests;
mod codegen_tests;
mod contract_rule_tests;
mod deferred_tests;
mod dto_tests;
mod empty_value_tests;
mod error_status_tests;
mod forms_tests;
mod golden_tests;
mod ledger_tests;
mod mutate_tests;
mod naming_contract_tests;
mod operations_json_tests;
mod operations_md_tests;
mod request_body_mode_tests;
mod route_only_tests;
mod runtime_contract_tests;
mod sensitive_debug_tests;
mod structural_union_tests;
mod tagging_tests;
mod tolerance_tests;
mod unwrapped_empty_value_tests;
mod url_tests;
mod xml_list_tests;
