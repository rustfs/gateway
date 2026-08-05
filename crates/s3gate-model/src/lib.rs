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

//! Smithy model parsing and the frozen s3gate IR.
//!
//! Responsible for: loading the pinned AWS Smithy model, applying overlays, producing the IR.
//! NOT responsible for: emitting Rust code (that is `s3gate-codegen`), any runtime behaviour.
//! Upstream: the pinned `model/` directory. Downstream: `s3gate-codegen`.
//!
//! Build-time only — never appears in a runtime dependency tree.
#![forbid(unsafe_code)]
