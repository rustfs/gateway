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

//! Crate-level tests for the generated surface.
//!
//! Responsible for: the properties ADR-0004 promises to a downstream consumer, asserted against
//! the generated types as they are actually compiled rather than against the emitter's output text.
//! NOT responsible for: the scalar vocabulary, which is tested in `src/scalar/tests/`, or the
//! generator's shape rules, which are tested in `rustfs-gateway-codegen`.
//! Upstream: `crate::ops` and `crate::dto`. Downstream: nothing.

mod dto_tests;
