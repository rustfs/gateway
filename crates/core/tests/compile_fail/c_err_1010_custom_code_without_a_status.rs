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

//! `c-err-1010`: a code nobody chose a status for cannot be built.
//!
//! Responsible for: proving `ErrorCode::custom` has no one-argument form, so an error code this
//! gateway invents at a call site cannot reach the wire with a status its author never named.
//! NOT responsible for: the statuses the authority declares, which are total by construction and
//! are checked by `scripts/check_error_status_total.sh`.
//! Upstream: `rustfs_gateway_types::ErrorCode`. Downstream: every `s3_error!` call site.
//!
//! Before rustfs/backlog#1694 an unlisted code took a silent fallback, and s3s#430 is the same
//! defect one band worse: its custom codes defaulted to 500, so a client's mistake was reported as
//! a server fault and every SDK in front of it retried and opened a circuit breaker. A status the
//! caller must name is the only version of this that cannot regress quietly, which is why the
//! second parameter is a compile error to omit rather than a lint.

use rustfs_gateway_types::ErrorCode;

fn main() {
    let _code = ErrorCode::custom("Foo");
}
