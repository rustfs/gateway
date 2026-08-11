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

//! The crate's tests, grouped by the property each group defends.
//!
//! Responsible for: pointing at the four groups — trailer ordering, the capability matrix,
//! adaptation cost, and file-region ranges — and at the scripted producers they share.
//! NOT responsible for: any assertion of its own.
//! Upstream: the crate's own modules. Downstream: nothing.
//!
//! These live inside `src/` rather than in `tests/` on purpose: the properties under test are
//! about the crate's internals — a producer that lies about its capabilities, an adapter that
//! must not lose a byte count — and asserting them from outside would mean widening the public
//! surface just to make it testable.

mod adapt_cost;
mod body;
mod cancellation;
mod caps_matrix;
mod eof_trailers;
#[cfg(unix)]
mod file_region;
mod observer;
mod support;
mod trailers;
mod zero_copy;
