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

//! The one integration target of `compat-sut`: every test here spawns the built binary.
//!
//! Responsible for: linking the binary-level suites into a single test executable, so each new
//! topic costs a module rather than another linked target (rustfs/gateway#277).
//! NOT responsible for: any assertion of its own; the topics below own theirs.
//! Upstream: `CARGO_BIN_EXE_compat-sut`. Downstream: `cargo test -p rustfs-gateway-compat-sut`.

/// The encrypted listener beside the plaintext one (rustfs/gateway#719).
mod tls;

/// `--external`: the observer in front of an endpoint started elsewhere (rustfs/backlog#2758).
mod external;
