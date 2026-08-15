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

//! `c-sig-0376`: dangerous replacement acknowledgement must be explicit.
//!
//! Responsible for: proving `DangerAck` has no `Default` or public tuple constructor.
//! NOT responsible for: enabling or installing a replacement verifier.
//! Upstream: dangerous feature opt-in. Downstream: replacement-verifier builder APIs.

use rustfs_gateway_sig::DangerAck;

fn main() {
    let _ = DangerAck::default();
    let _ = DangerAck(());
}
