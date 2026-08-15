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

//! `c-sig-0345`: callers cannot construct a scope before H5 verifies it.
//!
//! Responsible for: proving every `VerifiedScope` field remains private.
//! NOT responsible for: runtime date, region, service, or terminator checks.
//! Upstream: client-presented credential scope. Downstream: signing-key derivation.

use rustfs_gateway_sig::VerifiedScope;

fn private_field_value<T>() -> T {
    panic!("the private fields must reject this construction")
}

fn main() {
    let _ = VerifiedScope {
        date: private_field_value(),
        region: private_field_value(),
        service: private_field_value(),
    };
}
