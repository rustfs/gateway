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

//! Compile-fail fixture for the credential-provider return type.
//!
//! Responsible for: proving a provider cannot skip authentication by returning a verdict.
//! NOT responsible for: runtime credential lookup.
//! Upstream: `rustfs-gateway`. Downstream: the credential trybuild contract.

use rustfs_gateway::{BoxFuture, CredentialProvider, ProviderError};
use rustfs_gateway::sig::Verdict;

struct Bad;

impl CredentialProvider for Bad {
    fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<Verdict, ProviderError>> {
        todo!()
    }
}

fn main() {}
