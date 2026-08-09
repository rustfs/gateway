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

mod support;

use rustfs_gateway_core::{DerivedResourceError, Operation};

struct MissingResources;

impl Operation for MissingResources {
    const NAME: &'static str = "example:Probe";
    type Input = ();
    type Output = ();

    fn derive_resources(_: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static rustfs_gateway_core::OperationSpec { &support::SPEC }
    fn floor() -> &'static rustfs_gateway_sig::OperationFloor { &support::FLOOR }
}

fn main() {}
