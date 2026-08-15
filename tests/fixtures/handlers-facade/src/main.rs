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

//! Compiles the registration macro from a downstream crate that depends only on the public facade.
//!
//! Responsible for: proving generated paths resolve through a sole `rustfs-gateway` dependency.
//! NOT responsible for: runtime dispatch or registry equivalence.
//! Upstream: `rustfs-gateway`. Downstream: nothing.

use std::sync::Arc;

use rustfs_gateway::{
    HandlerResult, Req, Resp, RouterBuilder,
    dto::{GetObject, GetObjectOutput},
    handlers,
};

struct Backend;

#[handlers]
impl Backend {
    async fn get_object(&self, _request: Req<GetObject>) -> HandlerResult<GetObject> {
        Ok(Resp::new(GetObjectOutput::default()))
    }
}

fn main() {
    let _: fn(&Arc<Backend>, RouterBuilder) -> RouterBuilder = Backend::register;
}
