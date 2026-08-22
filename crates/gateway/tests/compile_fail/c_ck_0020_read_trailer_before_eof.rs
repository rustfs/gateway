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

//! Compile-time proof that a consumer cannot inspect stream-produced trailers before EOF.
//!
//! Responsible for: making `c-ck-0020` fail to compile when it tries to read trailers directly
//! from an arbitrary progress event.
//! NOT responsible for: constructing a producer or assigning protocol meaning to trailer fields.
//! Upstream: `rustfs-gateway-stream`. Downstream: the consolidated gateway trybuild target.

use rustfs_gateway_stream::{ReadProgress, TrailingHeaders};

fn read_trailers_before_eof(progress: &ReadProgress) -> &TrailingHeaders {
    progress.trailers()
}

fn main() {}
