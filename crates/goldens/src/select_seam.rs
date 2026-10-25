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

//! Select request/response seam evidence through the public codec and every bound legacy serializer.
//!
//! Responsible for: three compilations of wire, presence, header, name-policy and polling checks.
//! NOT responsible for: implementing conversion or native query execution.
//! Upstream: independent public-API measurements. Downstream: migration regression gates.

mod checks;
mod input;

checks::define_tests!(release, s3s_0_17_0, "0.17.0", "Access Denied");
checks::define_tests!(rustfs, s3s_5761ddfe, "5761ddfe", "Access Denied");
checks::define_tests!(baseline, s3s_9c4690d8, "9c4690d8", "");
