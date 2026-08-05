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

//! XML serialization/deserialization machinery.
//!
//! Responsible for: the `XmlSerialize`/`XmlDeserialize` traits and the reader/writer machinery.
//! NOT responsible for: any S3 semantics — it holds no S3 types. Generated impls live in
//! `s3gate-types` (traits here + types there satisfies the orphan rule, same shape as serde).
//! Upstream: `quick-xml`. Downstream: `s3gate-types`.
#![forbid(unsafe_code)]
