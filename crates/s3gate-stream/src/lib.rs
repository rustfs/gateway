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

//! Payload and body primitives.
//!
//! Responsible for: `Body`, `ByteStream`, `Payload`, trailer delivery typing.
//! NOT responsible for: anything S3-specific. This crate exists so that
//! `GetObjectOutput.body: StreamingBlob` does not create a `s3gate-types` <-> `s3gate-http` cycle.
//! Upstream: `bytes`/`http`. Downstream: `s3gate-types`, `s3gate-http`.
#![forbid(unsafe_code)]
