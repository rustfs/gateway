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

//! Signature verification state machine (SigV2/SigV4, presigned, POST policy).
//!
//! Responsible for: `PayloadMode`/`AuthScheme`, canonical request construction, the
//! constant-time verification proof that makes "never compared" unrepresentable.
//! NOT responsible for: authorization (that is `s3gate-core`), credential storage.
//! Upstream: `s3gate-http`. Downstream: `s3gate-core`.
#![forbid(unsafe_code)]
