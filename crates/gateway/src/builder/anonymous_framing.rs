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

//! The RustFS-profile switch that leaves an anonymous aws-chunked body undecoded, as legacy
//! RustFS does (rustfs/gateway#1060).
//!
//! Responsible for: [`ServiceBuilder::leave_anonymous_streaming_payloads_undecoded`], the one
//! knob that turns the anonymous framing decode off for an assembly.
//! NOT responsible for: the decode itself or the chunk-signed refusal
//! (`crate::payload_header::anonymous_framing`), or which anonymous requests are admitted at all
//! (the security floor and the authorizer).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, which hands the flag to
//! `anonymous_framing` for every anonymous admission.

use super::ServiceBuilder;

impl ServiceBuilder {
    /// Leaves the body of an anonymous request undecoded whatever `x-amz-content-sha256` declares,
    /// as legacy RustFS does, instead of decoding an anonymous `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
    /// upload and refusing an anonymous chunk-signed one.
    ///
    /// Off by default: the gateway decodes the unsigned streaming form for an anonymous request
    /// exactly as for a signed one (rustfs/gateway#1060). The RustFS profile turns it on, so the
    /// RustFS handler is handed an anonymous streaming upload exactly as legacy RustFS's handler
    /// is — the framed bytes and the framed length — and refuses it by its own size rule: it sizes
    /// the object by `x-amz-decoded-content-length` and refuses the surplus framing bytes (RustFS
    /// main `rustfs/src/app/object/put.rs` L91-L108 and L651-L678). This is the assembly's
    /// behaviour before rustfs/gateway#1060; a handler without that size rule is handed the
    /// framing as it was then.
    #[must_use]
    pub fn leave_anonymous_streaming_payloads_undecoded(mut self) -> Self {
        self.decode_anonymous_framing = false;
        self
    }
}
