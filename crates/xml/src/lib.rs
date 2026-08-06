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
//! Responsible for: the writer a generated encoder writes a response body through, the bounded
//! reader a generated decoder reads a request body through, and the refusals both of them share.
//! NOT responsible for: any S3 semantics — it holds no S3 type, knows no element name, and has no
//! opinion about which member goes where. Generated impls live in `rustfs-gateway-core`, whose
//! codecs supply every name and every ordering from the IR.
//! Upstream: `quick-xml`. Downstream: `rustfs-gateway-types`, `rustfs-gateway-core`.
//!
//! # Why the writer offers no formatting options
//!
//! S3 writes a response body with no whitespace between elements and writes an empty element in
//! its paired form. Both are byte-observable, and a conformance case that pins a body fails on
//! either. An option a caller could set the other way is a defect waiting for a caller.
#![forbid(unsafe_code)]

pub mod error;
pub mod read;
pub mod write;

#[cfg(test)]
mod tests;

pub use crate::error::XmlError;
pub use crate::read::{MAX_DEPTH, MAX_ELEMENTS, XmlNode, parse};
pub use crate::write::{DECLARATION, S3_XMLNS, XmlWriter, escape_attribute, escape_text};
