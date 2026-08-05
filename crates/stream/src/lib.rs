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

//! Body, byte-stream and payload primitives for the data plane.
//!
//! Responsible for: the one owned [`Body`] type, the pull and push halves of the data plane
//! ([`AsyncPayloadRead`] and [`PayloadStream`]), the named capability set a transport
//! negotiates over ([`Payload`] and [`PayloadCaps`]), the price of adapting between the two
//! halves ([`AdaptCost`] and [`StreamMetrics`]), and the typing that makes a trailer section
//! reachable only through an end-of-stream event ([`TrailingHeaders`]).
//!
//! NOT responsible for: anything with protocol meaning. No header name, no digest algorithm, no
//! status code and no storage vocabulary appears here, deliberately. This crate exists because a
//! streaming output field would otherwise force the type crate and the wire crate to depend on
//! each other; if protocol vocabulary leaks in here, that cycle comes back in another shape.
//! It also does no framing, no back-pressure policy and no kernel-side transfer: it names the
//! shapes those layers need, and stops there.
//!
//! Upstream: `bytes`, `http` and `bitflags` — and nothing internal, by construction.
//! Downstream: `rustfs-gateway-types` (streaming fields), `rustfs-gateway-http` (the wire layer that produces
//! bodies), and every layer above them.
//!
//! # The two properties worth knowing before you touch this crate
//!
//! **A trailer section can only be obtained at end-of-stream.** [`PayloadRead::Eof`] owns the
//! only [`TrailingHeaders`] a consumer will ever see. There is no shared mutable slot to look
//! into early; a consumer that has not reached the end has no value to read, so "the digest
//! that trailed the body was never checked because the handler looked too early" is not a
//! reachable state. An absent trailer section is an empty map, never `None`, because `None`
//! would again mean either "no trailer was sent" or "the body is not finished".
//!
//! **Capability negotiation is named and exhaustible.** [`Payload`] is an enum of shapes, and a
//! transport asks for what it wants with `try_into_file_region`, [`Payload::try_as_vectored`],
//! [`Payload::try_into_reader`] or [`Payload::try_into_stream`]. There is no `as_any()` and no
//! downcast: a downcast has no contract, so it fails silently into a slower path with no
//! compile error and no counter, and it can also hand a transport the inner payload of a
//! wrapper that existed to validate the bytes. Every refusal here returns the payload unchanged
//! plus a named reason, and every adaptation returns an [`AdaptCost`] that is recorded in
//! [`StreamMetrics`].

#![forbid(unsafe_code)]

mod adapt;
mod body;
mod byte_stream;
mod caps;
mod error;
#[cfg(unix)]
mod file_region;
mod metrics;
mod payload;
mod read;
mod stream;
mod trailers;

#[cfg(test)]
mod tests;

pub use crate::adapt::{Adapt, AdaptCost, MemoryReader, MemoryStream, ReaderToStream, StreamToReader};
pub use crate::body::Body;
pub use crate::byte_stream::{ByteStream, RemainingLength};
pub use crate::caps::{CapsInconsistency, PayloadCaps, validate_caps};
pub use crate::error::{StreamError, StreamErrorKind};
#[cfg(unix)]
pub use crate::file_region::{FileRegion, FileRegionError};
pub use crate::metrics::StreamMetrics;
pub use crate::payload::{AdaptRefusal, Payload};
pub use crate::read::{AsyncPayloadRead, BoxPayloadReader, ReadProgress};
pub use crate::stream::{BoxPayloadStream, PayloadRead, PayloadStream};
pub use crate::trailers::TrailingHeaders;
