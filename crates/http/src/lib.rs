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

//! HTTP wire layer.
//!
//! Responsible for: request acceptance ([`WireRequest::accept`]), the framing decision that HTTP
//! itself makes ([`Framing`]), the one effective-host determination ([`EffectiveHost`]), and the
//! allocation-free header and query views every layer above reads through.
//! NOT responsible for: deciding the *payload* framing mode — that is derived from the signature
//! (`PayloadMode` is frozen in `rustfs-gateway-sig`, which is why P2 precedes P3); verifying signatures;
//! extracting a bucket from a host; percent-decoding a path; or `aws-chunked` framing (P3-03).
//! Upstream: `rustfs-gateway-types`, `rustfs-gateway-stream`, `http`. Downstream: `rustfs-gateway-sig`, `rustfs-gateway-core`.
//!
//! # The three properties this crate exists to hold
//!
//! 1. **The raw request stops here.** [`WireRequest::accept`] takes an [`http::Request`] *by
//!    value* and never gives it back: no accessor returns a [`http::HeaderMap`], a [`http::Uri`],
//!    or the request itself. Layers above see [`HeaderView`], [`QueryView`], [`RawPath`] and
//!    [`EffectiveHost`], all of which have already been disambiguated.
//! 2. **Ambiguity is rejected, never resolved.** Whenever two sources of the same fact disagree —
//!    `Content-Length` against `Transfer-Encoding`, `:authority` against `Host`, one single-valued
//!    header appearing twice — the request is refused. A silent first-wins or last-wins choice is
//!    how request smuggling and signature bypass are built: one component signs one
//!    interpretation and another acts on the other. Two *identical* `Content-Length` headers are
//!    refused for the same reason a conflicting pair is; leaving the tolerant case open leaves
//!    the parser divergence to be discovered downstream instead of here.
//! 3. **Signing reads raw bytes, routing reads derived values.** [`EffectiveHost::as_str`] is
//!    normalised and is what a router may use; the original bytes are reachable only through
//!    [`EffectiveHost::raw_for_signing`], which yields a [`RawHost`] and nothing else. Because
//!    normalisation is many-to-one, letting a signer read the normalised form would make several
//!    distinct spellings share one valid signature.
//!
//! # What this crate deliberately does not assume
//!
//! [`WireRequest::accept`] is generic over the body type rather than tied to one server
//! implementation. That keeps the kernel transport-agnostic, and it means every check here runs
//! against whatever headers the transport actually surfaces. A transport that silently repairs a
//! `Content-Length` / `Transfer-Encoding` pair before this layer sees it defeats rule W-1 no
//! matter what is written here, so the facade that wires up a server is responsible for handing
//! the request over as received.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::panic
)]

mod framing;
mod header_view;
mod host;
mod ingest;
mod limits;
mod metadata;
mod query_view;
mod reject;
mod text;
mod wire;

pub use crate::framing::{BodyLength, Framing, MAX_CHUNK_SIZE_LINE_BYTES, validate_chunk_size_line};
pub use crate::header_view::{
    CanonicalHeadersError, HeaderView, SINGLE_VALUED_HEADERS, SignedHeaderList, SignedHeadersError, is_significant_header,
};
pub use crate::host::{EffectiveHost, HostError, HostSource, MAX_HOST_BYTES, RawHost, effective_host, effective_host_of};
pub use crate::ingest::{
    ChunkFraming, ChunkReject, ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey, DecodedLength, IngestPipeline, IngestPolicy,
    MAX_SCOPE_LINE_BYTES, MIN_CHUNK_META_BYTES, ModeConfusion, PayloadFramingSource, ScopeId, SigningKeyCache,
    validate_decoded_length,
};
pub use crate::limits::{ChunkLimits, LimitKind, Limits};
pub use crate::metadata::{METADATA_PREFIX, MetadataReject, validate_metadata_key, validate_metadata_value};
pub use crate::query_view::{QueryIndex, QueryView, SINGLE_VALUED_QUERY_PARAMS};
pub use crate::reject::{MAX_LINGER_DRAIN_BYTES, WireReject};
pub use crate::wire::{RawPath, WireRequest};

/// A [`WireRequest`] carrying the workspace-wide owned body.
///
/// The generic form exists so a transport can hand over its own body type without this crate
/// depending on that transport; this alias is the shape the pipeline settles on once the body has
/// been adopted.
pub type OwnedWireRequest = WireRequest<rustfs_gateway_stream::Body>;
