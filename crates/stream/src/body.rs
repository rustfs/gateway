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

//! The one body type a request or a response carries.
//!
//! Responsible for: giving both body shapes — bytes already in hand, and bytes still to come —
//! a single owned type, so a pipeline stage can hold a body without a lifetime parameter. That
//! matters beyond tidiness: a stage that borrowed its body would become self-referential the
//! moment it crossed an await point, and pinning it safely is not expressible without `unsafe`.
//! NOT responsible for: capability negotiation, which belongs to the payload it wraps, and any
//! protocol meaning — a body here has no length header, no digest and no status code.
//! Upstream: `bytes`, plus this crate's `payload` and `caps`. Downstream: `rustfs-gateway-types`, whose
//! streaming output fields hold one of these, and `rustfs-gateway-http`.

use bytes::Bytes;

use crate::caps::{CapsInconsistency, PayloadCaps};
use crate::payload::Payload;
use crate::read::AsyncPayloadRead;
use crate::stream::PayloadStream;

#[cfg(unix)]
use crate::file_region::FileRegion;

/// A request or response body.
///
/// A thin owned wrapper over [`Payload`]. It exists so that the layers above have one name for
/// "the body", while the capability detail stays in the payload where a transport can negotiate
/// over it.
#[derive(Debug, Default)]
pub struct Body {
    payload: Payload,
}

impl Body {
    /// A body with no bytes.
    #[must_use]
    pub fn empty() -> Self {
        Self { payload: Payload::Empty }
    }

    /// A body whose bytes are already in memory.
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            payload: Payload::from_bytes(bytes),
        }
    }

    /// A body assembled from segments that are already in memory.
    #[must_use]
    pub fn from_segments(segments: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            payload: Payload::from_segments(segments),
        }
    }

    /// A body produced by a push-model producer.
    ///
    /// Returns an error when the producer's capability bits contradict its length hint. The
    /// check happens here, where the producer enters the system, because every consumer
    /// downstream trusts those bits.
    pub fn from_stream<S>(stream: S) -> Result<Self, CapsInconsistency>
    where
        S: PayloadStream + Send + 'static,
    {
        Ok(Self {
            payload: Payload::from_stream(stream)?,
        })
    }

    /// A body produced by a pull-model producer.
    pub fn from_reader<R>(reader: R) -> Result<Self, CapsInconsistency>
    where
        R: AsyncPayloadRead + Send + 'static,
    {
        Ok(Self {
            payload: Payload::from_reader(reader)?,
        })
    }

    /// A body that is a range of a file.
    #[cfg(unix)]
    #[must_use]
    pub fn from_file_region(region: FileRegion) -> Self {
        Self {
            payload: Payload::File(region),
        }
    }

    /// A body over an already built payload.
    #[must_use]
    pub fn from_payload(payload: Payload) -> Self {
        Self { payload }
    }

    /// Borrows the payload, to read its capabilities before deciding how to send it.
    #[must_use]
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Takes the payload out, to negotiate a transfer strategy over it.
    #[must_use]
    pub fn into_payload(self) -> Payload {
        self.payload
    }

    /// What this body can do.
    #[must_use]
    pub fn caps(&self) -> PayloadCaps {
        self.payload.caps()
    }

    /// The exact body length, when it is known.
    #[must_use]
    pub fn len_hint(&self) -> Option<u64> {
        self.payload.len_hint()
    }

    /// Whether this body is known to carry no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(Bytes::from(bytes))
    }
}

impl From<Payload> for Body {
    fn from(payload: Payload) -> Self {
        Self::from_payload(payload)
    }
}

impl From<Body> for Payload {
    fn from(body: Body) -> Self {
        body.into_payload()
    }
}
