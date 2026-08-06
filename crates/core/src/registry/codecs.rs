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

//! Where the operation type disappears: one operation's wire codec, erased at registration.
//!
//! Responsible for: [`erase`] — turning an [`OperationCodec`] implementation into two closures
//! that mention the operation nowhere — [`ErasedDecode`] and [`ErasedEncode`], and [`ErasedCodec`],
//! the pair the registry stores them in.
//! NOT responsible for: any wire rule. Every one of those is generated into
//! `generated/codec/ops/` and reached through [`OperationCodec`]. Nor for deciding whether a
//! registration is allowed (`super::reject`), nor for calling the handler (`super::handlers`).
//! Upstream: `crate::codec`, `crate::handler`, `crate::op`. Downstream: [`super::HandlerTable`],
//! which holds a codec in the same entry as the handler it arrived with, and the pipeline above
//! it, which has a name and no type.
//!
//! # Why the erasure has to happen at registration and nowhere else
//!
//! [`OperationCodec::decode`] and [`OperationCodec::encode`] are generic per operation, and every
//! layer above the registry holds an operation *name* — a `&str` from the route table. There is
//! exactly one place that has both the type `O` and the name `O::NAME` in scope, and that is the
//! registration call. So the bridge from one to the other is built there or it is not built at
//! all: a later layer cannot name the type it would need to call.
//!
//! # Why a codec is never installed on its own
//!
//! A decoder with no handler produces a `Req<O>` nothing will answer, and a handler with no
//! decoder is an operation that routes and then has nothing able to read it. Both halves are
//! erased from the same `register_handler::<O, B>` call and stored in one map entry, so the two
//! cannot drift apart and no call sequence can produce a half-registered operation.
//!
//! # Why the erased encoder is not handed a status
//!
//! [`OperationCodec::encode`] takes one, because it encodes an `O::Output`. What is erased here is
//! a [`Resp<O>`], which already carries the status the handler chose — the operation's declared
//! success status, or the one it overrode for a ranged read or a per-key delete report. A second
//! status parameter would let the caller contradict the handler, and nothing would say which of
//! the two answers is the right one.

use std::fmt;
use std::sync::Arc;

use crate::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody};
use crate::handler::{Req, Resp};
use crate::registry::handlers::{ErasedRequest, ErasedResponse};

/// An operation's decoder, with the operation type erased.
///
/// `Arc` rather than `Box` for the same reason as [`super::ErasedHandler`]: [`super::Registry`]
/// stays `Clone`, so handing a router to another task costs a refcount rather than a rebuild.
pub type ErasedDecode = Arc<dyn Fn(&MetaView<'_>, RequestBody) -> Result<ErasedRequest, CodecError> + Send + Sync>;

/// An operation's encoder, with the operation type erased.
///
/// Takes the answer and the request the answer is to: a `HEAD` carries no body, `response-*`
/// parameters overwrite response headers, and `encoding-type` decides how body members are
/// escaped — three observable behaviours that are functions of both.
pub type ErasedEncode = Arc<dyn Fn(ErasedResponse, &MetaView<'_>) -> Result<EncodedResponse, CodecError> + Send + Sync>;

/// The answer an encoder gives when it is handed another operation's response.
///
/// A `500`, not a `4xx`: nothing a caller sends can select which entry the pipeline looks up, so
/// reaching this is a defect on this side. Answered rather than panicked, for the same reason
/// `super::handlers` answers its mismatch — a framework bug must not be able to take the process
/// down. The text is a compile-time constant, like every other [`CodecError`] message.
const RESPONSE_MISMATCH: CodecError =
    CodecError::internal("the registered encoder for this operation was called with another operation's response");

/// One operation's wire codec, with the operation type erased.
///
/// Produced only by [`erase`], and only from a `register_handler::<O, B>` call, so the decoder and
/// the encoder in one of these are always the two halves of a single [`OperationCodec`]
/// implementation.
#[derive(Clone)]
pub struct ErasedCodec {
    operation: &'static str,
    decode: ErasedDecode,
    encode: ErasedEncode,
}

impl ErasedCodec {
    /// The operation this codec was erased from.
    #[must_use]
    pub const fn operation_name(&self) -> &'static str {
        self.operation
    }

    /// The decoder, for a caller that wants to keep it.
    #[must_use]
    pub const fn decoder(&self) -> &ErasedDecode {
        &self.decode
    }

    /// The encoder, for a caller that wants to keep it.
    #[must_use]
    pub const fn encoder(&self) -> &ErasedEncode {
        &self.encode
    }

    /// Reads a request head and a body into a boxed `Req<O>`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] naming the model member that could not be read. The operation has already
    /// been routed, so every failure here is a statement about a value and never a `501`.
    pub fn decode(&self, request: &MetaView<'_>, body: RequestBody) -> Result<ErasedRequest, CodecError> {
        (self.decode)(request, body)
    }

    /// Writes a boxed `Resp<O>` as a status, a header set and a body.
    ///
    /// # Errors
    ///
    /// [`CodecError::internal`] when the response is another operation's, or when the output holds
    /// a value with no wire form.
    pub fn encode(&self, response: ErasedResponse, request: &MetaView<'_>) -> Result<EncodedResponse, CodecError> {
        (self.encode)(response, request)
    }
}

impl fmt::Debug for ErasedCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasedCodec").field("operation", &self.operation).finish()
    }
}

/// Erases one operation's codec into a decoder and an encoder that mention it nowhere.
///
/// The decode half needs no downcast — it produces the box, so the payload is the right type by
/// construction. The encode half does: it is handed a box somebody else chose, and it answers a
/// wrong one with [`RESPONSE_MISMATCH`].
pub(crate) fn erase<O: OperationCodec>() -> ErasedCodec {
    let decode: ErasedDecode = Arc::new(|request: &MetaView<'_>, body: RequestBody| {
        let input = O::decode(request, body)?;
        Ok(Box::new(Req::<O>::new(input)) as ErasedRequest)
    });
    let encode: ErasedEncode = Arc::new(|response: ErasedResponse, request: &MetaView<'_>| {
        let response = response.downcast::<Resp<O>>().map_err(|_| RESPONSE_MISMATCH)?;
        let (output, status) = response.into_parts();
        O::encode(output, request, status)
    });
    ErasedCodec {
        operation: O::NAME,
        decode,
        encode,
    }
}
