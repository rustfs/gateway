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

//! What a decoder is allowed to read, and the one place a path is decoded.
//!
//! Responsible for: [`MetaView`] — the head of an accepted request, with the URI labels already
//! split and percent-decoded exactly once — and [`RequestBody`], the three shapes a body can
//! arrive in.
//! NOT responsible for: reading a body byte, accepting a request (`rustfs-gateway-http`), or
//! deciding which operation a request names (`crate::route`).
//! Upstream: `rustfs-gateway-http`'s [`WireRequest`]. Downstream: every generated codec.
//!
//! # Why the path is decoded here and nowhere else
//!
//! `RawPath` is deliberately undecoded and offers no `decode` method: a path that can be decoded
//! anywhere can be decoded twice, and a doubly decoded `%252e%252e` is a traversal no single-decode
//! check would have seen. This is the one place the single decode happens, on the way to a
//! [`rustfs_gateway_types::ObjectKey`], and the result is what every decoder reads.

use std::borrow::Cow;

use bytes::Bytes;
use http::Method;
use rustfs_gateway_http::{HeaderView, QueryView, WireRequest};
use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::{BucketName, ObjectKey};

use crate::codec::error::CodecError;
use crate::route::TargetKind;

/// The head of an accepted request, as a decoder sees it.
///
/// Borrows the [`WireRequest`]; it owns nothing but the two decoded URI labels, which cannot be
/// borrowed from the still-encoded path.
#[derive(Debug)]
pub struct MetaView<'a> {
    method: &'a Method,
    headers: HeaderView<'a>,
    query: QueryView<'a>,
    bucket: Option<BucketName>,
    key: Option<ObjectKey>,
}

impl<'a> MetaView<'a> {
    /// Splits an accepted request's path according to what the route says it addresses.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the path does not have the shape the target kind requires, or when a
    /// label is not a valid bucket name or object key. Both are `400`: routing has already decided
    /// which operation this is, so an unusable label is the caller's mistake and not a `501`.
    pub fn of<B>(request: &'a WireRequest<B>, target: TargetKind) -> Result<Self, CodecError> {
        let path = request.raw_path().as_str();
        let (bucket, key) = split_labels(path, target)?;
        Ok(Self {
            method: request.method(),
            headers: request.headers(),
            query: request.query(),
            bucket,
            key,
        })
    }

    /// The request method. Needed by encoders, because a `HEAD` response never carries a body.
    #[must_use]
    pub fn method(&self) -> &'a Method {
        self.method
    }

    /// The value of a header, with repeated field lines joined the way RFC 9110 §5.3 defines them.
    ///
    /// Borrows when the field appears once, which is every request in practice; the owned form is
    /// built only for the repeated case.
    ///
    /// # Why the repeats are joined rather than reduced to the first
    ///
    /// Because "one field whose value is the members joined by commas" is what the message
    /// *means*, and taking the first line is a decoder answering a request the client did not
    /// send. The family where that difference is a security property rather than a nicety is the
    /// conditional headers: two `If-Match` lines joined produce a value no entity-tag parser
    /// accepts, so the request is refused instead of being evaluated against whichever of the
    /// client's two conditions happened to arrive first — a compare-and-swap defeated by a
    /// header-parsing shortcut.
    ///
    /// That outcome is not written here. It falls out of the joined value reaching the type the
    /// binding declares, which is the only place a wire refusal belongs.
    ///
    /// The headers acceptance already treats as single-valued — `authorization`, `content-length`,
    /// `content-md5`, `content-type`, `range` and the rest of
    /// `rustfs_gateway_http::SINGLE_VALUED_HEADERS` — never reach here repeated at all: a request
    /// carrying two of them is refused before a codec runs. So this rule governs everything else,
    /// which is where the conditional headers live.
    ///
    /// A field line whose bytes are not UTF-8 is skipped, exactly as `HeaderView::get_str` skips
    /// an unreadable single value: acceptance has already refused that case for every header this
    /// gateway treats as significant.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<Cow<'a, str>> {
        let name = http::HeaderName::from_bytes(name.as_bytes()).ok()?;
        if !self.headers.is_multi(&name) {
            return self.headers.get_str(&name).map(Cow::Borrowed);
        }
        let mut joined = String::new();
        let mut lines = 0usize;
        for (each, value) in self.headers.iter_text() {
            if *each != name {
                continue;
            }
            if lines > 0 {
                joined.push_str(", ");
            }
            joined.push_str(value);
            lines = lines.saturating_add(1);
        }
        if lines == 0 {
            return None;
        }
        Some(Cow::Owned(joined))
    }

    /// Every header under a prefix, as `(suffix, value)` pairs with the prefix stripped.
    ///
    /// The suffix is lowercased by the transport already; user metadata keys are returned in that
    /// form, which is the form AWS returns them in too.
    pub fn headers_with_prefix(&self, prefix: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.headers
            .iter_text()
            .filter_map(move |(name, value)| name.as_str().strip_prefix(prefix).map(|suffix| (suffix, value)))
    }

    /// A query parameter, percent-decoded exactly once.
    ///
    /// `None` covers "absent"; a present parameter with an empty value is `Some("")`, because
    /// `?prefix=` and no `prefix` at all are different requests.
    #[must_use]
    pub fn query(&self, key: &str) -> Option<Cow<'a, str>> {
        self.query.get(key).map(decode_component)
    }

    /// Whether a query parameter is present, whatever its value.
    #[must_use]
    pub fn has_query(&self, key: &str) -> bool {
        self.query.contains(key)
    }

    /// The bucket the path addressed, when it addressed one.
    #[must_use]
    pub fn bucket(&self) -> Option<&BucketName> {
        self.bucket.as_ref()
    }

    /// The object key the path addressed, when it addressed one.
    #[must_use]
    pub fn key(&self) -> Option<&ObjectKey> {
        self.key.as_ref()
    }

    /// The bucket, or the error a decoder raises when the route promised one and the path had none.
    ///
    /// # Errors
    ///
    /// [`CodecError::invalid_argument`] naming the member.
    pub fn require_bucket(&self) -> Result<BucketName, CodecError> {
        self.bucket
            .clone()
            .ok_or_else(|| CodecError::invalid_argument("the request path names no bucket").about("Bucket"))
    }

    /// The object key, or the error a decoder raises when the route promised one and the path had
    /// none.
    ///
    /// # Errors
    ///
    /// [`CodecError::invalid_argument`] naming the member.
    pub fn require_key(&self) -> Result<ObjectKey, CodecError> {
        self.key
            .clone()
            .ok_or_else(|| CodecError::invalid_argument("the request path names no object key").about("Key"))
    }
}

/// Splits a request path into the labels the target kind declares.
fn split_labels(path: &str, target: TargetKind) -> Result<(Option<BucketName>, Option<ObjectKey>), CodecError> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    match target {
        TargetKind::Service => Ok((None, None)),
        TargetKind::Bucket => {
            let name = trimmed.strip_suffix('/').unwrap_or(trimmed);
            Ok((Some(bucket_of(name)?), None))
        }
        TargetKind::Object => {
            let (name, key) = trimmed
                .split_once('/')
                .ok_or_else(|| CodecError::invalid_argument("the request path names no object key").about("Key"))?;
            // `from_encoded_path` is the single decode. It rejects a key whose decoded form is
            // empty or carries a byte an object key may not hold.
            let key = ObjectKey::from_encoded_path(key)
                .map_err(|_| CodecError::invalid_argument("the object key in the request path is not usable").about("Key"))?;
            Ok((Some(bucket_of(name)?), Some(key)))
        }
    }
}

fn bucket_of(raw: &str) -> Result<BucketName, CodecError> {
    // A bucket label is never percent-encoded on the wire: the naming rules admit only characters
    // that need no escaping, so a `%` here is a spelling no client produces.
    BucketName::new(raw)
        .map_err(|_| CodecError::invalid_argument("the bucket name in the request path is not usable").about("Bucket"))
}

/// Percent-decodes one query component, borrowing when there is nothing to decode.
///
/// A byte sequence that is not UTF-8 after decoding is returned lossily rather than refused: S3
/// query values carry object keys, and a key is bytes. The refusal, when there is one, belongs to
/// the type the value is parsed into.
fn decode_component(raw: &str) -> Cow<'_, str> {
    percent_encoding::percent_decode_str(raw).decode_utf8_lossy()
}

/// The three shapes a request body reaches a decoder in.
///
/// Which one an operation gets is the IR's `payload.request.buffering`, not a decoder's choice: an
/// operation whose body is `Streaming` never sees `Buffered`, so no generated decoder can
/// accidentally aggregate an unbounded upload into memory — the shape it is handed cannot express
/// that.
#[derive(Debug, Default)]
pub enum RequestBody {
    /// The operation takes no body.
    #[default]
    None,
    /// A complete body, already bounded by the operation's declared cap.
    Buffered(Bytes),
    /// A live producer, handed straight to the handler.
    Stream(ByteStream),
}

impl RequestBody {
    /// The buffered bytes, or the error a decoder raises when the body was not buffered.
    ///
    /// # Errors
    ///
    /// [`CodecError::internal`]: an operation whose IR says `Full` was handed something else, which
    /// is a pipeline defect and not a caller mistake.
    pub fn into_buffered(self) -> Result<Bytes, CodecError> {
        match self {
            Self::Buffered(bytes) => Ok(bytes),
            Self::None => Ok(Bytes::new()),
            Self::Stream(_) => Err(CodecError::internal(
                "this operation declares a buffered request body and was handed a stream",
            )),
        }
    }

    /// The streaming body, when there is one.
    #[must_use]
    pub fn into_stream(self) -> Option<ByteStream> {
        match self {
            Self::Stream(stream) => Some(stream),
            _ => None,
        }
    }
}
