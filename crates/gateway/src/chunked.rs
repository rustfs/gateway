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

//! Where this assembly runs `rustfs-gateway-http`'s `aws-chunked` pipeline.
//!
//! Responsible for: [`ChunkIngest`] — the head-level decision about whether the chunk parser runs
//! for a request, the material it runs with, and the pass itself.
//! NOT responsible for: any framing rule (`rustfs_gateway_http::ingest` owns every one of them),
//! deciding the payload mode (`rustfs-gateway-sig` does, from `x-amz-content-sha256` and nothing
//! else), or reading the body off the transport (`crate::gate`, which calls this).
//! Upstream: `rustfs-gateway-http`, `rustfs-gateway-sig`, `rustfs-gateway-stream`. Downstream:
//! `crate::gate`.
//!
//! # Where this sits in the pipeline, and why it cannot sit anywhere else
//!
//! `crate::service`'s order is fixed by types: `govern → admit → authenticate → authorize →
//! contradict → read body → decode → dispatch`. Chunk decoding is part of *reading the body* — it
//! is the last thing that happens to the octets before they become an operation's input — so it
//! runs inside [`crate::gate::SealedBody::read`], which takes an `&crate::gate::Authenticated` and
//! therefore cannot be reached before the verifier. That is not a convention: `Authenticated` has
//! one fallible constructor, so a pipeline that decoded first does not compile.
//!
//! It has to be after the verifier for a second reason of its own. A signed `aws-chunked` body's
//! chunk chain is seeded by the *request* signature, so there is nothing to verify chunks against
//! until the request signature has been verified. Decoding first would mean decoding on behalf of
//! a caller nobody had identified.
//!
//! # Which bytes the ceilings count
//!
//! **The wire bytes — before decoding.** [`crate::gate::BodyCeilings`] is applied to what arrives
//! frame by frame, and this pass runs on what survived it.
//!
//! Two reasons, and they point the same way:
//!
//! * **Memory.** The ceiling exists to bound what this process holds. What it holds is the wire
//!   body: chunk headers, signatures, CRLFs and payload alike, all of it resident before a
//!   decoder can tell them apart. Counting decoded bytes would let a peer spend the difference —
//!   and under signed framing the framing is 86 bytes per chunk against a payload the peer chooses
//!   the size of, so a body of a million one-byte chunks is 87 MB on the wire and 1 MB decoded. A
//!   ceiling counted after decoding would admit it.
//! * **Who controls the number.** The attacker writes wire bytes. Decoded bytes are what is left
//!   after this service has already read, parsed and buffered the wire bytes, so a limit stated in
//!   them is a limit enforced after the cost has been paid — the same "aggregate first, check
//!   afterwards" shape `c-object-0015` exists to refuse.
//!
//! The decoded length is bounded too, and by a different mechanism that is not a ceiling: the
//! decoder counts what it produces and fails the moment it diverges from
//! `x-amz-decoded-content-length`, which [`rustfs_gateway_http::validate_decoded_length`] has
//! already cross-checked against `Content-Length` *before the first byte is read*. So the decoded
//! size is pinned by the head, not policed by a budget.
//!
//! # What is not wired, stated rather than faked
//!
//! **Trailered modes are refused.** `rustfs_gateway_http::IngestPipeline::commit_allowed` stays
//! `false` after a body that declared `x-amz-trailer`, because the trailer's checksum and — under
//! signed framing — its own signature are P3-04's and are not verified anywhere yet. Delivering
//! such a body would mean committing an object whose declared integrity check was never run, so
//! this refuses instead. `c-chunked-0001` is a trailered upload; it is currently skipped by the
//! conformance runner for an unrelated reason (a `half_close` control chunk needs a transport that
//! owns the connection, and the in-process target hands over a complete body), so this refusal is
//! not what that case is waiting on.

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkReject, ChunkScope, ChunkSeed, ChunkSigner, DecodedLength, Framing, IngestPipeline,
    IngestPolicy, PayloadFramingSource, validate_decoded_length,
};
use rustfs_gateway_sig::PayloadMode;
use rustfs_gateway_stream::{AsyncPayloadRead, MemoryReader, ReadProgress, TrailingHeaders};
use rustfs_gateway_types::ErrorCode;

use crate::close::ConnectionIntent;
use crate::ext::ChunkSink;
use crate::render::{S3Error, from_chunk_reject, from_handler};

/// The header carrying the decoded length of a framed body.
const DECODED_LENGTH_HEADER: &str = "x-amz-decoded-content-length";

/// How much of the decoded body is copied out per pass.
const DRAIN_BUFFER_BYTES: usize = 64 * 1024;

/// Adapts a [`PayloadMode`] to the four questions the ingest layer is allowed to ask about it.
///
/// A newtype because both types belong to other crates. The adaptation adds nothing: every answer
/// is a method on `PayloadMode`, so `Content-Encoding` has no route in here either.
struct FramingOf<'a>(&'a PayloadMode);

impl PayloadFramingSource for FramingOf<'_> {
    fn is_framed(&self) -> bool {
        self.0.is_framed()
    }

    fn has_chunk_signatures(&self) -> bool {
        self.0.has_chunk_signatures()
    }

    fn requires_decoded_length(&self) -> bool {
        self.0.requires_decoded_length()
    }

    fn declares_trailers(&self) -> bool {
        self.0.trailer().is_some_and(rustfs_gateway_sig::TrailerSet::is_declared)
    }
}

/// One request's `aws-chunked` decode, prepared from the head and run over the wire bytes.
pub(crate) struct ChunkIngest {
    framing: ChunkFraming,
    declared: DecodedLength,
    signer: Option<ChunkSigner>,
    limits: ChunkLimits,
}

impl ChunkIngest {
    /// Decides whether the chunk parser runs, and assembles what it runs with.
    ///
    /// Everything here is decidable from the head, and all of it happens before a body byte is
    /// read: [`validate_decoded_length`] cross-checks `x-amz-decoded-content-length` against the
    /// mode and against `Content-Length`, so a body that declares more decoded bytes than the wire
    /// can carry is refused without being transferred.
    ///
    /// # Errors
    ///
    /// * `Ok(None)` — not an error: the mode does not frame the body, and the bytes are the
    ///   object's own.
    /// * A `501` for a trailered mode, and for a signed mode whose verification material the
    ///   authenticator did not publish. Both fail closed; see the module documentation.
    /// * The mapped [`ChunkReject`] for a head-level framing contradiction.
    pub(crate) fn prepare(
        payload: &PayloadMode,
        headers: &HeaderMap,
        wire: &Framing,
        sink: &ChunkSink,
        seed: Option<&str>,
        limits: ChunkLimits,
    ) -> Result<Option<Self>, S3Error> {
        let framing = ChunkFraming::derive(&FramingOf(payload)).map_err(from_chunk_reject)?;
        if !framing.is_framed() {
            return Ok(None);
        }
        if framing.declares_trailers() {
            return Err(trailers_not_verified());
        }

        let header = headers.get(DECODED_LENGTH_HEADER).and_then(|value| value.to_str().ok());
        let declared = validate_decoded_length(&framing, header, wire)
            .map_err(from_chunk_reject)?
            .ok_or_else(|| {
                from_chunk_reject(ChunkReject::ModeConfusion(rustfs_gateway_http::ModeConfusion::DecodedLengthMissing))
            })?;

        let signer = if framing.has_chunk_signatures() {
            Some(build_signer(sink, seed)?)
        } else {
            None
        };

        Ok(Some(Self {
            framing,
            declared,
            signer,
            limits,
        }))
    }

    /// Runs the pass over the wire bytes and returns the decoded body.
    ///
    /// The bytes are already resident — [`crate::gate::SealedBody::read`] collected them under the
    /// ceilings — so the pipeline is driven over a [`MemoryReader`] and never actually waits. The
    /// `poll_fn` is how a pull-model reader is consumed from an `async fn`; it is not a spin, and
    /// [`MemoryReader`] returns `Pending` for nothing.
    ///
    /// # Errors
    ///
    /// The mapped [`ChunkReject`] for any framing or signature verdict, and a `501` if the
    /// pipeline finishes without permitting a commit — which can only happen for a shape this
    /// assembly declined to accept at [`Self::prepare`], and is refused again rather than
    /// delivered.
    pub(crate) async fn run(self, wire_bytes: Bytes) -> Result<Bytes, S3Error> {
        let reader = MemoryReader::new([wire_bytes], TrailingHeaders::empty());
        let mut pipeline = IngestPipeline::new(
            reader,
            self.framing,
            self.declared,
            self.signer,
            // `SmallVec::default()` without naming `smallvec`: this assembly attaches no digest
            // observer, and the crate is `rustfs-gateway-http`'s dependency rather than this one's.
            Default::default(),
            self.limits,
            IngestPolicy::verify_before_deliver(),
        )
        .map_err(from_chunk_reject)?;

        let mut decoded = BytesMut::new();
        let mut buffer = vec![0_u8; DRAIN_BUFFER_BYTES];
        loop {
            let progress = core::future::poll_fn(|cx| {
                let pinned = core::pin::Pin::new(&mut pipeline);
                pinned.poll_fill(cx, &mut buffer)
            })
            .await;
            match progress {
                // The reject is the reason; the `StreamError` is only its carrier, and recovering
                // it by downcast would be a negotiation with no contract. `IngestPipeline::reject`
                // exists so the status and the code come from the rule that fired.
                Err(_) => return Err(pipeline.reject().map_or_else(chunk_stream_failed, from_chunk_reject)),
                Ok(ReadProgress::Filled(0)) => continue,
                Ok(ReadProgress::Filled(written)) => match buffer.get(..written) {
                    Some(run) => decoded.extend_from_slice(run),
                    None => return Err(chunk_stream_failed()),
                },
                Ok(ReadProgress::Eof { .. }) => break,
            }
        }

        if !pipeline.commit_allowed() {
            // Unreachable for the shapes `prepare` admits, and refused rather than delivered
            // anyway: "the pipeline says this must not be committed" is not a sentence to answer
            // by committing it.
            return Err(trailers_not_verified());
        }
        Ok(decoded.freeze())
    }
}

/// Builds the chunk signer from what the authenticator published and the signature the client
/// presented.
///
/// Both halves are required and neither is invented. The key is the `k_signing` the request
/// signature was derived from, which only an [`crate::Authenticator`] can produce; the seed is the
/// request signature itself, read back off the wire. Reading it back is safe *here* and only here:
/// this runs after the verdict was checked, so the presented value has already been shown equal to
/// the derived one in constant time. A seed read before that check would be a value an attacker
/// chose.
fn build_signer(sink: &ChunkSink, seed: Option<&str>) -> Result<ChunkSigner, S3Error> {
    let Some(material) = sink.get() else {
        return Err(chunk_signatures_unavailable());
    };
    let Some(key) = material.chunk_signing_key() else {
        return Err(chunk_signatures_unavailable());
    };
    let scope = ChunkScope::new(material.scope_line(), material.amz_date()).map_err(from_chunk_reject)?;
    let seed = seed
        .ok_or_else(chunk_signatures_unavailable)
        .and_then(|hex| ChunkSeed::from_hex(hex).map_err(from_chunk_reject))?;
    Ok(ChunkSigner::new(key, scope, seed))
}

/// The refusal for a body whose declared trailer this assembly cannot verify.
///
/// `501` and not `400`: the request is well-formed and it is this service that is incomplete.
/// Answering `400` would tell a correct client to change a correct request.
fn trailers_not_verified() -> S3Error {
    from_handler(
        HandlerError::new(
            ErrorCode::NOT_IMPLEMENTED,
            "this service does not yet verify the trailer this upload declared",
        ),
        ResponseKind::Other,
        // The body was not read to its end, so RFC 9112 §9.3 leaves no choice.
        ConnectionIntent::Close,
    )
}

/// The refusal for a signed framed body with no verification material.
///
/// A configuration or extension-point gap rather than a client error, and it fails closed: the
/// alternative is decoding a signed body without checking any of its signatures, which is the
/// framing-confusion shape the ingest layer exists to prevent.
fn chunk_signatures_unavailable() -> S3Error {
    from_handler(
        HandlerError::new(
            ErrorCode::NOT_IMPLEMENTED,
            "this deployment cannot verify the per-chunk signatures this upload declared",
        ),
        ResponseKind::Other,
        ConnectionIntent::Close,
    )
}

/// The refusal for a pipeline that failed without naming a rule.
fn chunk_stream_failed() -> S3Error {
    from_handler(
        HandlerError::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed"),
        ResponseKind::Other,
        ConnectionIntent::Close,
    )
}

/// The presented request signature, as the lowercase hex the chunk seed is spelled in.
///
/// Read off `Authorization` for header-signed requests and `X-Amz-Signature` for presigned ones.
/// Returning `None` is never an admission of anything: [`build_signer`] refuses without it.
pub(crate) fn presented_signature_hex(headers: &HeaderMap, query: &str) -> Option<String> {
    if let Some(value) = headers.get(http::header::AUTHORIZATION).and_then(|value| value.to_str().ok())
        && let Some(hex) = value.split("Signature=").nth(1)
    {
        let hex: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
        if !hex.is_empty() {
            return Some(hex);
        }
    }
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=')?;
        if name.eq_ignore_ascii_case("X-Amz-Signature") {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A `Framing` announcing `length` bytes.
    ///
    /// Built through `Framing::classify` because that is the only constructor: the type has no
    /// public literal form, which is what keeps a framing decision from being asserted into
    /// existence anywhere other than acceptance.
    fn wire_length(length: u64) -> Framing {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&length.to_string()).expect("a digit run"),
        );
        Framing::classify(http::Version::HTTP_11, &headers, &rustfs_gateway_http::Limits::default()).expect("a framed request")
    }

    /// Positive — the header form is read, and only the hex run is taken. The signature is the
    /// last element of the header, but a parser that took the rest of the string would break the
    /// moment a client appended anything.
    #[test]
    fn the_header_signature_is_read_as_hex_and_stops_at_the_hex() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static(
                "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=host, Signature=abcdef0123456789, Extra=1",
            ),
        );
        assert_eq!(presented_signature_hex(&headers, "").as_deref(), Some("abcdef0123456789"));
    }

    /// Negative — a header with no signature element yields nothing rather than a guess. The
    /// caller refuses on `None`; a parser that returned an empty string here would build a signer
    /// seeded with nothing.
    #[test]
    fn a_header_without_a_signature_element_yields_nothing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=AKID/x, SignedHeaders=host"),
        );
        assert_eq!(presented_signature_hex(&headers, ""), None);
        assert_eq!(presented_signature_hex(&HeaderMap::new(), ""), None);
    }

    /// Negative — `Signature=` with nothing usable after it is nothing, not the empty seed.
    #[test]
    fn an_empty_signature_element_is_not_a_seed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("AWS4-HMAC-SHA256 Signature=, SignedHeaders=host"),
        );
        assert_eq!(presented_signature_hex(&headers, ""), None);
    }

    /// Positive — the presigned form is read from the query when the header carries nothing.
    #[test]
    fn the_presigned_signature_is_read_from_the_query() {
        let query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef&X-Amz-Expires=60";
        assert_eq!(presented_signature_hex(&HeaderMap::new(), query).as_deref(), Some("deadbeef"));
    }

    /// Negative — a mode that does not frame the body produces no ingest at all, whatever
    /// `Content-Encoding` says. This is the one rule the whole ingest layer is arranged around,
    /// asserted at the point this assembly could break it.
    #[tokio::test]
    async fn an_unframed_mode_never_builds_a_pipeline() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static("content-encoding"),
            http::HeaderValue::from_static("aws-chunked"),
        );
        let wire = wire_length(64);
        let prepared =
            ChunkIngest::prepare(&PayloadMode::Unsigned, &headers, &wire, &ChunkSink::new(), None, ChunkLimits::default())
                .expect("an unframed mode is not an error");
        assert!(prepared.is_none());
    }

    /// Negative — a signed framed body with no published material is refused rather than decoded
    /// without verification. Failing open here would decode every chunk of a signed upload and
    /// check none of them.
    #[tokio::test]
    async fn a_signed_framed_body_without_material_is_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(http::HeaderName::from_static(DECODED_LENGTH_HEADER), http::HeaderValue::from_static("11"));
        let wire = wire_length(4096);
        let error = ChunkIngest::prepare(
            &PayloadMode::StreamingSigned {
                trailer: rustfs_gateway_sig::TrailerSet::None,
            },
            &headers,
            &wire,
            &ChunkSink::new(),
            Some(&"a".repeat(64)),
            ChunkLimits::default(),
        )
        .err()
        .expect("no material was published");
        assert_eq!(error.status(), http::StatusCode::NOT_IMPLEMENTED);
        assert!(error.must_close_connection());
    }

    /// A sink holding material that verifies nothing real.
    ///
    /// The key is a fixed pattern and the scope is the published AWS example, so nothing here
    /// authenticates anything anywhere. It exists so that the tests below reach the decoder rather
    /// than stopping at "no material was published", which is a different refusal.
    fn sink_with_material() -> ChunkSink {
        let sink = ChunkSink::new();
        sink.publish(crate::ext::ChunkVerification::new(
            rustfs_gateway_sig::SigningKey::from_array([0x5a; 32]),
            "20130524/us-east-1/s3/aws4_request".to_owned(),
            "20130524T000000Z".to_owned(),
        ));
        sink
    }

    /// The streaming-signed mode without a trailer, which is the one shape this assembly decodes.
    fn signed_streaming() -> PayloadMode {
        PayloadMode::StreamingSigned {
            trailer: rustfs_gateway_sig::TrailerSet::None,
        }
    }

    /// Positive — a framed mode with material builds an ingest, so the decoder is reachable.
    ///
    /// Without this the negative cases below could all be passing because `prepare` refused for
    /// some earlier reason, which is exactly how an assertion reads green while measuring nothing.
    #[tokio::test]
    async fn a_signed_framed_body_with_material_builds_an_ingest() {
        let mut headers = HeaderMap::new();
        headers.insert(http::HeaderName::from_static(DECODED_LENGTH_HEADER), http::HeaderValue::from_static("11"));
        let prepared = ChunkIngest::prepare(
            &signed_streaming(),
            &headers,
            &wire_length(4096),
            &sink_with_material(),
            Some(&"a".repeat(64)),
            ChunkLimits::default(),
        )
        .expect("every head-level check passes");
        assert!(prepared.is_some());
    }

    /// Negative — a framed body whose bytes are not chunk framing is refused rather than stored.
    ///
    /// This is the defect the wiring exists to remove, in one assertion. Before it, a request whose
    /// `x-amz-content-sha256` declared `aws-chunked` framing had its body read raw and handed to the
    /// operation, so the object's content was the chunk headers and signatures — and no assertion
    /// anywhere noticed, because the request succeeded.
    #[tokio::test]
    async fn a_framed_body_that_is_not_framed_is_refused_rather_than_stored() {
        let mut headers = HeaderMap::new();
        headers.insert(http::HeaderName::from_static(DECODED_LENGTH_HEADER), http::HeaderValue::from_static("11"));
        let ingest = ChunkIngest::prepare(
            &signed_streaming(),
            &headers,
            &wire_length(4096),
            &sink_with_material(),
            Some(&"a".repeat(64)),
            ChunkLimits::default(),
        )
        .expect("head-level checks pass")
        .expect("a framed mode");
        let error = ingest
            .run(Bytes::from_static(b"hello world"))
            .await
            .expect_err("plain text is not aws-chunked framing");
        assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
    }

    /// Negative — well-formed framing whose chunk signature does not verify is refused, and as an
    /// authentication outcome rather than a framing one.
    ///
    /// The signature here is syntactically perfect and cryptographically meaningless, which is the
    /// only interesting case: a decoder that checked the *shape* of the extension and not its value
    /// would pass this and would verify nothing at all.
    #[tokio::test]
    async fn a_chunk_signature_that_does_not_verify_is_a_forbidden_and_not_a_bad_request() {
        let mut headers = HeaderMap::new();
        headers.insert(http::HeaderName::from_static(DECODED_LENGTH_HEADER), http::HeaderValue::from_static("5"));
        let ingest = ChunkIngest::prepare(
            &signed_streaming(),
            &headers,
            &wire_length(4096),
            &sink_with_material(),
            Some(&"a".repeat(64)),
            ChunkLimits::default(),
        )
        .expect("head-level checks pass")
        .expect("a framed mode");
        let body = format!(
            "5;chunk-signature={}\r\nhello\r\n0;chunk-signature={}\r\n\r\n",
            "b".repeat(64),
            "c".repeat(64)
        );
        let error = ingest
            .run(Bytes::from(body))
            .await
            .expect_err("the chunk signature is not the one the chain derives");
        assert_eq!(error.status(), http::StatusCode::FORBIDDEN);
        assert!(error.must_close_connection(), "an unverified peer's connection does not survive");
    }

    /// Negative — a trailered mode is refused, and with the status that says the gap is this
    /// service's rather than the client's.
    ///
    /// `commit_allowed` stays `false` for a trailered body because nothing verifies the trailer's
    /// checksum yet. Delivering it anyway would commit an object whose declared integrity check was
    /// never run, so the refusal is the honest answer and `501` is the honest status.
    #[tokio::test]
    async fn a_trailered_mode_is_refused_as_unimplemented_and_not_as_malformed() {
        let mut headers = HeaderMap::new();
        headers.insert(http::HeaderName::from_static(DECODED_LENGTH_HEADER), http::HeaderValue::from_static("11"));
        let trailer = rustfs_gateway_sig::DeclaredTrailers::new(
            [rustfs_gateway_sig::TrailerName::new("x-amz-checksum-crc32").expect("a valid trailer name")],
            false,
        )
        .expect("one name is a valid set");
        let error = ChunkIngest::prepare(
            &PayloadMode::StreamingSigned {
                trailer: rustfs_gateway_sig::TrailerSet::Declared(trailer),
            },
            &headers,
            &wire_length(4096),
            &sink_with_material(),
            Some(&"a".repeat(64)),
            ChunkLimits::default(),
        )
        .err()
        .expect("trailer verification is not wired");
        assert_eq!(error.status(), http::StatusCode::NOT_IMPLEMENTED);
    }

    /// Negative — a framed body that declares no decoded length is refused at the head, before a
    /// byte is read. Without the header the decoder has nothing to check the arriving length
    /// against, which is the state every length check exists to avoid.
    #[tokio::test]
    async fn a_framed_body_without_a_decoded_length_is_refused_at_the_head() {
        let wire = wire_length(4096);
        let error = ChunkIngest::prepare(
            &PayloadMode::StreamingSigned {
                trailer: rustfs_gateway_sig::TrailerSet::None,
            },
            &HeaderMap::new(),
            &wire,
            &ChunkSink::new(),
            None,
            ChunkLimits::default(),
        )
        .err()
        .expect("no decoded length");
        assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
    }
}
